# update-iam-role.ps1 — push the updated permissions policy to the IAM role
# that GitHub Actions uses for this repo. Run once after pulling the changes
# that add the detection-validation workflow.
#
# Prereqs:
#   - AWS CLI installed (winget install Amazon.AWSCLI) and `aws configure` done
#   - Credentials on this machine belong to the AWS account that owns the role
#
# Usage (interactive — will prompt for role name if not passed):
#   pwsh .\update-iam-role.ps1
#
# Usage (explicit):
#   pwsh .\update-iam-role.ps1 -RoleName github-actions-suricata-zeek -PolicyName SuricataZeekCI

param(
    [string]$RoleName = '',
    [string]$PolicyName = ''
)

$ErrorActionPreference = 'Stop'

# --- Preflight ------------------------------------------------------------
if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Error "aws CLI not found on PATH. Install: winget install Amazon.AWSCLI"
}

Write-Host "Verifying AWS credentials..." -ForegroundColor Cyan
$ident = aws sts get-caller-identity --output json | ConvertFrom-Json
if (-not $ident.Account) {
    Write-Error "aws sts get-caller-identity failed. Run 'aws configure' first."
}
Write-Host "  Account: $($ident.Account)"
Write-Host "  ARN:     $($ident.Arn)"

# --- Find the role --------------------------------------------------------
if (-not $RoleName) {
    Write-Host "`nSearching for candidate IAM roles..." -ForegroundColor Cyan
    $candidates = aws iam list-roles `
        --query "Roles[?contains(RoleName, 'github') || contains(RoleName, 'suricata') || contains(RoleName, 'zeek') || contains(RoleName, 'gha')].RoleName" `
        --output text
    if ($candidates) {
        Write-Host "  Candidates: $candidates"
    }
    $RoleName = Read-Host "Role name to update"
}

Write-Host "`nVerifying role '$RoleName' exists..." -ForegroundColor Cyan
aws iam get-role --role-name $RoleName --query 'Role.Arn' --output text | Out-Null

# --- Find the inline policy name ------------------------------------------
if (-not $PolicyName) {
    $existing = aws iam list-role-policies --role-name $RoleName --query 'PolicyNames' --output text
    if (-not $existing) {
        Write-Host "`nNo inline policy found on role '$RoleName'."
        $PolicyName = Read-Host "Policy name to CREATE"
    } else {
        $names = $existing -split '\s+'
        if ($names.Count -eq 1) {
            $PolicyName = $names[0]
            Write-Host "  Found one inline policy: $PolicyName (will update it)"
        } else {
            Write-Host "  Multiple inline policies found: $($names -join ', ')"
            $PolicyName = Read-Host "Which one to update"
        }
    }
}

# --- The policy document --------------------------------------------------
$policyJson = @'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeImages",
        "ec2:DescribeSecurityGroups",
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:ImportKeyPair",
        "ec2:DeleteKeyPair",
        "ec2:DescribeKeyPairs",
        "ec2:CreateTags",
        "ec2:CreateNetworkInterface",
        "ec2:AttachNetworkInterface",
        "ec2:DetachNetworkInterface",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:ModifyNetworkInterfaceAttribute",
        "ec2:CreateTrafficMirrorTarget",
        "ec2:DeleteTrafficMirrorTarget",
        "ec2:DescribeTrafficMirrorTargets",
        "ec2:CreateTrafficMirrorFilter",
        "ec2:CreateTrafficMirrorFilterRule",
        "ec2:DeleteTrafficMirrorFilter",
        "ec2:DeleteTrafficMirrorFilterRule",
        "ec2:DescribeTrafficMirrorFilters",
        "ec2:CreateTrafficMirrorSession",
        "ec2:DeleteTrafficMirrorSession",
        "ec2:DescribeTrafficMirrorSessions"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:*::parameter/aws/service/canonical/ubuntu/*"
    }
  ]
}
'@

$tmp = New-TemporaryFile
$tmpJson = "$($tmp.FullName).json"
Move-Item $tmp.FullName $tmpJson
Set-Content -Path $tmpJson -Value $policyJson -Encoding ASCII

# --- Apply ----------------------------------------------------------------
Write-Host "`nApplying policy to role '$RoleName' / '$PolicyName'..." -ForegroundColor Cyan
aws iam put-role-policy `
    --role-name $RoleName `
    --policy-name $PolicyName `
    --policy-document "file://$tmpJson"

Remove-Item $tmpJson -Force

# --- Verify ---------------------------------------------------------------
Write-Host "`nVerifying..." -ForegroundColor Cyan
$actions = aws iam get-role-policy `
    --role-name $RoleName `
    --policy-name $PolicyName `
    --query 'PolicyDocument.Statement[0].Action' `
    --output json | ConvertFrom-Json

$required = @(
    'ec2:CreateTrafficMirrorSession',
    'ec2:CreateNetworkInterface',
    'ec2:AttachNetworkInterface'
)
$missing = $required | Where-Object { $_ -notin $actions }
if ($missing) {
    Write-Error "Applied but required actions missing: $($missing -join ', ')"
}

Write-Host "`nSuccess. Role '$RoleName' now has $($actions.Count) EC2 actions." -ForegroundColor Green
Write-Host "The validate-detections.yml workflow can now be run from the Actions tab."
