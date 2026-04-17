# AWS setup for the Actions workflows

Two workflows provision ephemeral AWS resources per run:

- `validate-standalone.yml` — one EC2, install-only smoke test. Runs on every
  push that touches `standalone.sh`.
- `validate-detections.yml` — three EC2s (sensor, victim, attacker) plus a
  VPC Traffic Mirror session, end-to-end detection validation. Manual
  trigger only. Requires Nitro-family instance types (t3/m5/c5/...) —
  VPC Traffic Mirroring is not supported on non-Nitro hardware.

This is a one-time setup — do it once and every future run works.

## What you're creating

1. A **GitHub OIDC provider** in IAM (once per AWS account).
2. An **IAM role** that GitHub Actions assumes via OIDC federation. No
   long-lived access keys anywhere.
3. One **repo secret** (`AWS_ROLE_ARN`) pointing at that role.

## 1. GitHub OIDC provider

In the IAM console → Identity providers → Add provider:

- Provider type: **OpenID Connect**
- Provider URL: `https://token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`

AWS auto-verifies the thumbprint. Only do this once per account.

## 2. IAM role

Create a role with **Web identity** as the trusted entity, using the OIDC
provider from step 1. When prompted, set `sts.amazonaws.com` as the audience
and `repo:teffore/suricata-zeek-bundle:*` as the repository filter.

### Trust policy (paste exactly)

Replace `YOUR_ACCOUNT_ID` with your 12-digit AWS account ID.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:teffore/suricata-zeek-bundle:*"
        }
      }
    }
  ]
}
```

The `sub` condition scopes the role to this repo only — another repo in your
account can't assume it even if they know the ARN.

### Permissions policy (paste exactly)

This is the minimum both workflows need. No `iam:*`, no `s3:*`, nothing
outside EC2 + a read of the Ubuntu AMI ID from SSM Parameter Store.

```json
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
```

The network-interface and traffic-mirror actions are only used by
`validate-detections.yml`. If you don't plan to run that workflow, you
can omit the bottom half of the first statement — `validate-standalone.yml`
works with just the original action set.

## 3. Add the role ARN to the repo

Once the role is created, copy its ARN (e.g.
`arn:aws:iam::123456789012:role/github-actions-suricata-zeek`) and add it as
a repo secret:

- Repo → Settings → Secrets and variables → Actions → New repository secret
- Name: `AWS_ROLE_ARN`
- Value: the role ARN

That's it. Next push to `main` that touches `standalone.sh` will trigger
the workflow.

## Cost

Per `validate-standalone.yml` run:

- EC2 t3.medium on-demand: ~$0.0416/hr → ~$0.005 for a 7-min run
- 20 GB gp3 volume: ~$0.08/GB-month → negligible at 7 min
- Data out (AMI pulls, apt, PPA): few MB, negligible

Typical run: **under $0.01**.

Per `validate-detections.yml` run:

- 3× t3.medium on-demand for ~15 min ≈ $0.03
- 3× 20 GB gp3 for ~15 min ≈ $0.001
- VPC Traffic Mirroring: free when source and target are in the same AZ
- Data out: negligible (attack traffic stays intra-VPC)

Typical run: **~$0.05**. Actions runner minutes are separate but free on
public repos.

## Manual trigger

You can also run the workflow ad-hoc from the Actions tab via the
**Run workflow** button (comes from the `workflow_dispatch` trigger).

## Fork PRs

Fork-based PRs will fail at the OIDC step. This is intentional: GitHub
does not hand out OIDC tokens with the right `sub` claim to fork PRs, so
they cannot assume your AWS role. Same-repo branch PRs and pushes to
`main` work normally.

## Troubleshooting

- **`Could not assume role`**: check the `sub` condition in the trust
  policy matches your actual repo path (`repo:<owner>/<repo>:*`).
- **`UnauthorizedOperation`**: the permission policy is missing an
  EC2 action. Copy it again from above.
- **Instance launches but SSH never connects**: default VPC may be
  missing or has no default subnet. Recreate the default VPC from the
  VPC console or set the region to one that has one.
