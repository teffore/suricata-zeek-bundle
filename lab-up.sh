#!/bin/bash
# lab-up.sh — provision the Suricata+Zeek 3-box lab (attacker / victim /
# sensor) with traffic mirror, install the full stack, and print the
# purple_agent.py invocation to run against it. Mirrors CI workflow
# .github/workflows/validate-detections.yml but kept running indefinitely
# until lab-down.sh is invoked.
#
# Usage:  ./lab-up.sh
#
# Requires: AWS credentials exported (aws sts get-caller-identity must
# work), jq on PATH, ssh/scp/ssh-keygen/curl on PATH.
#
# Cost:   ~$0.13/hr for 3 t3.medium + VPC traffic-mirror fees.
# Output: .lab-state (env-sourcable), .lab-key + .lab-key.pub, cheat sheet
#         on stdout.

set -euo pipefail

# Git Bash / MSYS aggressively rewrites args that look like Unix paths (e.g.
# /dev/sda1, 0.0.0.0/0) into Windows paths before passing to native AWS CLI.
# Disable that for the whole script — our args are never local paths.
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
STATE_FILE="$SCRIPT_DIR/.lab-state"
KEY_FILE="$SCRIPT_DIR/.lab-key"
LOG_DIR="$SCRIPT_DIR/.install-logs"

AWS_REGION="${AWS_REGION:-us-east-1}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.medium}"
# Pinned Kali Linux AMI (us-east-1). Attacker only — sensor + victim stay Ubuntu
# because standalone.sh targets Ubuntu 22.04.
KALI_AMI_ID="${KALI_AMI_ID:-ami-003fa928ba1faa587}"
export AWS_DEFAULT_REGION="$AWS_REGION"

# ---------- prereqs ----------
for bin in aws jq ssh-keygen ssh scp curl; do
  command -v "$bin" >/dev/null 2>&1 \
    || { echo "FAIL: $bin not in PATH" >&2; exit 1; }
done
aws sts get-caller-identity >/dev/null 2>&1 \
  || { echo "FAIL: AWS credentials not configured" >&2; exit 1; }
[ -e "$STATE_FILE" ] && {
  echo "FAIL: $STATE_FILE exists — prior lab not torn down. Run lab-down.sh." >&2
  exit 1
}

RUN_TAG="purple-lab-$(whoami | tr -cd 'a-z0-9')-$(date +%s)"
echo "=== $RUN_TAG ==="

# ---------- SSH key ----------
rm -f "$KEY_FILE" "$KEY_FILE.pub"
ssh-keygen -t ed25519 -f "$KEY_FILE" -N '' -q
chmod 600 "$KEY_FILE"
# AWS CLI on Windows can't parse /c/... paths in fileb://; cygpath -m gives a
# native-style path AWS CLI accepts. No-op on Linux.
KEY_PUB_NATIVE="$KEY_FILE.pub"
command -v cygpath >/dev/null && KEY_PUB_NATIVE="$(cygpath -m "$KEY_FILE.pub")"
aws ec2 import-key-pair --key-name "$RUN_TAG" \
  --public-key-material "fileb://$KEY_PUB_NATIVE" >/dev/null
echo "  key registered"

# ---------- context ----------
MY_IP=$(curl -fsSL https://checkip.amazonaws.com | tr -d '[:space:]')
# ec2:DescribeImages is broader in IAM policies than ssm:GetParameter — use it
# instead of the public SSM AMI param which some principals can't read.
AMI_ID=$(aws ec2 describe-images --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
            "Name=state,Values=available" "Name=architecture,Values=x86_64" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text)
VPC_ID=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)
SUBNET_ID=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=$VPC_ID Name=default-for-az,Values=true \
  --query 'Subnets[0].SubnetId' --output text)
echo "  ip=$MY_IP  ami=$AMI_ID  vpc=$VPC_ID  subnet=$SUBNET_ID"

# ---------- security group ----------
SG_ID=$(aws ec2 create-security-group --group-name "$RUN_TAG" \
  --description "persistent purple-team lab" --vpc-id "$VPC_ID" \
  --tag-specifications "ResourceType=security-group,Tags=[{Key=PurpleLabRunTag,Value=$RUN_TAG}]" \
  --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "$MY_IP/32" >/dev/null
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
  --protocol -1 --source-group "$SG_ID" >/dev/null
echo "  sg=$SG_ID (ssh from $MY_IP/32, intra-SG any-any for VXLAN)"

# ---------- launch 3 instances ----------
# Second arg is the AMI so attacker can get Kali while sensor+victim stay Ubuntu.
launch() {
  local role="$1" ami="$2"
  aws ec2 run-instances --image-id "$ami" --instance-type "$INSTANCE_TYPE" \
    --key-name "$RUN_TAG" --security-group-ids "$SG_ID" --subnet-id "$SUBNET_ID" \
    --associate-public-ip-address \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3}' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$RUN_TAG-$role},{Key=PurpleLabRunTag,Value=$RUN_TAG},{Key=Role,Value=$role}]" \
    --query 'Instances[0].InstanceId' --output text
}
echo "=== launching sensor / victim / attacker (attacker=Kali) ==="
SENSOR_ID=$(launch sensor   "$AMI_ID")
VICTIM_ID=$(launch victim   "$AMI_ID")
ATTACKER_ID=$(launch attacker "$KALI_AMI_ID")
echo "  sensor=$SENSOR_ID  victim=$VICTIM_ID  attacker=$ATTACKER_ID"

# ---------- wait for running + networking ----------
for ID in $SENSOR_ID $VICTIM_ID $ATTACKER_ID; do
  for i in $(seq 1 60); do
    S=$(aws ec2 describe-instances --instance-ids "$ID" \
      --query 'Reservations[0].Instances[0].State.Name' --output text)
    [ "$S" = "running" ] && break
    sleep 2
  done
  [ "$S" = "running" ] || { echo "FAIL: $ID stuck at $S" >&2; exit 1; }
done

describe() {
  aws ec2 describe-instances --instance-ids "$1" \
    --query "Reservations[0].Instances[0].$2" --output text
}
SENSOR_IP=$(describe $SENSOR_ID PublicIpAddress)
VICTIM_IP=$(describe $VICTIM_ID PublicIpAddress)
ATTACKER_IP=$(describe $ATTACKER_ID PublicIpAddress)
VICTIM_PRIVATE=$(describe $VICTIM_ID PrivateIpAddress)
ATTACKER_PRIVATE=$(describe $ATTACKER_ID PrivateIpAddress)
SENSOR_ENI=$(describe $SENSOR_ID 'NetworkInterfaces[0].NetworkInterfaceId')
VICTIM_ENI=$(describe $VICTIM_ID 'NetworkInterfaces[0].NetworkInterfaceId')
ATTACKER_ENI=$(describe $ATTACKER_ID 'NetworkInterfaces[0].NetworkInterfaceId')
# Source/dest check must be off on the mirror-target ENI so mirrored frames
# with arbitrary inner IPs aren't dropped by the Nitro NIC.
aws ec2 modify-network-interface-attribute \
  --network-interface-id "$SENSOR_ENI" --no-source-dest-check
echo "  sensor=$SENSOR_IP  victim=$VICTIM_IP  attacker=$ATTACKER_IP"

# ---------- state file (written early so lab-down can recover partial) ----------
cat >"$STATE_FILE" <<EOF
RUN_TAG=$RUN_TAG
REGION=$AWS_REGION
KEY_FILE=$KEY_FILE
SG_ID=$SG_ID
SENSOR_ID=$SENSOR_ID
VICTIM_ID=$VICTIM_ID
ATTACKER_ID=$ATTACKER_ID
SENSOR_IP=$SENSOR_IP
VICTIM_IP=$VICTIM_IP
ATTACKER_IP=$ATTACKER_IP
VICTIM_PRIVATE=$VICTIM_PRIVATE
ATTACKER_PRIVATE=$ATTACKER_PRIVATE
SENSOR_ENI=$SENSOR_ENI
VICTIM_ENI=$VICTIM_ENI
ATTACKER_ENI=$ATTACKER_ENI
EOF

# ---------- wait for SSH + cloud-init (parallel) ----------
SSH_OPTS="-i $KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
# Attacker is Kali (default user 'kali'); sensor + victim are Ubuntu.
# Kali's cloud-init status --wait can exit non-zero on "degraded but done"
# states; tolerate it and gate on a follow-up `echo ready` SSH.
wait_box() {
  local IP="$1" USER="${2:-ubuntu}"
  for i in $(seq 1 60); do
    ssh $SSH_OPTS -o BatchMode=yes "$USER"@"$IP" true 2>/dev/null && break
    sleep 5
  done
  ssh $SSH_OPTS "$USER"@"$IP" "cloud-init status --wait || true" >/dev/null 2>&1
  ssh $SSH_OPTS "$USER"@"$IP" "echo ready" >/dev/null \
    || { echo "[$USER@$IP] post-cloud-init SSH failed"; return 1; }
}
echo "=== waiting for SSH + cloud-init on all three (~2 min) ==="
wait_box "$SENSOR_IP"   ubuntu & SP=$!
wait_box "$VICTIM_IP"   ubuntu & VP=$!
wait_box "$ATTACKER_IP" kali   & AP=$!
wait $SP; wait $VP; wait $AP
echo "  reachable"

# ---------- sensor NIC: promisc + jumbo MTU for VXLAN frames ----------
ssh $SSH_OPTS ubuntu@"$SENSOR_IP" '
  IF=$(ip -o link show | awk -F": " "{print \$2}" | grep -v lo | head -1)
  sudo ip link set "$IF" promisc on
  sudo ip link set "$IF" mtu 9001
' >/dev/null
echo "  sensor NIC: promisc + mtu 9001"

# ---------- install stack in parallel ----------
# scp install scripts, strip CRLF on remote (Windows Git Bash writes CRLF
# and remote bash chokes on \r), then run.
rm -rf "$LOG_DIR" && mkdir -p "$LOG_DIR"
echo "=== installing stacks in parallel ($LOG_DIR/) ==="
(
  scp $SSH_OPTS "$REPO_ROOT/standalone.sh"              ubuntu@"$SENSOR_IP":/tmp/standalone.sh
  scp $SSH_OPTS "$REPO_ROOT/testing/verify_alerts.sh"   ubuntu@"$SENSOR_IP":/tmp/verify_alerts.sh
  scp $SSH_OPTS "$REPO_ROOT/testing/probe_catalog.json" ubuntu@"$SENSOR_IP":/tmp/probe_catalog.json
  # Bundle the purple-*.zeek behavioral scripts so standalone.sh can install them
  # into /opt/zeek/share/zeek/site/ and @load them from local.zeek.
  if [ -d "$REPO_ROOT/zeek/site" ]; then
    ssh $SSH_OPTS ubuntu@"$SENSOR_IP" "mkdir -p /tmp/purple-zeek"
    scp $SSH_OPTS "$REPO_ROOT"/zeek/site/*.zeek ubuntu@"$SENSOR_IP":/tmp/purple-zeek/
  fi
  ssh $SSH_OPTS ubuntu@"$SENSOR_IP" "sudo sed -i 's/\r\$//' /tmp/standalone.sh /tmp/verify_alerts.sh /tmp/purple-zeek/*.zeek 2>/dev/null || true"
  ssh $SSH_OPTS ubuntu@"$SENSOR_IP" "sudo bash /tmp/standalone.sh --force"
  ssh $SSH_OPTS ubuntu@"$SENSOR_IP" "systemctl is-active suricata && sudo /opt/zeek/bin/zeekctl status && sudo apt-get install -y -qq tcpdump jq"
) >"$LOG_DIR/sensor.log" 2>&1 &
SP=$!
(
  scp $SSH_OPTS "$REPO_ROOT/testing/victim_setup.sh" ubuntu@"$VICTIM_IP":/tmp/victim_setup.sh
  ssh $SSH_OPTS ubuntu@"$VICTIM_IP" "sudo sed -i 's/\r\$//' /tmp/victim_setup.sh"
  ssh $SSH_OPTS ubuntu@"$VICTIM_IP" "sudo bash /tmp/victim_setup.sh"
) >"$LOG_DIR/victim.log" 2>&1 &
VP=$!
(
  # Attacker is Kali — SSH as 'kali', not 'ubuntu'.
  scp $SSH_OPTS "$REPO_ROOT/testing/attacker_setup.sh" kali@"$ATTACKER_IP":/tmp/attacker_setup.sh
  scp $SSH_OPTS "$REPO_ROOT/testing/run_attacks.sh"    kali@"$ATTACKER_IP":/tmp/run_attacks.sh
  ssh $SSH_OPTS kali@"$ATTACKER_IP" "sudo sed -i 's/\r\$//' /tmp/attacker_setup.sh /tmp/run_attacks.sh"
  ssh $SSH_OPTS kali@"$ATTACKER_IP" "sudo bash /tmp/attacker_setup.sh && chmod +x /tmp/run_attacks.sh"
) >"$LOG_DIR/attacker.log" 2>&1 &
AP=$!
fail=0
wait $SP || { echo "SENSOR install failed — see $LOG_DIR/sensor.log"   >&2; fail=1; }
wait $VP || { echo "VICTIM install failed — see $LOG_DIR/victim.log"   >&2; fail=1; }
wait $AP || { echo "ATTACKER install failed — see $LOG_DIR/attacker.log" >&2; fail=1; }
[ $fail -eq 0 ] || exit 1
echo "  all stacks installed"

# ---------- traffic mirror (dual-session, same as CI) ----------
echo "=== creating traffic-mirror plumbing ==="
TGT_ID=$(aws ec2 create-traffic-mirror-target \
  --network-interface-id "$SENSOR_ENI" \
  --description "$RUN_TAG-tgt" \
  --tag-specifications "ResourceType=traffic-mirror-target,Tags=[{Key=PurpleLabRunTag,Value=$RUN_TAG}]" \
  --query 'TrafficMirrorTarget.TrafficMirrorTargetId' --output text)

# Victim mirror: VNI=1, captures ALL victim traffic
FILTER_ID=$(aws ec2 create-traffic-mirror-filter --description "$RUN_TAG-flt" \
  --tag-specifications "ResourceType=traffic-mirror-filter,Tags=[{Key=PurpleLabRunTag,Value=$RUN_TAG}]" \
  --query 'TrafficMirrorFilter.TrafficMirrorFilterId' --output text)
aws ec2 create-traffic-mirror-filter-rule --traffic-mirror-filter-id "$FILTER_ID" \
  --traffic-direction ingress --rule-number 100 --rule-action accept \
  --destination-cidr-block 0.0.0.0/0 --source-cidr-block 0.0.0.0/0 >/dev/null
aws ec2 create-traffic-mirror-filter-rule --traffic-mirror-filter-id "$FILTER_ID" \
  --traffic-direction egress  --rule-number 100 --rule-action accept \
  --destination-cidr-block 0.0.0.0/0 --source-cidr-block 0.0.0.0/0 >/dev/null
SESS_ID=$(aws ec2 create-traffic-mirror-session \
  --network-interface-id "$VICTIM_ENI" \
  --traffic-mirror-target-id "$TGT_ID" --traffic-mirror-filter-id "$FILTER_ID" \
  --session-number 1 --virtual-network-id 1 --description "$RUN_TAG-sess" \
  --tag-specifications "ResourceType=traffic-mirror-session,Tags=[{Key=PurpleLabRunTag,Value=$RUN_TAG}]" \
  --query 'TrafficMirrorSession.TrafficMirrorSessionId' --output text)

# Attacker mirror: VNI=2, rejects attacker<->victim to prevent double-capture
FILTER_A_ID=$(aws ec2 create-traffic-mirror-filter --description "$RUN_TAG-flt-a" \
  --tag-specifications "ResourceType=traffic-mirror-filter,Tags=[{Key=PurpleLabRunTag,Value=$RUN_TAG}]" \
  --query 'TrafficMirrorFilter.TrafficMirrorFilterId' --output text)
aws ec2 create-traffic-mirror-filter-rule --traffic-mirror-filter-id "$FILTER_A_ID" \
  --traffic-direction egress  --rule-number 50  --rule-action reject \
  --source-cidr-block 0.0.0.0/0 --destination-cidr-block "$VICTIM_PRIVATE/32" >/dev/null
aws ec2 create-traffic-mirror-filter-rule --traffic-mirror-filter-id "$FILTER_A_ID" \
  --traffic-direction ingress --rule-number 50  --rule-action reject \
  --destination-cidr-block 0.0.0.0/0 --source-cidr-block "$VICTIM_PRIVATE/32" >/dev/null
aws ec2 create-traffic-mirror-filter-rule --traffic-mirror-filter-id "$FILTER_A_ID" \
  --traffic-direction egress  --rule-number 100 --rule-action accept \
  --source-cidr-block 0.0.0.0/0 --destination-cidr-block 0.0.0.0/0 >/dev/null
aws ec2 create-traffic-mirror-filter-rule --traffic-mirror-filter-id "$FILTER_A_ID" \
  --traffic-direction ingress --rule-number 100 --rule-action accept \
  --source-cidr-block 0.0.0.0/0 --destination-cidr-block 0.0.0.0/0 >/dev/null
SESS_A_ID=$(aws ec2 create-traffic-mirror-session \
  --network-interface-id "$ATTACKER_ENI" \
  --traffic-mirror-target-id "$TGT_ID" --traffic-mirror-filter-id "$FILTER_A_ID" \
  --session-number 2 --virtual-network-id 2 --description "$RUN_TAG-sess-a" \
  --tag-specifications "ResourceType=traffic-mirror-session,Tags=[{Key=PurpleLabRunTag,Value=$RUN_TAG}]" \
  --query 'TrafficMirrorSession.TrafficMirrorSessionId' --output text)

cat >>"$STATE_FILE" <<EOF
TGT_ID=$TGT_ID
FILTER_ID=$FILTER_ID
FILTER_A_ID=$FILTER_A_ID
SESS_ID=$SESS_ID
SESS_A_ID=$SESS_A_ID
EOF
sleep 15  # let AWS program the mirror before declaring it live

# ---------- cheat sheet ----------
cat <<EOF

========================================================================
=== LAB IS UP — $RUN_TAG
========================================================================

State:  $STATE_FILE
Key:    $KEY_FILE
Cost:   ~\$0.13/hr until you run lab-down.sh

Public IPs:
  sensor   = $SENSOR_IP
  victim   = $VICTIM_IP
  attacker = $ATTACKER_IP

Private IPs (attack targets): victim=$VICTIM_PRIVATE  attacker=$ATTACKER_PRIVATE

SSH one-liners (copy-paste) — attacker uses 'kali' user, others 'ubuntu':
  ssh -i $KEY_FILE ubuntu@$SENSOR_IP
  ssh -i $KEY_FILE ubuntu@$VICTIM_IP
  ssh -i $KEY_FILE kali@$ATTACKER_IP

Recipes:
  # Full CI attack battery (same as validate-detections.yml runs)
  ssh -i $KEY_FILE kali@$ATTACKER_IP "sudo bash /tmp/run_attacks.sh $VICTIM_PRIVATE"

  # Watch Suricata + Zeek detections live
  ssh -i $KEY_FILE ubuntu@$SENSOR_IP "sudo tail -F /var/log/suricata/fast.log /opt/zeek/logs/current/notice.log"

  # Coverage gate (same as CI)
  ssh -i $KEY_FILE ubuntu@$SENSOR_IP "sudo bash /tmp/verify_alerts.sh"

*** Purple-team agent invocation ***
  uv run --with claude-agent-sdk --with PyYAML python purple_agent.py \\
    --attacker-ip $ATTACKER_IP --sensor-ip $SENSOR_IP \\
    --victim-ip $VICTIM_PRIVATE --key $KEY_FILE --budget 30

Tear down when done:
  ./lab-down.sh

========================================================================
EOF
