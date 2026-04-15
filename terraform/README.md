# Terraform test harness

Spins up an Ubuntu 22.04 EC2 instance in `us-east-1` to test `standalone.sh`.

## Prereqs
- Terraform 1.5+ (`terraform -version`)
- AWS CLI configured (`aws sts get-caller-identity` works)
- EC2 key pair named `default` already exists in us-east-1
- Private key at `~/.ssh/default.pem` (chmod 400)

## Deploy
```bash
cd terraform
terraform init
terraform apply
```

Outputs include `public_ip` and a ready-to-paste `ssh_command`.

## Test the script
```bash
# from your laptop:
scp -i ~/.ssh/default.pem ../standalone.sh ubuntu@<public_ip>:/tmp/

# then ssh in:
ssh -i ~/.ssh/default.pem ubuntu@<public_ip>
sudo bash /tmp/standalone.sh --iface ens5
```

Find the interface name with `ip -br link` (usually `ens5` on t3 instances).

## Tear down
```bash
terraform destroy
```

Cost: t3.medium ~$0.04/hr + ~$0.002/hr for 20 GB gp3. Destroy when done.
