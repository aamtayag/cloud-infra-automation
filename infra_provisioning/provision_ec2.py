#!/usr/bin/env python3

# ###########################################################
# Script name: provision_ec2.py
# Description:
#   Provision and tag AWS EC2 instances
# Features:
#   - Create one or more EC2 instances with tags
#   - Idempotency by --name (reuses existing running/stopped instance if found)
#   - Optional creation of key pair and security group
#   - Optional IAM instance profile and user-data
#   - Dry-run support
#   - Outputs instance ID(s), state, public IP/DNS
# Usage:
#  ./provision_ec2.py \
#  --region ap-southeast-2 \
#  --name demo-web-01 \
#  --ami ami-0123456789abcdef0 \
#  --type t3.micro \
#  --subnet-id subnet-0abc123def456 \
#  --sg-name web-sg \
#  --create-sg \
#  --key-name demo-key \
#  --volume-size 16 \
#  --tag Environment=Dev --tag CostCenter=ENG
# Prereqs:
#   - pip install boto3
#   - AWS credentials via env vars, shared credentials file, SSO, or instance role
# ###########################################################

import argparse
import base64
import os
import sys
import time
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError


def parse_tags(tag_list: List[str]) -> List[Dict[str, str]]:
    tags = []
    for item in tag_list:
        if "=" not in item:
            raise ValueError(f"Invalid tag '{item}'. Use key=value.")
        k, v = item.split("=", 1)
        tags.append({"Key": k.strip(), "Value": v.strip()})
    return tags


def get_boto3_session(region: Optional[str], profile: Optional[str]):
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def get_existing_instances(ec2, name: str):
    flt = [
        {"Name": "tag:Name", "Values": [name]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}
    ]
    return list(ec2.instances.filter(Filters=flt))


def get_or_create_keypair(ec2_client, key_name: str, create_if_missing: bool, save_to: Optional[str] = None) -> str:
    try:
        ec2_client.describe_key_pairs(KeyNames=[key_name])
        return key_name
    except ClientError as e:
        if "InvalidKeyPair.NotFound" in str(e) and create_if_missing:
            kp = ec2_client.create_key_pair(KeyName=key_name)
            material = kp.get("KeyMaterial")
            if save_to:
                with open(save_to, "w", encoding="utf-8") as f:
                    os.chmod(save_to, 0o600)
                    f.write(material)
            return key_name
        raise


def get_or_create_sg(ec2_client, vpc_id: str, sg_name: str, create_if_missing: bool, description: str = "Managed by provision_ec2.py") -> str:
    # Try find SG by group-name (unique per VPC)
    resp = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [sg_name]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )
    if resp.get("SecurityGroups"):
        return resp["SecurityGroups"][0]["GroupId"]

    if not create_if_missing:
        raise RuntimeError(f"Security group '{sg_name}' not found in VPC {vpc_id} and --create-sg not set.")

    # Create with no ingress by default (least privilege)
    sg = ec2_client.create_security_group(
        GroupName=sg_name,
        Description=description,
        VpcId=vpc_id,
        TagSpecifications=[{
            "ResourceType": "security-group",
            "Tags": [{"Key": "Name", "Value": sg_name}]
        }]
    )
    return sg["GroupId"]


def read_user_data(user_data_path: Optional[str]) -> Optional[str]:
    if not user_data_path:
        return None
    with open(user_data_path, "rb") as f:
        data = f.read()
    # boto3 accepts raw string; api base64s. Keep plain text.
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # If it's binary cloud-init mime, base64-encode
        return base64.b64encode(data).decode("utf-8")


def get_vpc_id_for_subnet(ec2_client, subnet_id: str) -> str:
    resp = ec2_client.describe_subnets(SubnetIds=[subnet_id])
    return resp["Subnets"][0]["VpcId"]


def ensure_instance_profile_association(iam_profile: Optional[str]) -> Optional[Dict[str, str]]:
    if not iam_profile:
        return None
    # API expects dict with Name or Arn
    return {"Name": iam_profile}


def wait_for_instances(ec2_client, instance_ids: List[str], wait_state: str = "instance_running", timeout: int = 600):
    waiter = ec2_client.get_waiter(wait_state)
    waiter.config.delay = 10
    waiter.config.max_attempts = max(1, timeout // waiter.config.delay)
    waiter.wait(InstanceIds=instance_ids)


def main():
    p = argparse.ArgumentParser(description="Provision and tag AWS EC2 instances.")
    p.add_argument("--region", help="AWS region (e.g. ap-southeast-2)")
    p.add_argument("--profile", help="AWS profile name from ~/.aws/credentials")
    p.add_argument("--name", required=True, help="Name tag for the instance(s). Used for idempotency.")
    p.add_argument("--ami", required=True, help="AMI ID (e.g. ami-0abcdef1234567890)")
    p.add_argument("--type", default="t3.micro", help="Instance type (default: t3.micro)")
    p.add_argument("--count", type=int, default=1, help="Number of instances to create (default: 1)")
    p.add_argument("--subnet-id", required=True, help="Subnet ID to launch into")
    p.add_argument("--sg-id", help="Existing Security Group ID to attach")
    p.add_argument("--sg-name", help="Security Group name to find or create (requires --create-sg)")
    p.add_argument("--create-sg", action="store_true", help="Create the SG if not found (requires --sg-name)")
    p.add_argument("--key-name", help="Existing EC2 key pair name")
    p.add_argument("--create-key", action="store_true", help="Create the key pair if missing (requires --key-name)")
    p.add_argument("--save-key-to", help="Path to save created private key (chmod 600 will be applied)")
    p.add_argument("--volume-size", type=int, default=20, help="Root volume size in GiB (default: 20)")
    p.add_argument("--iam-instance-profile", help="IAM instance profile name to attach")
    p.add_argument("--user-data", help="Path to user-data (cloud-init) file")
    p.add_argument("--tag", action="append", default=[], help="Additional tag key=value (repeatable)")
    p.add_argument("--dry-run", action="store_true", help="Perform a dry run without creating resources")
    p.add_argument("--reuse-by-name", action="store_true", help="If an instance with the same Name exists, reuse instead of creating")
    args = p.parse_args()

    session = get_boto3_session(args.region, args.profile)
    ec2 = session.resource("ec2")
    ec2_client = session.client("ec2")

    # Idempotency: reuse by Name if requested
    if args.reuse_by_name:
        existing = get_existing_instances(ec2, args.name)
        if existing:
            print(f"[INFO] Found {len(existing)} existing instance(s) with Name={args.name}.")
            for inst in existing:
                inst.reload()
                print(f" - {inst.id} | state={inst.state['Name']} | public_ip={inst.public_ip_address} | public_dns={inst.public_dns_name}")
            sys.exit(0)

    # Key pair handling
    key_name = None
    if args.key_name:
        key_name = get_or_create_keypair(
            ec2_client,
            key_name=args.key_name,
            create_if_missing=args.create_key,
            save_to=args.save_key_to
        )

    # Security group handling
    if args.sg_id:
        sg_id = args.sg_id
    else:
        if not args.sg_name:
            raise SystemExit("ERROR: Provide --sg-id OR (--sg-name and optionally --create-sg).")
        vpc_id = get_vpc_id_for_subnet(ec2_client, args.subnet_id)
        sg_id = get_or_create_sg(
            ec2_client,
            vpc_id=vpc_id,
            sg_name=args.sg_name,
            create_if_missing=args.create_sg
        )

    # Prepare block device mapping (root volume)
    block_devices = [{
        "DeviceName": "/dev/xvda",
        "Ebs": {
            "VolumeSize": args.volume_size,
            "VolumeType": "gp3",
            "DeleteOnTermination": True,
            "Encrypted": True
        }
    }]

    # Tags
    extra_tags = parse_tags(args.tag)
    all_tags = [{"Key": "Name", "Value": args.name}] + extra_tags
    tag_spec = [
        {"ResourceType": "instance", "Tags": all_tags},
        {"ResourceType": "volume", "Tags": all_tags},
        {"ResourceType": "network-interface", "Tags": all_tags},
    ]

    user_data = read_user_data(args.user_data)
    iam_profile = ensure_instance_profile_association(args.iam_instance_profile)

    # Launch
    try:
        resp = ec2_client.run_instances(
            ImageId=args.ami,
            InstanceType=args.type,
            MinCount=args.count,
            MaxCount=args.count,
            KeyName=key_name,
            SubnetId=args.subnet_id,
            SecurityGroupIds=[sg_id],
            BlockDeviceMappings=block_devices,
            IamInstanceProfile=iam_profile,
            UserData=user_data,
            TagSpecifications=tag_spec,
            DryRun=args.dry_run
        )
    except ClientError as e:
        # Special-case DryRun
        if args.dry_run and "DryRunOperation" in str(e):
            print("[DRY-RUN] API permissions and parameters look valid.")
            return
        raise

    instance_ids = [i["InstanceId"] for i in resp["Instances"]]
    print(f"[INFO] Launched instance(s): {', '.join(instance_ids)}")
    print("[INFO] Waiting for instances to enter 'running' state...")
    wait_for_instances(ec2_client, instance_ids, "instance_running", timeout=900)

    # Describe to print IP/DNS
    desc = ec2_client.describe_instances(InstanceIds=instance_ids)
    for r in desc["Reservations"]:
        for inst in r["Instances"]:
            iid = inst["InstanceId"]
            state = inst["State"]["Name"]
            pub_ip = inst.get("PublicIpAddress")
            pub_dns = inst.get("PublicDnsName")
            az = inst.get("Placement", {}).get("AvailabilityZone")
            print(f"✅ {iid} | state={state} | az={az} | public_ip={pub_ip} | public_dns={pub_dns}")


if __name__ == "__main__":
    main()
