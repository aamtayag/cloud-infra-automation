#!/usr/bin/env python3


# ###########################################################
# Script Name: deploy_sit_env.py
# Description:
#   Provision or shut down an AWS EC2 instance used as an SIT environment.
# Usage:
#   Bring UP an SIT env named 'mrsg-sit' in ap-southeast-2
#   python deploy_sit_env.py --action up --env-name mrsg-sit --region ap-southeast-2 \
#   --ami-id ami-0123456789abcdef0 --subnet-id subnet-abc123 --sg-ids sg-1a2b3c4d \
#   --instance-type t3.medium --key-name mykey --volume-size 50
#
#   Bring DOWN (stop) that environment:
#   python deploy_sit_env.py --action down --env-name mrsg-sit --region ap-southeast-2
#
#   Bring DOWN and TERMINATE it (delete instance):
#   python deploy_sit_env.py --action down --env-name mrsg-sit --terminate --region ap-southeast-2
# Notes:
#   - Identifies SIT instances by tags: Environment=SIT, EnvName=<env-name>.
#   - "down" defaults to STOP (keeps EBS volume). Use --terminate to fully remove the instance.
# ###########################################################

import argparse
import sys
from typing import List, Optional, Dict
import boto3
from botocore.exceptions import ClientError, BotoCoreError

SIT_TAG_ENVIRONMENT = "Environment"
SIT_TAG_ENVIRONMENT_VALUE = "SIT"
SIT_TAG_ENVNAME = "MRSGSIT001"

USER_DATA_BASH = r"""#!/bin/bash
set -eux
# Basic bootstrap for SIT (Ubuntu/Amazon Linux friendly)
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y git curl unzip jq
elif command -v yum >/dev/null 2>&1; then
  yum update -y
  yum install -y git curl unzip jq
fi
# Time sync and log hint
timedatectl || true
echo "SIT bootstrap complete: $(date -Is)" | tee /var/log/sit-bootstrap.log
"""

def parse_args():
    p = argparse.ArgumentParser(description="Spin up or shut down an EC2-based SIT environment.")
    p.add_argument("--action", choices=["up", "down"], required=True, help="up = create; down = stop/terminate")
    p.add_argument("--env-name", required=True, help="Logical name for the SIT env (e.g., mrsg-sit)")
    p.add_argument("--region", required=True, help="AWS region, e.g., ap-southeast-2")
    p.add_argument("--profile", help="AWS credential profile")

    # Creation options (used when --action up)
    p.add_argument("--ami-id", help="AMI ID to launch (required for 'up')")
    p.add_argument("--instance-type", default="t3.medium", help="EC2 instance type (default: t3.medium)")
    p.add_argument("--subnet-id", help="Subnet ID for the instance (required for 'up')")
    p.add_argument("--sg-ids", nargs="+", help="One or more Security Group IDs (required for 'up')")
    p.add_argument("--key-name", help="EC2 key pair name (optional)")
    p.add_argument("--iam-instance-profile", help="Instance profile name or ARN (optional)")
    p.add_argument("--volume-size", type=int, default=30, help="Root EBS volume size in GiB (default: 30)")
    p.add_argument("--user-data-file", help="Path to a custom user-data script (optional)")
    p.add_argument("--no-public-ip", action="store_true", help="Do not associate a public IP")

    # Down options
    p.add_argument("--terminate", action="store_true", help="When --action down, terminate instead of stop")
    p.add_argument("--include-stopped", action="store_true", help="Also match stopped instances (default: running only)")

    # Misc
    p.add_argument("--dry-run", action="store_true", help="Validate permissions without making changes")
    return p.parse_args()

def session_for(region: str, profile: Optional[str] = None) -> boto3.Session:
    return boto3.Session(region_name=region, profile_name=profile) if profile else boto3.Session(region_name=region)

def build_tags(env_name: str) -> List[Dict[str, str]]:
    return [
        {"Key": "Name", "Value": f"SIT-{env_name}"},
        {"Key": SIT_TAG_ENVIRONMENT, "Value": SIT_TAG_ENVIRONMENT_VALUE},
        {"Key": SIT_TAG_ENVNAME, "Value": env_name},
    ]

def get_user_data(path: Optional[str]) -> str:
    if not path:
        return USER_DATA_BASH
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def create_sit_instance(
    sess: boto3.Session,
    *,
    env_name: str,
    ami_id: str,
    instance_type: str,
    subnet_id: str,
    sg_ids: List[str],
    key_name: Optional[str],
    iam_instance_profile: Optional[str],
    volume_size: int,
    user_data: str,
    no_public_ip: bool,
    dry_run: bool
) -> Dict:
    ec2 = sess.client("ec2")
    ni = {
        "DeviceIndex": 0,
        "SubnetId": subnet_id,
        "Groups": sg_ids,
        "AssociatePublicIpAddress": (not no_public_ip),
    }
    block_device_mappings = [{
        "DeviceName": "/dev/xvda",
        "Ebs": {
            "VolumeSize": volume_size,
            "VolumeType": "gp3",
            "DeleteOnTermination": True
        }
    }]

    params = {
        "ImageId": ami_id,
        "InstanceType": instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        "NetworkInterfaces": [ni],
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": build_tags(env_name)},
            {"ResourceType": "volume",   "Tags": build_tags(env_name)},
        ],
        "BlockDeviceMappings": block_device_mappings,
        "UserData": user_data,
        "DryRun": dry_run
    }
    if key_name:
        params["KeyName"] = key_name
    if iam_instance_profile:
        params["IamInstanceProfile"] = {"Name": iam_instance_profile} if ":" not in iam_instance_profile else {"Arn": iam_instance_profile}

    try:
        resp = ec2.run_instances(**params)
    except ClientError as e:
        # If dry-run, AWS throws DryRunOperation when you have perms
        if e.response.get("Error", {}).get("Code") == "DryRunOperation":
            return {"dry_run": True, "message": "DryRunOperation: you have permission to run instances."}
        raise

    instance = resp["Instances"][0]
    instance_id = instance["InstanceId"]
    print(f"Launched instance: {instance_id}")

    # Wait until running
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id])
    desc = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    return {
        "dry_run": False,
        "instance_id": instance_id,
        "state": desc["State"]["Name"],
        "private_ip": desc.get("PrivateIpAddress"),
        "public_ip": desc.get("PublicIpAddress"),
        "az": desc.get("Placement", {}).get("AvailabilityZone"),
    }

def find_sit_instances(sess: boto3.Session, env_name: str, include_stopped: bool) -> List[Dict]:
    ec2 = sess.client("ec2")
    states = ["pending", "running", "stopping", "stopped"] if include_stopped else ["running"]
    filters = [
        {"Name": f"tag:{SIT_TAG_ENVIRONMENT}", "Values": [SIT_TAG_ENVIRONMENT_VALUE]},
        {"Name": f"tag:{SIT_TAG_ENVNAME}", "Values": [env_name]},
        {"Name": "instance-state-name", "Values": states}
    ]
    paginator = ec2.get_paginator("describe_instances")
    found = []
    for page in paginator.paginate(Filters=filters):
        for res in page.get("Reservations", []):
            found.extend(res.get("Instances", []))
    return found

def down_sit_instances(sess: boto3.Session, instances: List[Dict], terminate: bool, dry_run: bool) -> Dict:
    ec2 = sess.client("ec2")
    ids = [i["InstanceId"] for i in instances]
    if not ids:
        return {"affected": [], "dry_run": dry_run}

    try:
        if terminate:
            if dry_run:
                # Dry-run via per-call to show proper behavior
                for iid in ids:
                    try:
                        ec2.terminate_instances(InstanceIds=[iid], DryRun=True)
                    except ClientError as e:
                        if e.response.get("Error", {}).get("Code") != "DryRunOperation":
                            raise
                return {"affected": ids, "dry_run": True, "action": "terminate"}
            resp = ec2.terminate_instances(InstanceIds=ids, DryRun=False)
            action = "terminate"
        else:
            if dry_run:
                for iid in ids:
                    try:
                        ec2.stop_instances(InstanceIds=[iid], DryRun=True)
                    except ClientError as e:
                        if e.response.get("Error", {}).get("Code") != "DryRunOperation":
                            raise
                return {"affected": ids, "dry_run": True, "action": "stop"}
            resp = ec2.stop_instances(InstanceIds=ids, DryRun=False)
            action = "stop"
    except ClientError as e:
        # Bubble up meaningful errors (e.g., UnauthorizedOperation)
        raise

    # Optionally wait
    waiter_name = "instance_terminated" if terminate else "instance_stopped"
    waiter = ec2.get_waiter(waiter_name)
    waiter.wait(InstanceIds=ids)
    return {"affected": ids, "dry_run": False, "action": action}


# #####################################
# Main
# #####################################

def main():
    args = parse_args()
    sess = session_for(args.region, args.profile)

    try:
        if args.action == "up":
            # Validate required args
            missing = []
            for k in [("ami-id", args.ami_id), ("subnet-id", args.subnet_id), ("sg-ids", args.sg_ids)]:
                if not k[1]:
                    missing.append(k[0])
            if missing:
                print(f"Missing required arguments for 'up': {', '.join(missing)}", file=sys.stderr)
                sys.exit(2)

            ud = get_user_data(args.user_data_file)
            result = create_sit_instance(
                sess,
                env_name=args.env_name,
                ami_id=args.ami_id,
                instance_type=args.instance_type,
                subnet_id=args.subnet_id,
                sg_ids=args.sg_ids,
                key_name=args.key_name,
                iam_instance_profile=args.iam_instance_profile,
                volume_size=args.volume_size,
                user_data=ud,
                no_public_ip=args.no_public_ip,
                dry_run=args.dry_run
            )
            if result.get("dry_run"):
                print("[DRY-RUN] You have permission to create the SIT instance.")
            else:
                print("SIT instance is up:")
                print(f"  InstanceId : {result['instance_id']}")
                print(f"  State      : {result['state']}")
                print(f"  Private IP : {result.get('private_ip')}")
                print(f"  Public IP  : {result.get('public_ip')}")
                print(f"  AZ         : {result.get('az')}")

        else:  # down
            instances = find_sit_instances(sess, args.env_name, args.include_stopped or args.terminate)
            if not instances:
                print("No SIT instances matched the given env-name and state filters.")
                sys.exit(0)
            ids = [i["InstanceId"] for i in instances]
            print(f"Matched instances: {', '.join(ids)}")
            result = down_sit_instances(sess, instances, args.terminate, args.dry_run)
            if result.get("dry_run"):
                print(f"[DRY-RUN] Would {result['action']} instances: {', '.join(result['affected'])}")
            else:
                print(f"Successfully {result['action']}ped instances: {', '.join(result['affected'])}")

    except (ClientError, BotoCoreError) as e:
        print(f"AWS error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
