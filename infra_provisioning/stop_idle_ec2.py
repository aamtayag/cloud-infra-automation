#!/usr/bin/env python3

# ###########################################################
# Script Name: stop_idle_ec2.py
# Description:
#   Stop running EC2 instances whose average CPUUtilization is below a user-specified threshold,
#   then email a summary via Amazon SES.
# Usage examples:
#   python stop_idle_ec2.py --threshold 2.5 --email-to you@email.com --email-from ops@email.com
#   python stop_idle_ec2.py --threshold 3 --regions ap-southeast-2 us-east-1 --lookback-minutes 90 --dry-run
#   python stop_idle_ec2.py --threshold 5 --tag Name=Env,Values=dev --tag Name=Owner,Values=team-a --email-to you@x --email-from ops@x
# Notes:
#   - Ensure SES is out of sandbox (or recipients verified) and emails are verified in the SES region used.
#   - Default CloudWatch period is 300s (5 min). Adjust with --period if needed.
# ###########################################################

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Iterable

import boto3
from botocore.exceptions import ClientError, BotoCoreError

MAX_CW_QUERIES = 500  # CloudWatch GetMetricData limit per request


def parse_args():
    p = argparse.ArgumentParser(description="Stop EC2 instances below a CPU threshold and email a report.")
    p.add_argument("--threshold", type=float, help="CPUUtilization average threshold (percent).", required=False)
    p.add_argument("--lookback-minutes", type=int, default=60, help="How many minutes back to average over. Default: 60")
    p.add_argument("--period", type=int, default=300, help="Metric period in seconds. Default: 300 (5 min)")
    p.add_argument("--regions", nargs="*", help="AWS regions to scan (space-separated). Defaults to current env/SDK region.")
    p.add_argument("--profile", help="AWS credential profile name.")
    p.add_argument("--email-to", required=True, help="Destination email address (SES).")
    p.add_argument("--email-from", required=True, help="Source/Sender email address (SES verified).")
    p.add_argument("--email-subject", default="[EC2 Idle Stopper] Summary of Stopped Instances")
    p.add_argument("--tag", action="append",
                   help="EC2 filter in form Name=TagKey,Values=val1;val2  (repeatable). Example: --tag Name=Env,Values=dev;test",
                   default=[])
    p.add_argument("--dry-run", action="store_true", help="Do not actually stop; just report what would happen.")
    p.add_argument("--ses-region", help="SES region to send email from (defaults to same region loop or env).")
    return p.parse_args()


def build_ec2_filters(tag_args: List[str]) -> List[Dict]:
    """
    Convert --tag Name=Key,Values=v1;v2 into EC2 describe filters.
    """
    filters = [{"Name": "instance-state-name", "Values": ["running"]}]
    for t in tag_args:
        try:
            parts = t.split(",")
            name_part = parts[0].strip()
            values_part = parts[1].strip()
            if not name_part.startswith("Name=") or not values_part.startswith("Values="):
                raise ValueError
            name = name_part.split("=", 1)[1]
            values = values_part.split("=", 1)[1].split(";")
            filters.append({"Name": name, "Values": [v.strip() for v in values if v.strip()]})
        except Exception:
            raise ValueError(f"Invalid --tag format: {t}. Expected Name=Key,Values=v1;v2")
    return filters


def chunked(it: List, size: int) -> Iterable[List]:
    for i in range(0, len(it), size):
        yield it[i:i+size]


def list_running_instances(session: boto3.Session, region: str, filters: List[Dict]) -> List[Dict]:
    ec2 = session.client("ec2", region_name=region)
    instances = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=filters):
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                instances.append(inst)
    return instances


def get_avg_cpu_for_instances(session: boto3.Session, region: str, instance_ids: List[str],
                              lookback_minutes: int, period: int) -> Dict[str, float]:
    """
    Use CloudWatch GetMetricData to fetch average CPUUtilization for many instances efficiently.
    Returns {instance_id: average} for instances with at least one datapoint.
    """
    cw = session.client("cloudwatch", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=lookback_minutes)

    results: Dict[str, float] = {}
    for batch in chunked(instance_ids, MAX_CW_QUERIES):
        queries = []
        for i, iid in enumerate(batch):
            q = {
                "Id": f"m{i}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                        "Dimensions": [{"Name": "InstanceId", "Value": iid}],
                    },
                    "Period": period,
                    "Stat": "Average",
                    "Unit": "Percent",
                },
                "ReturnData": True,
            }
            queries.append(q)

        try:
            resp = cw.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end, ScanBy="TimestampAscending")
        except (ClientError, BotoCoreError) as e:
            print(f"[{region}] ERROR get_metric_data: {e}", file=sys.stderr)
            continue

        # Map query index back to instance id
        for i, r in enumerate(resp.get("MetricDataResults", [])):
            iid = batch[i]
            vals = r.get("Values", [])
            if not vals:
                # No datapoints; skip or treat as 0? We skip to avoid stopping instances without data.
                continue
            avg = sum(vals) / len(vals)
            results[iid] = avg

        # Handle pagination of GetMetricData (not common when we provide explicit queries)
        next_token = resp.get("NextToken")
        while next_token:
            try:
                resp = cw.get_metric_data(NextToken=next_token)
            except (ClientError, BotoCoreError) as e:
                print(f"[{region}] ERROR get_metric_data(next): {e}", file=sys.stderr)
                break
            for i, r in enumerate(resp.get("MetricDataResults", [])):
                iid = batch[i]
                vals = r.get("Values", [])
                if not vals:
                    continue
                avg = sum(vals) / len(vals)
                results[iid] = avg
            next_token = resp.get("NextToken")

        # Be polite to API
        time.sleep(0.2)

    return results


def stop_instances(session: boto3.Session, region: str, instance_ids: List[str], dry_run: bool) -> Tuple[List[str], Dict[str, str]]:
    ec2 = session.client("ec2", region_name=region)
    stopped = []
    errors = {}
    if not instance_ids:
        return stopped, errors
    try:
        resp = ec2.stop_instances(InstanceIds=instance_ids, DryRun=dry_run)
        # If dry-run, API throws DryRunOperation; catch and treat as success
        # But botocore raises exception before returning resp; handle that:
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "DryRunOperation":
            # Consider all as "would stop"
            return instance_ids, errors
        else:
            # Partial failures possible when DryRun=false; try per-instance
            errors = {iid: str(e)}  # record bulk error
            # attempt individual stops
            for iid in instance_ids:
                try:
                    ec2.stop_instances(InstanceIds=[iid], DryRun=dry_run)
                    stopped.append(iid)
                except ClientError as ie:
                    errors[iid] = str(ie)
            return stopped, errors
    else:
        # Real stop call returned OK
        for st in resp.get("StoppingInstances", []):
            stopped.append(st.get("InstanceId"))
    return stopped, errors


def build_instance_name(tags: List[Dict]) -> str:
    if not tags:
        return ""
    for t in tags:
        if t.get("Key") == "Name" and t.get("Value"):
            return t["Value"]
    return ""


def send_email(session: boto3.Session, ses_region: str, email_from: str, email_to: str,
               subject: str, text_body: str, html_body: str):
    ses = session.client("ses", region_name=ses_region)
    ses.send_email(
        Source=email_from,
        Destination={"ToAddresses": [email_to]},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {
                "Text": {"Data": text_body, "Charset": "UTF-8"},
                "Html": {"Data": html_body, "Charset": "UTF-8"},
            },
        },
    )


# #####################################
# Main
# #####################################

def main():
    args = parse_args()

    # Prompt interactively if threshold wasn’t provided
    threshold = args.threshold
    if threshold is None:
        try:
            threshold = float(input("Enter CPU threshold (%) below which to stop instances: ").strip())
        except Exception:
            print("Invalid threshold input.", file=sys.stderr)
            sys.exit(2)

    # Prepare session
    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    # Determine regions
    regions = args.regions
    if not regions:
        if session.region_name:
            regions = [session.region_name]
        else:
            # Fallback to describe regions
            ec2_global = session.client("ec2", region_name="us-east-1")
            regions = [r["RegionName"] for r in ec2_global.describe_regions(AllRegions=False)["Regions"]]

    filters = build_ec2_filters(args.tag)  # includes running-state filter
    lookback = args.lookback_minutes
    period = args.period

    all_reports = []
    grand_total_checked = 0
    grand_total_stopped = 0

    for region in regions:
        print(f"[{region}] Scanning running instances ...")
        try:
            instances = list_running_instances(session, region, filters)
        except (ClientError, BotoCoreError) as e:
            print(f"[{region}] ERROR describe_instances: {e}", file=sys.stderr)
            continue

        instance_ids = [i["InstanceId"] for i in instances]
        id_to_meta = {i["InstanceId"]: i for i in instances}
        if not instance_ids:
            all_reports.append((region, [], [], 0))
            print(f"[{region}] No running instances matched filters.")
            continue

        cpu_avgs = get_avg_cpu_for_instances(session, region, instance_ids, lookback, period)

        # Decide which to stop
        candidates = []
        for iid, avg in cpu_avgs.items():
            if avg < threshold:
                candidates.append((iid, avg))

        # Try to stop (or simulate)
        to_stop_ids = [iid for iid, _ in candidates]
        stopped_ids, stop_errors = stop_instances(session, region, to_stop_ids, args.dry_run)

        # Build report rows
        rows = []
        for iid, avg in sorted(candidates, key=lambda x: x[1]):
            inst = id_to_meta.get(iid, {})
            name = build_instance_name(inst.get("Tags", []))
            rows.append({
                "InstanceId": iid,
                "Name": name,
                "AvgCPU%": round(avg, 3),
                "PrivateIp": inst.get("PrivateIpAddress", ""),
                "State": inst.get("State", {}).get("Name", ""),
                "Action": "WOULD_STOP" if args.dry_run else ("STOPPED" if iid in stopped_ids else "FAILED"),
                "Error": stop_errors.get(iid, "")
            })

        total_checked = len(cpu_avgs)
        total_stopped = len(stopped_ids)
        grand_total_checked += total_checked
        grand_total_stopped += total_stopped
        all_reports.append((region, rows, stop_errors, total_checked))

    # Compose email
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode = "DRY-RUN" if args.dry_run else "EXECUTION"
    header = (f"EC2 Idle Stopper ({mode})\n"
              f"Threshold: {threshold}% | Lookback: {lookback} min | Period: {period}s\n"
              f"Regions: {', '.join(regions)} | When: {now_str}\n"
              f"Checked instances with datapoints: {grand_total_checked}\n"
              f"Stopped instances: {grand_total_stopped}\n")

    text_lines = [header, "-" * 72]
    html_lines = [
        f"<h3>EC2 Idle Stopper ({mode})</h3>",
        f"<p><b>Threshold:</b> {threshold}% &nbsp; <b>Lookback:</b> {lookback} min &nbsp; <b>Period:</b> {period}s<br>"
        f"<b>Regions:</b> {', '.join(regions)}<br>"
        f"<b>When:</b> {now_str}<br>"
        f"<b>Checked:</b> {grand_total_checked} &nbsp; <b>Stopped:</b> {grand_total_stopped}</p>"
    ]

    for region, rows, errs, total_checked in all_reports:
        text_lines.append(f"\n[{region}] checked={total_checked} stopped={sum(1 for r in rows if r['Action'] in ('STOPPED', 'WOULD_STOP'))}")
        text_lines.append("InstanceId\tName\tAvgCPU%\tPrivateIp\tState\tAction\tError")
        for r in rows:
            text_lines.append(f"{r['InstanceId']}\t{r['Name']}\t{r['AvgCPU%']}\t{r['PrivateIp']}\t{r['State']}\t{r['Action']}\t{r['Error']}")
        if not rows:
            text_lines.append("(no candidates below threshold or no datapoints)")

        # HTML table
        html_lines.append(f"<h4>Region: {region}</h4>")
        if rows:
            html_lines.append("<table border='1' cellpadding='4' cellspacing='0'>"
                              "<tr><th>InstanceId</th><th>Name</th><th>AvgCPU%</th><th>PrivateIp</th>"
                              "<th>State</th><th>Action</th><th>Error</th></tr>")
            for r in rows:
                html_lines.append(
                    f"<tr><td>{r['InstanceId']}</td><td>{r['Name']}</td><td>{r['AvgCPU%']}</td>"
                    f"<td>{r['PrivateIp']}</td><td>{r['State']}</td><td>{r['Action']}</td><td>{r['Error']}</td></tr>"
                )
            html_lines.append("</table>")
        else:
            html_lines.append("<p><i>No candidates below threshold or no datapoints.</i></p>")

    text_body = "\n".join(text_lines)
    html_body = "\n".join(html_lines)

    # Choose an SES region: explicit > first EC2 region > session default
    ses_region = args.ses_region or (regions[0] if regions else session.region_name or "us-east-1")
    try:
        send_email(session, ses_region, args.email_from, args.email_to, args.email_subject, text_body, html_body)
        print(f"\nEmail sent to {args.email_to} via SES region {ses_region}.")
    except (ClientError, BotoCoreError) as e:
        print(f"\nWARNING: Failed to send SES email: {e}", file=sys.stderr)
        # Still exit 0; stopping likely succeeded even if email failed.

    # Exit code: 0 always (idempotent ops). You may choose to nonzero on failures if desired.


if __name__ == "__main__":
    try:
        main()
    except ValueError as ve:
        print(str(ve), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
