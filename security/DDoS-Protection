import boto3
import datetime
import gzip
from collections import defaultdict

# AWS Clients
S3_CLIENT = boto3.client("s3")
SNS_CLIENT = boto3.client("sns")
WAFV2_CLIENT = boto3.client("wafv2")  # AWS WAFv2 API

# Configuration
S3_BUCKET = "<your-alb-logging-bucket-name>"
SNS_TOPIC_ARN = "<your-sns-topic-arn>"
REQUEST_THRESHOLD = 10  # Adjust threshold as needed
WAF_IP_SET_ID = "<IPset ID number>"  # Replace with your AWS WAF IP Set ID number, NOT the name. 
WAF_SCOPE = "REGIONAL"  # Change to CLOUDFRONT if applied to CloudFront
WAF_REGION = "us-east-1"  # Change to your region

# --- Retrieve Latest ALB Log File ---
def get_latest_log_file(bucket_name, prefix):
    """Fetch the most recent ALB log file from the given S3 prefix."""
    try:
        response = S3_CLIENT.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        if "Contents" not in response:
            print(f"⚠️ No log files found under prefix {prefix}")
            return None

        # Get the latest log file by LastModified timestamp
        latest_log = max(response["Contents"], key=lambda x: x["LastModified"])
        return latest_log["Key"]

    except Exception as e:
        print(f"⚠️ Error retrieving latest ALB log file: {e}")
        return None

# --- Load & Decompress ALB Log File ---
def load_alb_logs(bucket_name, log_key):
    """Load and decompress a Gzipped ALB log file from S3."""
    try:
        response = S3_CLIENT.get_object(Bucket=bucket_name, Key=log_key)
        compressed_body = response["Body"].read()  # Read compressed content

        # Decompress using gzip
        decompressed_body = gzip.decompress(compressed_body).decode("utf-8")
        
        return decompressed_body.splitlines()  # Return as a list of log lines

    except Exception as e:
        print(f"⚠️ Error loading log file {log_key}: {e}")
        return []

# --- Analyze Logs for DDoS Patterns ---
def analyze_logs(log_data):
    """Analyze ALB logs to detect high request rates per IP."""
    ip_counts = defaultdict(int)

    for line in log_data:
        parts = line.split(" ")
        if len(parts) < 5:
            continue  # Skip invalid lines

        # Extract client IP correctly (split IP:port and take only the IP)
        ip_address = parts[3].split(":")[0]  # Extracts only the IP portion

        ip_counts[ip_address] += 1

    return {ip: count for ip, count in ip_counts.items() if count > REQUEST_THRESHOLD}

# --- Send SNS Alert for DDoS Activity ---
def send_sns_alert(violations):
    """Send an SNS alert for detected DDoS-like activity."""
    if not violations:
        return

    message = "🚨 Potential DDoS Attack Detected 🚨\n\n"
    for ip, count in violations.items():
        message += f"- {ip}: {count} requests\n"

    try:
        SNS_CLIENT.publish(TopicArn=SNS_TOPIC_ARN, Message=message, Subject="AWS ALB DDoS Alert")
        print("✅ SNS alert sent successfully!")
    except Exception as e:
        print(f"⚠️ Error sending SNS alert: {e}")

# --- AWS WAF Integration ---
def get_waf_ip_set_lock_token():
    """Retrieve WAF IP Set lock token (needed for updates)."""
    try:
        response = WAFV2_CLIENT.get_ip_set(
            Name="DDoSBlockedIP",  # Keep the name for reference
            Scope=WAF_SCOPE,
            Id=WAF_IP_SET_ID  # Use the corrected ID
        )
        return response["LockToken"], response["IPSet"]["Addresses"]
    except Exception as e:
        print(f"⚠️ Error retrieving WAF IP Set: {e}")
        return None, []
def update_waf_ip_set(ip_addresses):
    """Update WAF IP Set with new blocked IPs."""
    lock_token, existing_ips = get_waf_ip_set_lock_token()
    if not lock_token:
        return

    # Convert detected IPs to CIDR format
    new_ips = [f"{ip}/32" for ip in ip_addresses]
    all_ips = list(set(existing_ips + new_ips))  # Prevent duplicates

    try:
        response = WAFV2_CLIENT.update_ip_set(
            Name="DDoSBlockedIP",
            Scope=WAF_SCOPE,
            Id=WAF_IP_SET_ID,
            LockToken=lock_token,
            Addresses=all_ips
        )
        print(f"✅ WAF updated! Blocked IPs: {new_ips}")
    except Exception as e:
        print(f"⚠️ Error updating WAF: {e}")

# --- Lambda Handler ---
def lambda_handler(event, context):
    """AWS Lambda entry point."""
    today = datetime.datetime.utcnow()
    prefix = f"AWSLogs/527274894823/elasticloadbalancing/us-east-1/{today.year}/{str(today.month).zfill(2)}/{str(today.day).zfill(2)}/"
    
    log_key = get_latest_log_file(S3_BUCKET, prefix)
    if not log_key:
        print("⚠️ No logs found for today.")
        return

    log_data = load_alb_logs(S3_BUCKET, log_key)
    if not log_data:
        print("⚠️ Log file is empty.")
        return

    violations = analyze_logs(log_data)
    if violations:
        print(f"🚨 DDoS-like activity detected: {violations}")
        send_sns_alert(violations)
        update_waf_ip_set(violations.keys())  # Block IPs in AWS WAF
    else:
        print("✅ No abnormal traffic detected.")
