import boto3
import hashlib
import json
import yaml
import datetime
from deepdiff import DeepDiff
from botocore.exceptions import ClientError

S3_BUCKET_NAME = "<your logging bucket name>"
IAM_CLIENT = boto3.client("iam")
SNS_CLIENT = boto3.client("sns")
S3_CLIENT = boto3.client("s3")

# File Paths
HASH_FILE = "securityHashes.json"
SNAPSHOT_FILE = "securitySnapshots.yaml"

# SNS Topic ARN
SNS_TOPIC_ARN = "<your sns topic arn>"

log_entries = []

def load_s3_json(file_key):
    """Load JSON data from S3, returning an empty dictionary if not found."""
    try:
        response = S3_CLIENT.get_object(Bucket=S3_BUCKET_NAME, Key=file_key)
        return json.loads(response["Body"].read().decode("utf-8"))
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            return {}  # No file exists yet
        raise

def save_s3_json(file_key, data):
    """Save JSON data to S3."""
    S3_CLIENT.put_object(Bucket=S3_BUCKET_NAME, Key=file_key, Body=json.dumps(data, indent=2))

def load_s3_yaml(file_key):
    """Load YAML data from S3, returning an empty dictionary if not found."""
    try:
        response = S3_CLIENT.get_object(Bucket=S3_BUCKET_NAME, Key=file_key)
        return yaml.safe_load(response["Body"].read().decode("utf-8")) or {}
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            return {}  # No file exists yet
        raise

def save_s3_yaml(file_key, data):
    """Save YAML data to S3."""
    S3_CLIENT.put_object(Bucket=S3_BUCKET_NAME, Key=file_key, Body=yaml.safe_dump(data))

def write_to_log(message):
    """Append messages to the log file."""
    log_entries.append(message)

def send_sns_message(messages):
    """Send a batch of messages to the SNS topic."""
    try:
        SNS_CLIENT.publish(TopicArn=SNS_TOPIC_ARN, Message=messages)
        write_to_log("✅ SNS message sent successfully!")
    except Exception as e:
        write_to_log(f"⚠️ Error sending SNS message: {e}")

def sort_dict(data):
    """Recursively sort dictionary keys and lists."""
    if isinstance(data, dict):
        return {k: sort_dict(v) for k, v in sorted(data.items())}
    elif isinstance(data, list):
        return sorted(data, key=lambda x: json.dumps(sort_dict(x), sort_keys=True))
    else:
        return data

def format_changes(old_data, new_data):
    """Use DeepDiff to detect meaningful changes with ❌ for removals and ✅ for additions, formatted cleanly."""
    diff = DeepDiff(old_data, new_data, ignore_order=True, verbose_level=2)
    formatted_changes = []

    if "dictionary_item_added" in diff:
        for path, value in diff["dictionary_item_added"].items():
            formatted_changes.append(f"✅ Added: {path}\n    {json.dumps(value, indent=2)}\n")

    if "dictionary_item_removed" in diff:
        for path, value in diff["dictionary_item_removed"].items():
            formatted_changes.append(f"❌ Removed: {path}\n    {json.dumps(value, indent=2)}\n")

    if "values_changed" in diff:
        for path, details in diff["values_changed"].items():
            formatted_changes.append(
                f"🔄 Modified: {path}\n"
                f"    ❌ OLD: {json.dumps(details['old_value'], indent=2)}\n"
                f"    ✅ NEW: {json.dumps(details['new_value'], indent=2)}\n"
            )

    if "iterable_item_added" in diff:
        for path, value in diff["iterable_item_added"].items():
            formatted_changes.append(f"✅ Added to {path}:\n    {json.dumps(value, indent=2)}\n")

    if "iterable_item_removed" in diff:
        for path, value in diff["iterable_item_removed"].items():
            formatted_changes.append(f"❌ Removed from {path}:\n    {json.dumps(value, indent=2)}\n")

    if not formatted_changes:
        return "No significant changes."

    return "\n".join(formatted_changes)

def get_role_data():
    """Retrieve all IAM roles and relevant security configurations."""
    roles = {}
    try:
        for role in IAM_CLIENT.list_roles()["Roles"]:
            role_name = role["RoleName"]
            roles[role_name] = {
                "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                "attached_policies": sorted(
                    [p["PolicyArn"] for p in IAM_CLIENT.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]]
                ),
                "inline_policies": {
                    policy: IAM_CLIENT.get_role_policy(RoleName=role_name, PolicyName=policy)["PolicyDocument"]
                    for policy in IAM_CLIENT.list_role_policies(RoleName=role_name)["PolicyNames"]
                },
            }
    except Exception as e:
        write_to_log(f"⚠️ Error retrieving IAM roles: {e}")
    return roles

def get_user_data():
    """Retrieve all IAM users and their attached/inline policies and groups."""
    users = {}
    try:
        for user in IAM_CLIENT.list_users()["Users"]:
            user_name = user["UserName"]
            users[user_name] = {
                "attached_policies": sorted(
                    [p["PolicyArn"] for p in IAM_CLIENT.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]]
                ),
                "inline_policies": {
                    policy: IAM_CLIENT.get_user_policy(UserName=user_name, PolicyName=policy)["PolicyDocument"]
                    for policy in IAM_CLIENT.list_user_policies(UserName=user_name)["PolicyNames"]
                },
                "groups": sorted(
                    [g["GroupName"] for g in IAM_CLIENT.list_groups_for_user(UserName=user_name)["Groups"]]
                ),
            }
    except Exception as e:
        write_to_log(f"⚠️ Error retrieving IAM users: {e}")
    return users

def generate_hash(data):
    """Generate a SHA-256 hash for structured data."""
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()

def check_security_integrity():
    """Check for new, changed, or deleted IAM roles, users, and S3 buckets."""
    stored_hashes = load_s3_json(HASH_FILE)
    updated_hashes = {}

    stored_snapshots = load_s3_yaml(SNAPSHOT_FILE)
    updated_snapshots = {}

    detected_changes = False

    ### IAM Roles ###
    latest_roles = get_role_data()
    role_names = set(latest_roles.keys())

    for role, data in latest_roles.items():
        role_hash = generate_hash(data)
        updated_hashes[f"role_{role}"] = role_hash
        updated_snapshots[f"role_{role}"] = data

        if f"role_{role}" not in stored_hashes:
            write_to_log(f"🆕 New IAM Role: {role}\nDetails:\n{json.dumps(data, indent=2)}")
            detected_changes = True
        elif stored_hashes[f"role_{role}"] != role_hash:
            write_to_log(f"⚠️ IAM Role Modified: {role}")
            changes = format_changes(stored_snapshots.get(f'role_{role}', {}), data)
            if changes.strip():
                write_to_log(f"🔄 Changes:\n{changes}")
            detected_changes = True

    for stored_role in stored_hashes.keys():
        if stored_role.startswith("role_") and stored_role.replace("role_", "") not in role_names:
            write_to_log(f"❌ IAM Role Deleted: {stored_role.replace('role_', '')}\nDetails:\n{json.dumps(stored_snapshots.get(stored_role, {}), indent=2)}")
            detected_changes = True

    ### IAM Users ###
    latest_users = get_user_data()
    user_names = set(latest_users.keys())

    for user, data in latest_users.items():
        user_hash = generate_hash(data)
        updated_hashes[f"user_{user}"] = user_hash
        updated_snapshots[f"user_{user}"] = data

        if f"user_{user}" not in stored_hashes:
            write_to_log(f"🆕 New IAM User: {user}\nDetails:\n{json.dumps(data, indent=2)}")
            detected_changes = True
        elif stored_hashes[f"user_{user}"] != user_hash:
            write_to_log(f"⚠️ IAM User Modified: {user}")
            changes = format_changes(stored_snapshots.get(f'user_{user}', {}), data)
            if changes.strip():
                write_to_log(f"🔄 Changes:\n{changes}")
            detected_changes = True

    for stored_user in stored_hashes.keys():
        if stored_user.startswith("user_") and stored_user.replace("user_", "") not in user_names:
            write_to_log(f"❌ IAM User Deleted: {stored_user.replace('user_', '')}\nDetails:\n{json.dumps(stored_snapshots.get(stored_user, {}), indent=2)}")
            detected_changes = True

    save_s3_json(HASH_FILE, updated_hashes)
    save_s3_yaml(SNAPSHOT_FILE, updated_snapshots)

    if detected_changes:
        log_content = "\n".join(log_entries)
        now = datetime.datetime.now()
        log_file_name = f"security-log-{now.strftime('%Y-%m-%d-%H-%M-%S')}.log"
        log_file_path = f"logs/{now.year}/{now.month}/{now.day}/{log_file_name}"
        S3_CLIENT.put_object(Bucket=S3_BUCKET_NAME, Key=log_file_path, Body=log_content)
        send_sns_message(log_content)

def lambda_handler(event, context):
    """AWS Lambda entry point."""
    check_security_integrity()
    return {
        "statusCode": 200,
        "body": json.dumps("IAM Security Check Completed Successfully!")
    }
