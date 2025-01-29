import boto3
import hashlib
import json
import yaml
import os
import datetime
from botocore.exceptions import ClientError

IAM_CLIENT = boto3.client("iam")
S3_CLIENT = boto3.client("s3")
SNS_CLIENT = boto3.client("sns")

# File Paths
HASH_FILE = "securityHashes.json"
SNAPSHOT_FILE = "securitySnapshots.yaml"
LOG_FILE = f"security-log-{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.log"

# SNS Topic ARN
SNS_TOPIC_ARN = "<your sns topic arn>"

log_entries = []

#Get hashes from json file:
def load_json_file(file_path):
    """Load JSON data from a file, returning an empty dictionary if the file does not exist."""
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except Exception as e:
        write_to_log(f"⚠️ Error loading {file_path}: {e}")
        return {}

#Save hash file if none exists, or update current file:
def save_json_file(file_path, data):
    """Save JSON data to a file."""
    try:
        with open(file_path, "w") as file:
            json.dump(data, file, indent=2)
    except Exception as e:
        write_to_log(f"⚠️ Error writing to {file_path}: {e}")

#Load snapshot file
def load_yaml_file(file_path):
    """Load YAML data from a file, returning an empty dictionary if the file does not exist."""
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r") as file:
            return yaml.safe_load(file) or {}
    except Exception as e:
        write_to_log(f"⚠️ Error loading {file_path}: {e}")
        return {}

#Save snapshot if none exists, or update current snapshot:
def save_yaml_file(file_path, data):
    """Save data to a YAML file."""
    try:
        with open(file_path, "w") as file:
            yaml.safe_dump(data, file)
    except Exception as e:
        write_to_log(f"⚠️ Error writing to {file_path}: {e}")

#Log file for all changes. If none, no log file will be generated:
def write_to_log(message):
    """Append messages to the log file."""
    log_entries.append(message)

#Send the log file in an SNS message:
def send_sns_message(messages):
    """Send a batch of messages to the SNS topic."""
    try:
        SNS_CLIENT.publish(TopicArn=SNS_TOPIC_ARN, Message=messages)
        write_to_log("✅ SNS message sent successfully!")
    except Exception as e:
        write_to_log(f"⚠️ Error sending SNS message: {e}")

#Sort all of data from the various functions into a dictionary:
def sort_dict(data):
    """Recursively sort dictionary keys and lists."""
    if isinstance(data, dict):
        return {k: sort_dict(v) for k, v in sorted(data.items())}
    elif isinstance(data, list):
        return sorted(data, key=lambda x: json.dumps(sort_dict(x), sort_keys=True))
    else:
        return data

#Compare the new output against the snapshot (new, old):
def format_changes(old_data, new_data):
    """Format changes with red '❌' for deletions and green '✅' for additions."""
    old_data_sorted = sort_dict(old_data)
    new_data_sorted = sort_dict(new_data)

    old_lines = json.dumps(old_data_sorted, indent=2).splitlines()
    new_lines = json.dumps(new_data_sorted, indent=2).splitlines()

    formatted_old = []
    formatted_new = []

    for line in old_lines:
        if line not in new_lines:
            formatted_old.append(f"❌ {line}")
        else:
            formatted_old.append(f"  {line}")

    for line in new_lines:
        if line not in old_lines:
            formatted_new.append(f"✅ {line}")
        else:
            formatted_new.append(f"  {line}")

    return "\n".join(formatted_old), "\n".join(formatted_new)

#Check for public buckets and add to the snapshot:
def is_bucket_public(bucket_name):
    """Check if the S3 bucket is public."""
    try:
        # Check Block Public Access settings
        public_access_block = S3_CLIENT.get_public_access_block(Bucket=bucket_name)
        block_config = public_access_block.get('PublicAccessBlockConfiguration', {})
        if block_config.get('BlockPublicAcls', False) or \
        block_config.get('IgnorePublicAcls', False) or \
        block_config.get('BlockPublicPolicy', False) or \
        block_config.get('RestrictPublicBuckets', False):
            return False
        elif not block_config.get('BlockPublicAcls', True) or \
            not block_config.get('IgnorePublicAcls', True) or \
            not block_config.get('BlockPublicPolicy', True) or \
            not block_config.get('RestrictPublicBuckets', True):
            return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            write_to_log(f"⚠️ No Public Access Block settings found for {bucket_name} (may be public).")
        else:
            write_to_log(f"⚠️ Error retrieving Public Access settings for {bucket_name}: {e}")

    try:
        acl = S3_CLIENT.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                write_to_log(f"✅ Bucket {bucket_name} is public via ACL.")
                return True
    except ClientError as e:
        write_to_log(f"⚠️ Error retrieving ACL for bucket {bucket_name}: {e}")

    try:
        policy = S3_CLIENT.get_bucket_policy(Bucket=bucket_name)
        policy_json = json.loads(policy['Policy'])
        for statement in policy_json.get('Statement', []):
            if statement.get('Effect') == 'Allow' and 'Principal' in statement and statement['Principal'] == '*':
                return True
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
            write_to_log(f"⚠️ Error retrieving policy for bucket {bucket_name}: {e}")

    return False

### IAM ROLE FUNCTIONS ###
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

### IAM USER FUNCTIONS ###
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

### S3 BUCKET POLICY FUNCTIONS ###
def get_bucket_data():
    """Retrieve all S3 buckets and their policies."""
    buckets = {}
    try:
        for bucket in S3_CLIENT.list_buckets()["Buckets"]:
            bucket_name = bucket["Name"]
            try:
                policy = json.loads(S3_CLIENT.get_bucket_policy(Bucket=bucket_name)["Policy"])
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    policy = {}  # No policy found
                else:
                    raise
            buckets[bucket_name] = {
                "policy": policy,
                "is_public": is_bucket_public(bucket_name)
            }
    except Exception as e:
        write_to_log(f"⚠️ Error retrieving S3 buckets: {e}")
    return buckets

#HASHING FUNCTION - Hash each output to validate integrity later:
def generate_hash(data):
    """Generate a SHA-256 hash for structured data."""
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()

#MAIN CHECK FUNCTION - Check for changes in IAM roles, users, and S3 buckets:
def check_security_integrity():
    """Check for new, changed, or deleted IAM roles, users, and S3 buckets."""
    stored_hashes = load_json_file(HASH_FILE)
    updated_hashes = {}

    stored_snapshots = load_yaml_file(SNAPSHOT_FILE)
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
            old_data, new_data = format_changes(stored_snapshots.get(f'role_{role}', {}), data)
            write_to_log(f"🔄 Changes:\nOLD:\n{old_data}\nNEW:\n{new_data}")
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
            old_data, new_data = format_changes(stored_snapshots.get(f'user_{user}', {}), data)
            write_to_log(f"🔄 Changes:\nOLD:\n{old_data}\nNEW:\n{new_data}")
            detected_changes = True

    for stored_user in stored_hashes.keys():
        if stored_user.startswith("user_") and stored_user.replace("user_", "") not in user_names:
            write_to_log(f"❌ IAM User Deleted: {stored_user.replace('user_', '')}\nDetails:\n{json.dumps(stored_snapshots.get(stored_user, {}), indent=2)}")
            detected_changes = True

    ### S3 Buckets ###
    latest_buckets = get_bucket_data()
    bucket_names = set(latest_buckets.keys())

    for bucket, data in latest_buckets.items():
        bucket_hash = generate_hash(data)
        updated_hashes[f"bucket_{bucket}"] = bucket_hash
        updated_snapshots[f"bucket_{bucket}"] = data

        if f"bucket_{bucket}" not in stored_hashes:
            write_to_log(f"🆕 New S3 Bucket: {bucket}\nDetails:\n{json.dumps(data, indent=2)}")
            detected_changes = True
        elif stored_hashes[f"bucket_{bucket}"] != bucket_hash:
            write_to_log(f"⚠️ S3 Bucket Modified: {bucket}")
            old_data, new_data = format_changes(stored_snapshots.get(f'bucket_{bucket}', {}), data)
            write_to_log(f"🔄 Changes:\nOLD:\n{old_data}\nNEW:\n{new_data}")
            detected_changes = True

    for stored_bucket in stored_hashes.keys():
        if stored_bucket.startswith("bucket_") and stored_bucket.replace("bucket_", "") not in bucket_names:
            write_to_log(f"❌ S3 Bucket Deleted: {stored_bucket.replace('bucket_', '')}\nDetails:\n{json.dumps(stored_snapshots.get(stored_bucket, {}), indent=2)}")
            detected_changes = True

    save_json_file(HASH_FILE, updated_hashes)
    save_yaml_file(SNAPSHOT_FILE, updated_snapshots)

    if detected_changes:
        with open(LOG_FILE, "w") as log_file:
            log_file.write("\n".join(log_entries))
        send_sns_message("\n".join(log_entries))

if __name__ == "__main__":
    check_security_integrity()
