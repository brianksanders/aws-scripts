#!/bin/bash

# Required: Define variables
AMI_ID="<AMI_ID>" 
INSTANCE_TYPE="t2.micro"
SUBNET_ID="<SUBNET_ID>"
SECURITY_GROUP_ID="<SECURITY_GROUP_ID>"
TAG_NAME="TestInstance"
PUBLIC_IP="true"         # Set to "true" or "false" based on whether you need a public IP

# Optional: Define IAM Role, Key Pair, Public IP, and User Data
IAM_ROLE_NAME=""         # Leave empty if no role is needed
KEY_PAIR_NAME=""         # Leave empty if no key pair is needed
USER_DATA_FILE=""        # Path to the user data script (e.g., /path/to/user-data.sh), leave empty if none

# Construct the base command
CMD="aws ec2 run-instances \
    --image-id $AMI_ID \
    --count 1 \
    --instance-type $INSTANCE_TYPE \
    --subnet-id $SUBNET_ID \
    --security-group-ids $SECURITY_GROUP_ID \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=$TAG_NAME}]' \
    --query 'Instances[0].InstanceId' \
    --output text"

# Add IAM role if specified
if [ -n "$IAM_ROLE_NAME" ]; then
    CMD+=" --iam-instance-profile Name=$IAM_ROLE_NAME"
fi

# Add key pair if specified
if [ -n "$KEY_PAIR_NAME" ]; then
    CMD+=" --key-name $KEY_PAIR_NAME"
fi

# Add public IP option if specified
if [ "$PUBLIC_IP" == "true" ]; then
    CMD+=" --associate-public-ip-address"
fi

# Add user data if specified
if [ -n "$USER_DATA_FILE" ]; then
    CMD+=" --user-data file://$USER_DATA_FILE"
fi

# Execute the command and capture the instance ID
INSTANCE_ID=$(eval $CMD)

# Output the launched instance ID
echo "Launched EC2 instance with Instance ID: $INSTANCE_ID"
