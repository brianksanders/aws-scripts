#!/bin/bash

# Variables
NAT_GATEWAY_ID="<nat-gateway-id>"  # Update with your NAT Gateway ID
PRIVATE_ROUTE_TABLE_IDS=("<route-table-id-1>" "<route-table-id-2>")  # Replace with your route table IDs

# Step 1: Delete Routes in Private Subnets
for ROUTE_TABLE_ID in "${PRIVATE_ROUTE_TABLE_IDS[@]}"; do
    echo "Removing NAT Gateway route from route table $ROUTE_TABLE_ID..."
    aws ec2 delete-route \
        --route-table-id $ROUTE_TABLE_ID \
        --destination-cidr-block 0.0.0.0/0
    echo "Route removed from route table $ROUTE_TABLE_ID."
done

# Step 2: Delete the NAT Gateway
echo "Deleting NAT Gateway $NAT_GATEWAY_ID..."
aws ec2 delete-nat-gateway --nat-gateway-id $NAT_GATEWAY_ID

# Wait for NAT Gateway to be deleted
echo "Waiting for NAT Gateway to be deleted..."
aws ec2 wait nat-gateway-deleted --nat-gateway-ids $NAT_GATEWAY_ID
echo "NAT Gateway deleted."

# Step 3: Release the Elastic IP
ALLOC_ID=$(aws ec2 describe-addresses --filters "Name=association.nat-gateway-id,Values=$NAT_GATEWAY_ID" --query 'Addresses[0].AllocationId' --output text)
if [ "$ALLOC_ID" != "None" ]; then
    echo "Releasing Elastic IP with Allocation ID: $ALLOC_ID..."
    aws ec2 release-address --allocation-id $ALLOC_ID
    echo "Elastic IP released."
else
    echo "No Elastic IP found to release."
fi

echo "NAT Gateway removal complete!"
