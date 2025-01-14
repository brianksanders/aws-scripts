#!/bin/bash

# Input: Specify the VPC ID
VPC_ID="<your-vpc-id>"  # Replace with your VPC ID

# Step 1: Retrieve the NAT Gateway ID
echo "Fetching NAT Gateway ID associated with VPC $VPC_ID..."
NAT_GATEWAY_ID=$(aws ec2 describe-nat-gateways \
    --filter "Name=vpc-id,Values=$VPC_ID" \
    --query "NatGateways[?State=='available'].[NatGatewayId]" \
    --output text)

if [ -z "$NAT_GATEWAY_ID" ]; then
    echo "Error: No available NAT Gateway found in VPC $VPC_ID. Exiting."
    exit 1
fi

echo "Found NAT Gateway ID: $NAT_GATEWAY_ID"

echo "Fetching private route table IDs associated with VPC $VPC_ID..."
PRIVATE_ROUTE_TABLE_IDS=$(aws ec2 describe-route-tables \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=*private*" \
    --query "RouteTables[*].RouteTableId" \
    --output text)

echo "Fetching Elastic IP associated with NAT Gateway..."
ALLOC_ID=$(aws ec2 describe-nat-gateways \
    --nat-gateway-ids $NAT_GATEWAY_ID \
    --query 'NatGateways[0].NatGatewayAddresses[0].AllocationId' \
    --output text)

if [ "$ALLOC_ID" == "None" ] || [ -z "$ALLOC_ID" ]; then
    echo "No Elastic IP associated with the NAT Gateway. Exiting."
    exit 1
else
    echo "Found Elastic IP Allocation ID: $ALLOC_ID"
fi

# Step 2: Delete Routes in Private Subnets
for ROUTE_TABLE_ID in $PRIVATE_ROUTE_TABLE_IDS; do
    echo "Checking for routes associated with NAT Gateway in route table $ROUTE_TABLE_ID..."
    ROUTE_EXISTS=$(aws ec2 describe-route-tables \
        --route-table-ids $ROUTE_TABLE_ID \
        --query "RouteTables[0].Routes[?NatGatewayId=='$NAT_GATEWAY_ID'].DestinationCidrBlock" \
        --output text)
    
    if [ "$ROUTE_EXISTS" != "None" ]; then
        echo "Removing route to NAT Gateway from route table $ROUTE_TABLE_ID..."
        aws ec2 delete-route \
            --route-table-id $ROUTE_TABLE_ID \
            --destination-cidr-block 0.0.0.0/0
        echo "Route removed from route table $ROUTE_TABLE_ID."
    else
        echo "No route to NAT Gateway found in route table $ROUTE_TABLE_ID."
    fi
done

# Step 3: Delete the NAT Gateway
echo "Deleting NAT Gateway $NAT_GATEWAY_ID..."
aws ec2 delete-nat-gateway --nat-gateway-id $NAT_GATEWAY_ID

# Wait for NAT Gateway to be deleted
echo "Waiting for NAT Gateway to be deleted..."
aws ec2 wait nat-gateway-deleted --nat-gateway-ids $NAT_GATEWAY_ID
echo "NAT Gateway deleted."

# Step 4: Release the Elastic IP
echo "Releasing Elastic IP with Allocation ID: $ALLOC_ID..."
aws ec2 release-address --allocation-id $ALLOC_ID
echo "Elastic IP released."

echo "Cleanup complete!"
