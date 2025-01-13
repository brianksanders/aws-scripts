#!/bin/bash

# Variables
VPC_ID="<VPC_ID>" #Add the VPC ID here. This is the only required input.
PUBLIC_SUBNET_ID=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=*public*" \
    --query "Subnets[*].SubnetId" \
    --output text | awk '{print $1}')
PRIVATE_ROUTE_TABLE_IDS=$(aws ec2 describe-route-tables \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=*private*" \
    --query "RouteTables[*].RouteTableId" \
    --output text)

# Step 1: Allocate an Elastic IP and save the ID to a variable
echo "Allocating Elastic IP..."
ALLOC_ID=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)
echo "Allocated Elastic IP with Allocation ID: $ALLOC_ID"

# Step 2: Create a NAT Gateway
echo "Creating NAT Gateway..."
NAT_GATEWAY_ID=$(aws ec2 create-nat-gateway \
    --subnet-id $PUBLIC_SUBNET_ID \
    --allocation-id $ALLOC_ID \
    --query 'NatGateway.NatGatewayId' \
    --output text)
echo "NAT Gateway created with ID: $NAT_GATEWAY_ID"

# Wait for NAT Gateway to become available
echo "Waiting for NAT Gateway to become available..."
aws ec2 wait nat-gateway-available --nat-gateway-ids $NAT_GATEWAY_ID
echo "NAT Gateway is available."

# Step 3: Associate the NAT Gateway with Private Subnets
for ROUTE_TABLE_ID in $PRIVATE_ROUTE_TABLE_IDS; do
    echo "Updating route table $ROUTE_TABLE_ID to route traffic through NAT Gateway..."
    aws ec2 create-route \
        --route-table-id $ROUTE_TABLE_ID \
        --destination-cidr-block 0.0.0.0/0 \
        --nat-gateway-id $NAT_GATEWAY_ID
    echo "Route table $ROUTE_TABLE_ID updated."
done


echo "NAT Gateway setup complete!"
echo "NAT Gateway ID: $NAT_GATEWAY_ID"
