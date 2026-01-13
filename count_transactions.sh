#!/bin/bash

# Count total transactions in Celestia height range 37-428
# Server: 51.159.171.247

RETH_RPC="http://51.159.171.247:8545"
EV_NODE="http://51.159.171.247:7331"
CELESTIA_RPC="http://51.159.171.247:26658"
NAMESPACE="a8045f161bf468bf4d44"

echo "Querying Celestia blobs from height 37 to 428..."
echo "This will show how many EVM blocks need to be executed."
echo ""

# Use the middleware endpoint to get the data
MIDDLEWARE="http://51.159.171.247:9091"

# Query middleware to see what blocks it would process
# We need to figure out the trusted height/root first
# Let's just query a few blocks manually to understand the pattern

total_txs=0
blocks_with_data=0

# Sample a few heights to see the pattern
for height in 37 50 100 200 300 400 428; do
    echo -n "Checking height $height... "

    # Query Celestia for blobs at this height
    response=$(curl -s -X POST "$CELESTIA_RPC" \
        -H "Content-Type: application/json" \
        -d "{
            \"jsonrpc\": \"2.0\",
            \"id\": 1,
            \"method\": \"blob.GetAll\",
            \"params\": [$height, [\"$NAMESPACE\"]]
        }")

    # Check if we got blobs
    blob_count=$(echo "$response" | jq -r '.result | length // 0')

    if [ "$blob_count" -gt 0 ]; then
        echo "Found $blob_count blob(s)"
        blocks_with_data=$((blocks_with_data + 1))
    else
        echo "No blobs"
    fi
done

echo ""
echo "To get exact transaction count, we need to decode the blobs and query the EVM blocks they reference."
echo "The middleware does this automatically. Let's check the RETH endpoint for block range..."
echo ""

# Try to get the latest block from RETH
latest=$(curl -s -X POST "$RETH_RPC" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    | jq -r '.result')

echo "Latest EVM block: $latest ($(printf "%d" $latest))"
