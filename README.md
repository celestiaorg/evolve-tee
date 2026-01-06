# Evolve Light Client using ZKPs of TEE Attestations
This project consists of two components that enable TEE attestations over Evolve State Roots:

`app`: The Phala application that attests to the replay of the executor inputs for a range of blocks

`circuit`: The SP1 program that verifies the attestation and outputs  previous_state || new_state

`light-client`: Block verification logic that depends largely on `celestia-zkevm`

## Prerequisites
There exists a docker image in [celestia-zkevm](https://github.com/celestiaorg/celestia-zkevm/blob/main/docker-compose.yml) that includes everything (ev-node, ev-reth, celestia-app, zkism deployment).

```
git clone git@github.com:celestiaorg/celestia-zkevm
cd celestia-zkevm
make start && make deploy-ism && make update-ism
```

## Publish the Phala app's docker image
```
phala docker build

phala docker push
```

## Deploy the Phala TEE instance
```
phala deploy --interactive
```

This will output a URL to the Phala dashboard for the newly created instance.
Navigate to `dashboard=>Network` and find the RPC URL used to request attestations and set it as `TEE_APP_URL`. Example: `https://e3ef58deb2acad4bd5dcc36b39e079198104745f-8080.dstack-pha-prod5.phala.network/attestation`.
