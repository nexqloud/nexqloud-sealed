# Erasure control plane

The three services that make federated cryptographic erasure (invention 3) work:
the **destruction coordinator**, the **destruction aggregator**, and the federated
key-derivation **registry**.

None of them needs a TEE, and none of them ever holds key material or plaintext —
the coordinator moves a signed order, the aggregator binds signed receipts, the
registry records which operator nodes hold a piece of a tenant's key. That is why
they can run on ordinary hosts instead of on the confidential-computing fleet.

## Image

```
ghcr.io/nexqloud/nexqloud-sealed/sealed-control-plane:stage    # staging
ghcr.io/nexqloud/nexqloud-sealed/sealed-control-plane:latest   # production
```

One image, three roles, selected by the first argument. Build locally with
`make image-control-plane` (tag `sealed-control-plane:local`).

`docker-compose.yml` in this directory brings the whole control plane up with one
command, and the same file works with `nerdctl compose` on a nanoserver host:

```bash
docker compose -f deploy/control-plane/docker-compose.yml up -d
```

It reads `COORDINATOR_KEY_HEX`, `SUBSTRATE_KEY_HEX`, `MONGO_URL`, `SHIM_OPERATOR_MAP`
and `CUSTOMER_JWKS_URL` from a gitignored `.env` next to it; the header of that file has
the exact generation commands, and the coordinator's public key for the shims comes from
`go run ./demo/two-vm/coordinator_pubkey.go "$COORDINATOR_KEY_HEX"`.

Every binary's sha256 is baked in at build time:

```bash
docker run --rm --entrypoint cat sealed-control-plane:local \
  /usr/local/share/nexqloud/destruction-coordinator.commitment
```

## One pair per federation, one registry per federation

There is **one** coordinator and **one** aggregator for the whole federation — not
one per operator node. They are the shared control plane; tenants and key scopes are
parameters. A per-operator coordinator would resolve a quorum of one and publish a
proof that leaves every other operator's copy of the key material intact.

## Running the roles

The registry (MongoDB-backed):

```bash
docker run -d --name sealed-registry -p 7001:7001 \
  -e MONGO_URL='…' \
  sealed-control-plane:local registry \
    --addr :7001 --db sealed_registry --collection commitments
```

The aggregator (holds the substrate signing key — keep it in a KMS/HSM in
production, and pin `--substrate-key-hex` from a secret store):

```bash
docker run -d --name sealed-aggregator -p 7004:7004 \
  sealed-control-plane:local aggregator \
    --addr :7004 --substrate-key-hex "$SUBSTRATE_KEY_HEX"
```

The coordinator (needs the registry, the aggregator, the operator map, and the
customer IdP JWKS used to verify the delete authorization):

```bash
docker run -d --name sealed-coordinator -p 7003:7003 \
  sealed-control-plane:local coordinator \
    --addr :7003 \
    --registry http://sealed-registry:7001 \
    --aggregator http://sealed-aggregator:7004 \
    --operators operator-a=https://<shim-a>:8080,operator-b=https://<shim-b>:8080 \
    --jwks https://<gateway>/.well-known/sealed-jwks.json \
    --coordinator-key-hex "$COORDINATOR_KEY_HEX"
```

`--coordinator-key-hex` is a 32-byte Ed25519 seed as hex. Print the matching public
key for the shims with:

```bash
go run ./demo/two-vm/coordinator_pubkey.go "$COORDINATOR_KEY_HEX"
```

## Connectivity the deployment must satisfy

```
shim  ──outbound──▶  registry      (open its scope seed)
shim  ──outbound──▶  aggregator    (push its destruction receipt)
coordinator ──in──▶  shim          (dispatch destruction, POST /destruction)
aggregator  ──out──▶ transparency log (publish the unified proof)
gateway     ──in──▶  coordinator   (register scopes, start erasures, read proofs)
```

The shim verifies a coordinator-signed request before touching anything, so the
control port does not need to be public — but keep it on the substrate network, not
the internet, and note that it currently speaks plain HTTP.

Shims are configured at deploy time with:

```
NEXQLOUD_REGISTRY_URL         e.g. http://sealed-registry:7001
NEXQLOUD_OPERATOR_ID          this node's identity in the registry (operator-a, …)
NEXQLOUD_COORDINATOR_PUB_HEX  ed25519 public key of the coordinator
NEXQLOUD_STATE_DIR            writable dir for the wrap cache / ciphertext overwrite
```

Without those four the shim behaves exactly as before — no destruction surface, no
scope seeds. Rotating the coordinator key means redeploying the shims, because the
key is injected at deploy time.

## Proving it works without a fleet

Both scripts run the whole chain on one machine:

```bash
bash scripts/e2e-keyscope-erasure.sh        # protocol logic (throwaway operator binaries)
bash scripts/e2e-shim-quorum-erasure.sh     # deployment shape: two sealed shims as quorum members,
                                            # MongoDB-backed registry, full delete → proof → refusal
```

They point `REKOR_SERVER` at a local stub so nothing is written to the public
transparency log. Before customer data flows, self-host the log (best mode says "a
Sigstore Rekor instance"; the alternatives are Trillian or any append-only log) —
the default endpoint is the public sigstore log, where proofs would be world-readable.
