# Two-VM Federated Deletion Demo

Scripts to start/stop the full demo without hunting `ps aux`. Each service runs in the
background with a **pid file** and **log file** under `RUN_DIR`.

## Quick start

### VM1 (management + operator A)

```bash
cd nexqloud-sealed/scripts/two-vm-demo
cp vm1.env.example vm1.env
# edit VM1_IP, VM2_IP, REPO_ROOT

./vm1-start.sh      # prints each step, saves pids + logs
# copy seed.hex output to VM2

./vm1-status.sh
./vm1-delete.sh     # after VM2 is up
./vm1-stop.sh       # clean shutdown
```

### VM2 (operator B only)

```bash
cd nexqloud-sealed/scripts/two-vm-demo
cp vm2.env.example vm2.env
# edit VM1_IP, VM2_IP, REPO_ROOT, SEED_HEX (from VM1)

./vm2-start.sh
./vm2-status.sh
./vm2-stop.sh
```

## Files

| Path | Purpose |
|------|---------|
| `$RUN_DIR/*.pid` | PID of each service — used by stop scripts |
| `$RUN_DIR/logs/*.log` | stdout/stderr per service |
| `$RUN_DIR/credentials.env` | Customer JWT (VM1) |
| `$RUN_DIR/seed.hex` | Federation seed for VM2 |
| `$RUN_DIR/last-proof.json` | Last unified proof after delete |

## Restart

```bash
./vm1-stop.sh && ./vm1-start.sh
./vm2-stop.sh && ./vm2-start.sh
```

`vm1-stop.sh` kills processes by **pid file and listening port**, so orphaned
`go run` children (from an older script version) are cleaned up too.

If status shows STOPPED but ports are busy, run `./vm1-stop.sh` then `./vm1-start.sh`.

No need to search `ps aux`. Each delete needs a **new nonce** — `vm1-delete.sh` generates one automatically.

## Troubleshooting

### `vm1-start.sh` stops after "Starting registry ..."

Binaries are built under `DEMO_BIN_DIR` (default `~/.cache/nexqloud-destruction-demo/bin`), not under `RUN_DIR`. Older script versions put binaries in `$RUN_DIR/bin/` which fails when `/tmp` is mounted `noexec`.

```bash
# Check the registry log
tail -30 /tmp/nexqloud-destruction-demo-vm1/logs/registry.log

# Confirm /tmp is noexec (common on hardened VMs)
mount | grep ' /tmp '
```

Pull the latest scripts and run `./vm1-start.sh` again. On failure you should now see log tail + `ERROR: registry failed to start`.

### View logs

```bash
tail -f /tmp/nexqloud-destruction-demo-vm1/logs/registry.log
tail -f /tmp/nexqloud-destruction-demo-vm1/logs/coordinator.log
```

## Ports

| Service | Port |
|---------|------|
| Registry | 7001 |
| Coordinator | 7003 |
| Aggregator | 7004 |
| Mock IdP | 7200 |
| Operator A | 7101 |
| Operator B | 7102 |
