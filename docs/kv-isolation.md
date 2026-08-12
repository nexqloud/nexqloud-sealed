# KV / prompt-cache isolation for sealed-llama

## Goal

One host-side `sealed-llama` serves every sealed VM on a nanoserver. Without
isolation flags, llama.cpp will reuse KV / prompt cache across requests
(slot-prompt similarity, `--cache-prompt`, RAM prompt cache). That is a
cross-tenant path.

Primary control is **config**. The attested wipe worker is secondary evidence:
it erases slots then runs the CUDA two-pass over free VRAM and signs a cert.

## Config (primary)

`scripts/start-sealed-sidecars.sh` probes `llama-server --help` and, when
supported, starts llama with:

| Flag | Effect |
|------|--------|
| `-np 1` | Single slot (recent builds also disable similarity selection) |
| `-sps 0.0` | Disable LCP similarity slot selection |
| `--no-cache-prompt` | Do not reuse KV across requests |
| `-cram 0` | Disable RAM prompt cache (no save/restore of idle slot KV) |
| `--no-context-shift` | Avoid context-shift path (also GHSA-8947-pfff-2f3c) |
| `--slots` | Keep `/slots` monitoring + erase API |
| `--slot-save-path /tmp/llama-slots` | Required by current llama-server to unlock `action=erase` (also unlocks save/restore). Mounted as container tmpfs — never bind-mounted to the host. |

Pin the image by digest once verified (`nerdctl image inspect` output printed
by the start script). Isolation claims depend on which llama build is running.

## Wipe worker (secondary / receipt claim)

With `LLAMA_URL` set (default `http://sealed-llama:8080` on `sealed-net`),
each `/v1/zeroize` call:

1. `GET /slots` then `POST /slots/{id}?action=erase` for every slot
2. CUDA two-pass over free VRAM
3. Signs a cert with `kv_cache_cleared: true` and `slots_erased: [...]`

Fail-closed if erase never lands. Escape hatch for GPU-less / dev hosts:
`WIPE_KV_REQUIRED=0`.

## What `action=erase` does

`POST /slots/{id}?action=erase` maps to `llama_memory_seq_rm`: it frees KV
**cells** (bookkeeping) so the sequence cannot be reused. It does **not**
overwrite the underlying tensor bytes in VRAM.

So:

- Erase + `--no-cache-prompt` / `-sps 0.0` / `-cram 0` → no logical reuse.
- Residual risk: stale bytes can remain in VRAM until overwritten by later
  allocations or by the free-VRAM two-pass wipe.
- llama runs on the host, outside the SNP guest boundary.

## Verify on a box

```bash
LLAMA_URL=http://127.0.0.1:8032 ./scripts/kv-isolation-check.sh
```

The script asserts `/props` (`total_slots: 1`; `cache_prompt: false` when that
field is exposed — some llama-server builds omit it from GET `/props`), runs a
canary leak probe across two overlapping requests, then erases slot 0 with
`Content-Length: 0` (workaround for llama.cpp hang #17387) and checks `/slots`.

## When to revisit a fork

If `kv-isolation-check.sh` fails against a pinned image after the config flags
are applied, plan a patched llama.cpp that memsets the KV range on slot
release. That is intentionally out of scope until the probe shows a gap.
