# Document API

Status: **ingest, extract and read-key are implemented** (`internal/documents`, `pkg/docwire`,
`internal/render`, `internal/blobfetch`, `internal/extract`, `internal/readkey`, `cmd/shim/documents.go`).
The attestation door is designed below and not yet written. This is the contract a document product
builds against, so it is worth arguing with — but it is no longer a proposal.

## Why not the chat door

`/v1/chat/completions` is the only data door the shim has today. It is the wrong shape for documents:

- it carries thread state (`encrypted_payload`) that a one-shot extraction has no use for;
- its content is a plain string, so no picture can be attached to it — which is why a scan is not
  read through the chat door at all: the documents door draws the pages inside the enclosure and
  attaches them to the read itself;
- it has no schema or grammar, so a caller smuggles the schema into the prompt and validates the
  reply itself — a malformed reply becomes an unusable record;
- it has no logprobs, so per-field confidence is the model's opinion rather than something measured;
- a document would travel base64 inside JSON, 33% larger, through a door that has nothing to do with
  documents;
- "seal this document" is not a chat operation.

The reader — the model — stays. The door is what changes.

## What already exists (build on this)

| Piece | Where |
|-------|-------|
| Sealed envelope + fingerprint | `internal/documents` (new: `Seal`, `Open`, `SealDocument`, `OpenDocument`) |
| DEK derivation from the four inputs | `internal/derive/kdf.DeriveDEK` |
| Operator-held tenant seed | `internal/keyscope.Resolver.Seed` (registry wrap + chip secret) |
| Chip secret, attestation binding, key version | `internal/derive/material` |
| AEAD (XChaCha20-Poly1305) | `internal/derive/state` — already used for chat state and registry wraps |
| Attested receipts | `internal/receipt` (ed25519, Rekor) |
| Verified customer claim | `internal/identity.VerifiedIdentity` (`X-NexQloud-Identity`) |
| Route + handler pattern | `cmd/shim/main.go` (`mux` + `requireReady`, handler shape of `handleChatCompletions`) |

Nothing above needs to be invented. The document API is a new package, four handlers, and two fields
on the inference request.

## Endpoints

### `POST /v1/documents/ingest`

```
in   the file itself (binary body or multipart), plus optional hints:
       filename, declared_type
     optional client-side sealing: wrapped_key + sealed_body
does fingerprint (SHA-256 of the plaintext) → detect form type → render page images →
     seal source and every page under the tenant DEK, stamped with key_version
out  { document_id, key_version, detected_type, pages,
       sealed: { source: <bytes>, pages: [<bytes>...] },
       receipt_id, sealed_receipt }
```

Every returned byte is ciphertext, so the caller can write it straight to object storage. No key
material is ever returned, and the plaintext never leaves the enclosure.

The per-call nonce travels in the `X-NexQloud-Challenge-Nonce` header, because the body is the
document itself. It is optional, as on every sealed door: supply one to bind the receipt to a
challenge you issued, or leave it out and the enclave generates one.

Open question 1 (below) decides whether the rendering happens here.

### `POST /v1/documents/{document_id}/extract`

```
in   { schema_id, schema, document_id, key_version, source_url, model?, challenge_nonce? }
out  { document_id, schema_id, model, fields, confidence, confidence_source,
       model_confidence, pages, receipt_id, sealed_receipt }
```

The document is **not** in the request. `source_url` is a presigned URL for the sealed object, which
the enclave fetches itself: a large case never travels through the calling application, and the caller
needs no credentials for the enclave to reach its storage. Presigned URLs are safe to hand over here
because what comes back is ciphertext, and ciphertext authenticates itself — a stale or hostile link
can only deliver bytes that fail the open.

`source_url` must serve what the ingest door handed out: the **sealed-document container**, source
envelope and page renders together. The door takes the source out of its own container (verifying
every part against its digest on the way) rather than making each caller learn the container format,
so a caller keeps one sealed object per document and hands the same URL to extract and to read-key.
Bytes that are not a container are still accepted as a bare source envelope, but a caller with a
container should not unwrap it first.

`key_version` is checked against the version this enclave derives before anything is fetched, so a
caller holding a document sealed under another version is told so rather than given a decryption
failure to interpret. A container whose header disagrees with the request (another document, another
version) is refused on the container's own evidence, not the caller's word.

The caller supplies the schema, and it is sent to the engine as a constraint. It **must allow null**
for every field: a schema that requires a string in every property leaves the model no honest answer
for a blank box, so it can only invent a value or break the grammar. The refusal to invent is the
point, so this is a requirement, not a style note.

Status codes: 400 for a request that cannot be answered, 401 identity, 403 `ErrNoKeyMaterial` (a
destroyed scope is an answer), 422 for a document that will not open, has no text layer, or drew an
answer that is not a record, 502 for object storage or the engine being unreachable.

#### Confidence is measured, not claimed

`confidence_source` is either `logprobs` or `none`, and `none` means **not measured** — never
"certain".

When the engine reports token probabilities, each field's confidence is the probability of the
weakest token inside that field's span (span = from the end of the field's key to the start of the
next key). Tokens that are nothing but punctuation are ignored: a brace the engine was unsure of says
nothing about whether it read the document, and a token such as `}}` straddles a value and the object
around it.

`model_confidence` is what the model claimed about itself, kept beside the measured figure rather than
in place of it. A review gate reads `confidence`. `internal/render`'s text extraction runs `pdftotext
-layout` because a customs form is a table: without layout, a part number and the quantity beside it
arrive with no relationship to each other.

### `POST /v1/documents/{document_id}/read-key`

```
in   { document_id, purpose, ttl_seconds, recipient_public_key, source_url, challenge_nonce? }
out  a sealed-document container:
       part "source"  the grant — the session key wrapped to the recipient, with its expiry
       parts "page-*" the page renders, re-sealed under that session key
```

For the human review screen: a short-lived key that opens one document's page renders, addressed to
the browser that asked for it, so a customer's reviewer can see a page while the application around
them stays blind. Every grant is receipted — "who looked at this document, and when" becomes a fact
rather than a log line, which for a customs claim is a feature, not overhead.

**The key is not addressed to the caller.** `recipient_public_key` is the reviewer's browser's own
P-256 public key, generated for that review session; the private half never leaves the browser. The
enclave wraps the session key to it (ECDH → HKDF-SHA256 → AES-256-GCM, all native to WebCrypto) and
re-seals the pages under the session key. The application relaying the request holds a container of
ciphertext it cannot open, and the enclave never sees the browser's private half. This is what makes
"the application only handles locked bytes" true for the review screen rather than aspirational.

The response is a container rather than JSON because the pages are bytes: the same reason ingest uses
one. A client reads the grant from the first part and the pages from the rest; the browser then
unwraps the session key and opens each page with it. Nothing in the response needs to pass base64
through the caller's database.

`purpose` is `review` or absent, which means `review`. A lifetime outside 30 s–15 min is cut to the
boundary, and an unstated one means 5 minutes. Only page renders are ever re-sealed — never the source
document, which no reviewer needs in order to check a field.

#### What a grant is worth, honestly

Scope is enforced by cryptography: the session key opens this grant's page renders and nothing else —
not the source document, not another grant, not another tenant's anything. Time is not: a key already
in a browser cannot be taken back by a clock, so the expiry is a recorded promise the caller honours,
not an enforcement point. What makes the promise meaningful is that the grant is receipted, and the
receipt names the document, the purpose, the lifetime and the digest of the recipient key.

The receipt never carries the wrapped session key, the salt or the ephemeral public key, only digests.
A receipt is published to a transparency log; the wrapped key is addressed to one browser.

### `GET /v1/documents/attestation`

The measurement, pinned artefacts and model commitment a customer's reviewer asks for. Partly
existing material (`internal/receipt/attestation.go`, `internal/modelattest`), exposed in one place.

## Key and version semantics

- The envelope header carries `key_version` outside the AEAD so a reader knows which key to derive
  before it can open anything. Those bytes are unauthenticated by design and safe: a tampered version
  selects a different key and can only fail the tag, never open wrongly.
- The version is already bound into the derivation — `hkdf` info is `sealed-dek/1|<tenant>|v<N>` — so a
  new version is a new key from the same seed. Rotation is therefore cheap; what needs deciding is
  policy: re-seal eagerly on rotation, or lazily on next read, and how long an old version stays
  openable. A five-year drawback lookback means old versions must keep working for years.
- No endpoint returns the tenant key, and none returns the seed or a wrap of it. `read-key` is not an
  exception, and the distinction is worth stating precisely: it returns a **new, single-document
  session key, addressed to a public key the enclave never holds the private half of**. The tenant DEK
  stays inside the boundary; what leaves is a grant that opens one document's renders for a few
  minutes, which is exactly the capability the review screen is supposed to have and no more.

## Receipts

Every document call returns a sealed receipt. Its package binds `document_id` (the plaintext
fingerprint), `key_version`, the envelope kind, `schema_id`, the model commitment, the identity claim
hash, the challenge nonce and the enclave measurement.

Note the cost: adding fields to `receipt.Package` changes the signed canonical form, so `pkg/verify`
and the browser verifier in `web/` both have to learn a new schema (`sealed-document/1`). That is a
coordinated change, not a local one.

### Development receipts

On a machine with no SEV-SNP (a laptop, CI) `RequestReport` fails, which used to end every receipt —
including in dev mode, which is exactly where a placeholder was intended to keep the loop working.
`NEXQLOUD_DEV=1` now falls back to a placeholder: the measurement becomes `placeholderMeasure`, the
identity claim hash becomes the dev constant, the certificate chain is empty, and the package carries

```
dev_placeholder: true
```

A verifier must treat that as "signed, but nothing attested this": it is part of the signed package, so
it cannot be stripped, and it is omitted entirely from a real receipt, so real signed bytes are
unchanged. Outside dev mode a missing report is still a hard error.

## Not in scope

- No change to `/v1/chat/completions`. Chat keeps its door.
- No new storage in the platform. The enclave is not a database; ciphertext belongs to the caller.

## Open questions

1. **The client-side sealing key for upload.** `read-key` settled the shape of the browser-facing
   crypto: ECDH on P-256, HKDF-SHA256, AES-256-GCM — all WebCrypto-native, because adding a
   hand-written XChaCha implementation to a browser security path would be a worse trade than using the
   platform's own. Sealing *before upload* needs the same wrapping in the other direction plus a way for
   the browser to be sure the public key it wraps to is the enclave's (today it is the enclave that
   wraps, so the direction of trust is the easy one). Not designed here.
2. **Schema ownership and versioning.** A `schema_id` that changes under existing cases silently
   changes what extraction returns for them. The schema is supplied per call today; if a case's
   extraction must stay reproducible years later, the schema (or its digest) has to be recorded with
   the case — the receipt carries the fields' digest, not the schema's.
3. **What a read-key grant cannot do.** It cannot be revoked before it expires, and it does not stop a
   reviewer screenshotting a page. Neither is fixable with crypto; both are worth saying plainly to a
   customer rather than implying otherwise. What remains open is whether a grant should be bound to a
   single page count or a single browser tab, and whether an explicit `revoke` (receipted, advisory)
   is worth having.
4. **Scanned pages.** `pdftotext` returns nothing for a scan, so the documents door draws the pages
   (`pdftoppm`, 400 DPI, one more than the bound so "too long" is distinguishable) and attaches them
   to the same read — same schema, same measurement, same receipt, which records `read=page_images`.
   An engine served without a vision projector rejects the request rather than silently answering
   from nothing. Each drawn page is cut into horizontal strips of at most ~4 Mpx
   (`internal/render/bands.go`, which carries the measurement), because a vision encoder resizes any
   image to a fixed budget of about 4,051 tokens: one image whatever its size is ~1,000 page pixels
   per token, so a page sent whole loses its small print to the downscale, while each strip gets its
   own budget at the resolution it was drawn at. **Measured afterwards, the strips do not buy
   resolution:** a scanned 7501 read as four 400 DPI strips cost 15,691 prompt tokens (llama-server:
   `prompt processing, n_tokens = 12917, progress = 0.77`), about 1,017 page pixels per token — the
   same ratio a whole 200 DPI page already had, since that page was *under* the per-image budget and
   was never downscaled. The binding limit is the per-image budget (~4,051 tokens, ~4 Mpx), so the
   grid's eight-point print is still under a token: reading it needs a raised per-image token budget
   on the server, or the region given its own picture. A read whose strips do not fit the deployment's
   context is refused `422` naming the estimated tokens and the budget, rather than handed to the
   engine to fail at. The receipt still counts *pages*, not strips. Open: nobody has measured a
   picture read's accuracy against a hand-checked set yet, and the 8-page bound is a guess at the
   guest's context rather than a measured limit — `SEALED_READ_TOKEN_BUDGET` (default 24,000, about
   one 400 DPI page as strips) is the measured one.
5. **Where the grammars come from.** The schema is handed to the engine per call. If extraction quality
   needs hand-written GBNF rather than a generated schema grammar, that is a `Request.Grammar` field
   away — it is already plumbed through.

## Testing

- `internal/documents`: round-trip of source and pages, refusal of wrong key version, wrong key,
  tampered ciphertext, foreign bytes, kind confusion, and a check that no envelope contains plaintext.
  `go test ./internal/documents/`
- Handlers: follow the existing `cmd/shim` test style once the transport shape is settled.
