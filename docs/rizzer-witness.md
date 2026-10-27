# Attaching Rizzer crash witnesses to Scrutineer findings

Scrutineer accepts Rizzer's **low-confidence SARIF candidate** through
`POST /api/v1/import`. The SARIF description includes the original
`campaignEvidenceSha256`, but the raw input and sanitizer log are not embedded.

The separate Rizzer `candidate-evidence.zip` contains the exact input and
diagnostic bytes, SHA-256 inventory, source commit, review and original
evidence manifest. After inspecting those files for secrets or other sensitive
information, an operator can attach the witness to the specific imported
finding using Scrutineer's **existing persistent `finding_pocs` storage**.

These actions are only supported by **localhost operator-authenticated**
`/api/v1` routes. Per-scan bearer tokens and anonymous callers cannot
attach or download.

## Step-by-step

Generate the reviewed Rizzer evidence pack using
`python3 -m integrations.scrutineer_bridge --pack --sarif --reviewed-candidate ...`
and inspect `review.json`, `candidate-evidence.zip`, and the raw sanitizer
log. Confirm that sharing those bytes is authorized. Do not expose private
source, secrets, or sensitive stack traces to unintended recipients.

Import the SARIF candidate:

```sh
TOKEN="$(cat data/operator-token)"
curl -H "Authorization: Bearer $TOKEN" \
  --data-binary @candidates.sarif \
  "http://127.0.0.1:8080/api/v1/import?revalidate=false"
```

Read `results[].finding_ids` from the response. **Only a created or already
known finding whose imported tool is exactly
`Rizzer (unverified candidates)` may receive the witness.** Select the
corresponding finding ID after manual review.

```sh
FINDING_ID=301  # replace with the returned finding ID
curl -H "Authorization: Bearer $TOKEN" \
  -H "X-Rizzer-Candidate-Reviewed: true" \
  -H "Content-Type: application/zip" \
  --data-binary @candidate-evidence.zip \
  "http://127.0.0.1:8080/api/v1/findings/$FINDING_ID/rizzer-witness"

curl -H "Authorization: Bearer $TOKEN" \
  -o returned-witness.zip \
  "http://127.0.0.1:8080/api/v1/findings/$FINDING_ID/rizzer-witness"
```

The POST returns `201` for a newly attached witness or `200` for an
identical already-stored witness, including its SHA-256. Conflicting persistent
PoC material returns `409` and is never replaced. Other common errors are
`422` for a hash/provenance mismatch and `413` above 1 MiB.

The current persistent PoC storage allows at most **1 MiB per file** and
**2 MiB total**. Rizzer can produce archives up to 16 MiB, but this initial
adapter intentionally accepts only ZIPs at or below the existing 1 MiB
per-file limit; larger packages are rejected, never truncated.

The binary remains durable after scan-workspace cleanup because it is stored in
`FindingPoC` and associated with the finding's existing scan. A subsequent
`GET /findings/{id}/bundle.tar.gz` includes the ZIP as
`poc/rizzer/candidate-evidence.zip`, preserving its original bytes, while
the dedicated download endpoint returns the ZIP directly.

## Boundaries

- The archive is inspected **without extraction or executing inputs**.
  Entry count, type, compression method, symlinks, path allowlist,
  expanded size, CRC, original campaign digests, matching commit and location
  are checked.
- Hash consistency is **not a signature**. A malicious producer could
  invent mutually consistent manifests. A sanitizer crash is **not** proof of
  public reachability, exploitability, or severity.
- This is a *human-gated* attachment, not automatic vulnerability disclosure
  or a trigger to run `verify` or `reattack`. Use `revalidate=false` if you
  intend to import without scheduling the existing automatic finding triage.
- **Disclosure hazard:** manually generated finding bundles contain the ZIP.
  The operator must inspect raw inputs/logs before sharing a bundle with
  maintainers, reporters or other parties. An untrusted report is not a
  trusted instruction to disclose, reproduce, or send data.
- Persistent storage contains the original crash log and can hold sensitive
  data. Host backups and database access must be treated accordingly.
