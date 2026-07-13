# Content Risk Assessment Service — Caller Protocol

This document is the complete interface reference for services that call the
classifier. It describes how to submit content for assessment, how to act on
the result, and how to query past assessments. Detection internals are
deliberately not part of this contract: callers integrate against the fields
documented here and nothing else.

## 1. Overview

The service assesses text before you use it as input to an LLM. You submit
the text; the service returns one of three verdicts:

| Verdict     | Meaning |
|-------------|---------|
| `safe`      | No risk signals were found. |
| `unsafe`    | The content should not be forwarded to the LLM. |
| `sanitized` | Flagged sections were replaced with redaction markers; the resulting text was re-assessed and cleared. |

Integration pattern: call `POST /v1/assess` with the untrusted text **before**
it reaches your LLM, then branch on the verdict (Section 4). Every assessment
is recorded by the service and can be retrieved later (Section 5).

## 2. Authentication

All endpoints except `GET /healthz` require a bearer token:

```
Authorization: Bearer <token>
```

Tokens are provisioned by the service operator. Requests without a valid
token receive `401`. Authentication fails before an assessment request id is
assigned, so these responses do not include `request_id`.

## 3. Assessing Content — `POST /v1/assess`

### Request

```json
{
  "content": "<text to assess>",
  "content_sha256": "<lowercase hex SHA-256 of the text>"
}
```

Both fields are required. Unknown fields are rejected with `400`.

- `content` — the text to assess. Must be non-empty, valid UTF-8, and within
  the operator-configured size limit. Oversize content is rejected, never
  truncated.
- `content_sha256` — SHA-256 over the **UTF-8 bytes of the text itself**,
  as lowercase hex. Hash the raw text you hold before JSON encoding — not the
  JSON-escaped string, not the whole request body:

  ```
  digest = sha256(utf8_bytes(content_text))
  content_sha256 = lowercase_hex(digest)
  ```

  The service independently hashes the bytes it received and rejects the
  request (`400`, reason `content_hash_mismatch`) if the two differ. This
  protects you: it guarantees the verdict — and every span offset in it —
  refers to exactly the bytes you intended to submit, and was not computed
  over text altered somewhere in transit.

### Response

**All three verdicts arrive as HTTP 200.** A 200 means the assessment
completed; it does not mean the content is safe. Branch on the `verdict`
field, never on the status code alone.

```json
{
  "request_id": "1f0c8a4e-…",
  "verdict": "sanitized",
  "content_sha256": "9b71d224…",
  "sanitized_content": "Please summarize this document. [REDACTED]",
  "sanitized_sha256": "5e884898…",
  "findings": [
    { "rule_id": "instruction-override", "severity": "suspect",
      "span": { "start": 32, "end": 61 } }
  ],
  "ruleset_version": "2026-07-13.1"
}
```

| Field | Presence | Meaning |
|-------|----------|---------|
| `request_id` | always | Server-assigned UUID for this assessment. Use it for support inquiries and history lookups (Section 5.2). |
| `verdict` | always | `safe`, `unsafe`, or `sanitized`. |
| `content_sha256` | always | The hash the service computed over the received text. Matches your submitted hash. |
| `sanitized_content` | `sanitized` only | The redacted text that passed re-assessment. Flagged sections appear as the literal marker `[REDACTED]`. |
| `sanitized_sha256` | `sanitized` only | SHA-256 (lowercase hex) of `sanitized_content`, so you can verify and forward it with the same integrity guarantee. |
| `findings` | always (may be empty) | What was flagged: rule id, severity, and location. See below. |
| `ruleset_version` | always | Version of the rule set that produced this verdict. See Section 7. |

**Findings.** Each finding locates one flagged region of your original text:

- `rule_id` — an informational identifier naming what matched. Treat it as an
  opaque string for logging and support; the set of ids is not a stable
  contract (Section 7).
- `severity` — `critical`, `suspect`, or `advisory`. `advisory` findings are
  informational and never affect the verdict on their own.
- `span` — `start`/`end` are **UTF-8 byte offsets** into your original text,
  end-exclusive. If your language indexes strings by code points (Python,
  JavaScript), convert before slicing: encode the text to UTF-8 bytes, slice
  by the span, then decode.

Findings never include excerpts of your content. Because the hash check
confirmed both sides hold identical bytes, slicing the span from your own
copy reproduces exactly what was flagged.

## 4. Acting on Verdicts

| Verdict | Required caller behavior |
|---------|--------------------------|
| `safe` | You may forward your original text to the LLM. |
| `unsafe` | Do not forward the text. What to do instead (reject, queue for review, notify) is your service's policy. |
| `sanitized` | Forward `sanitized_content` **only**. Never forward the original text of a `sanitized` verdict — the clearance applies to the redacted version alone. |

Two handling rules:

- **Fail closed.** If the call fails — timeout, connection error, `5xx`, or a
  response you cannot parse — treat the content as not cleared. Absence of a
  verdict is not approval.
- **Keep assessment details internal.** `findings`, rule ids, and spans are
  intended for your service's own logic and logs. Do not display them to the
  authors of submitted content; per-rule feedback lets a submitter reshape
  content until it passes.

A note on `safe`: it means no known risk signals were found by the current
rule set, not that the content is verified harmless. It is one layer of
protection, not a substitute for your own downstream safeguards.

## 5. Querying Assessment History

### 5.1 List — `GET /v1/assessments`

Returns past assessments, newest first. All parameters are optional and
combine with AND:

| Parameter | Type | Meaning |
|-----------|------|---------|
| `verdict` | string | Comma-separated subset of `safe,unsafe,sanitized`, or `all`. Omitted = `all`. Unknown values, duplicates, or `all` combined with other values → `400`. |
| `content_sha256` | string | Exact match: every assessment of that exact content. |
| `since_hours` | integer | Only records from the previous N hours (e.g. `48`). Must be a positive integer. |
| `limit` | integer | Page size. Server-capped; requests above the cap → `400`. |
| `cursor` | string | Continuation token from a previous response. Opaque — do not parse or construct it. |

Response:

```json
{
  "assessments": [
    {
      "request_id": "…",
      "created_at": "2026-07-13T09:14:02Z",
      "verdict": "unsafe",
      "content_sha256": "…",
      "sanitized_sha256": null,
      "ruleset_version": "…",
      "elapsed_ms": 3,
      "findings": [ { "rule_id": "…", "severity": "…", "span": { "start": 0, "end": 9 } } ]
    }
  ],
  "next_cursor": "…"
}
```

- `next_cursor` present means more rows exist — pass it back as `cursor` to
  continue. Absent means you have reached the end.
- List rows contain hashes and metadata only, never the text itself. To
  retrieve stored text, fetch the individual record (5.2).

### 5.2 Detail — `GET /v1/assessments/{request_id}`

Returns the full record for one assessment: every list-row field plus
`content` (the original submitted text) and `sanitized_content` (when one was
produced). Unknown `request_id` → `404`.

### 5.3 Health — `GET /healthz`

Unauthenticated. `200` once the service is ready to accept requests.

## 6. Errors and Retries

Error responses use this shape and never echo submitted content:

```json
{ "reason": "content_hash_mismatch", "request_id": "…" }
```

For authenticated `POST /v1/assess` requests, the service assigns `request_id`
before reading or validating the body. Every subsequent `400` or `500` response
includes it for service-log correlation. A rejected request is not persisted,
so its id cannot be retrieved through the assessment-history endpoints.
Authentication failures occur before assignment, and errors from other
endpoints may omit `request_id`.

| Status | Reasons (non-exhaustive) | Retry? |
|--------|--------------------------|--------|
| `400` | `invalid_body`, `empty_content`, `content_too_large`, `content_hash_mismatch`, `invalid_filter`, `invalid_cursor` | No — fix the request. A `content_hash_mismatch` that persists with a correct hash indicates transport-level text alteration; investigate before resubmitting. |
| `401` | missing or invalid token | No — fix credentials. |
| `404` | unknown `request_id` (detail endpoint only) | No. |
| `500` | internal error; `request_id` included when available | Yes, with backoff. Include the `request_id` when reporting persistent failures to the operator. |

Remember the fail-closed rule: no error status, timeout, or unparseable
response ever clears content for forwarding.

## 7. Stability Notes

- **Verdicts are a function of content and rule set.** The same content may
  receive a different verdict after the operator updates the rules.
  `ruleset_version` records which rule set judged each assessment; treat a
  verdict as valid for the version that produced it, not as a permanent
  property of the content.
- **Rule ids are informational, not contractual.** Ids may be added, renamed,
  or removed by rule-set updates without an API version change. Log them,
  correlate on them, but do not hard-code behavior against specific ids.
- **Stable contract surface**: endpoint paths, request/response field names
  and types, verdict values (`safe`, `unsafe`, `sanitized`), severity values
  (`critical`, `suspect`, `advisory`), span semantics (UTF-8 byte offsets,
  end-exclusive), the `[REDACTED]` marker string, and the error shape above.
  Changes to any of these will be versioned under a new path prefix.
