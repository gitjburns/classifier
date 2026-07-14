CREATE TABLE assessments (
  request_id        TEXT PRIMARY KEY,          -- UUID
  created_at_ms     INTEGER NOT NULL,          -- unix epoch milliseconds, UTC
  verdict           TEXT NOT NULL,             -- 'safe' | 'unsafe' | 'sanitized'
  content_sha256    TEXT NOT NULL,
  content           TEXT NOT NULL,             -- original submitted text
  sanitized_sha256  TEXT,                      -- NULL unless verdict = 'sanitized'
  sanitized_content TEXT,                      -- NULL unless verdict = 'sanitized'
  ruleset_version   TEXT NOT NULL,
  elapsed_ms        INTEGER NOT NULL
);

CREATE TABLE findings (
  request_id TEXT NOT NULL REFERENCES assessments(request_id),
  rule_id    TEXT NOT NULL,
  severity   TEXT NOT NULL,                    -- 'critical' | 'suspect' | 'advisory'
  span_start INTEGER NOT NULL,                 -- UTF-8 byte offset, original content
  span_end   INTEGER NOT NULL                  -- end exclusive
);

CREATE INDEX idx_assessments_created ON assessments (created_at_ms DESC, request_id);
CREATE INDEX idx_assessments_verdict ON assessments (verdict, created_at_ms DESC);
CREATE INDEX idx_assessments_hash    ON assessments (content_sha256, created_at_ms DESC);
CREATE INDEX idx_findings_request    ON findings (request_id);
