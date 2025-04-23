CREATE TABLE IF NOT EXISTS requests (
  id           SERIAL PRIMARY KEY,
  method       TEXT      NOT NULL,
  path         TEXT      NOT NULL,
  query_params JSONB     NOT NULL DEFAULT '{}'::jsonb,
  headers      JSONB     NOT NULL DEFAULT '{}'::jsonb,
  cookies      JSONB     NOT NULL DEFAULT '{}'::jsonb,
  post_params  JSONB     NOT NULL DEFAULT '{}'::jsonb,
  body         TEXT      NOT NULL DEFAULT '',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS responses (
  id             SERIAL PRIMARY KEY,
  request_id     INTEGER   NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  status_code    INTEGER   NOT NULL,
  status_message TEXT      NOT NULL,
  headers        JSONB     NOT NULL DEFAULT '{}'::jsonb,
  body           TEXT      NOT NULL DEFAULT '',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests(created_at);
CREATE INDEX IF NOT EXISTS idx_responses_request_id ON responses(request_id);
