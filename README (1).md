# Incident agent (ga5-incident-agent/v2)

Dependency-free Node.js (>=18) service. Endpoints: `POST /v2/incidents`, `POST /v2/incidents/{runId}/receipts`, `GET /v2/incidents/{runId}`.

## Configuration (env vars)
- `LLM_BASE_URL` – any OpenAI-compatible base URL (default `https://api.openai.com/v1`). Free option: Gemini `https://generativelanguage.googleapis.com/v1beta/openai`; Groq `https://api.groq.com/openai/v1`.
- `LLM_API_KEY` – your provider key (set as a host secret; never commit it).
- `LLM_MODEL` – a cheap model, e.g. `gpt-4o-mini`, `gemini-2.0-flash`, `llama-3.3-70b-versatile`.
- `PORT` – listen port (default 8080). `DATA_DIR` – where `state.json` is persisted.

## Run / test
    npm test        # local smoke test with a mock model (no key needed)
    LLM_API_KEY=... LLM_MODEL=... npm start

## Deploy
Deploy to any host that gives a public HTTPS URL without redirects (Render, Railway, Fly.io, Cloud Run), start command `node server.js`. Use a persistent disk or keep a single always-on instance, since state lives in `state.json`. Submit the base URL (no trailing path, query or fragment). Verify with `curl https://<host>/healthz` before using a Check.

## Design notes
- Model is called once per first-seen runId; replays, receipts, GET and OTLP never call it.
- Receipt replays return the stored original response; changed content returns 409.
- Sensitive values are never sent to the model and are redacted from every response.
