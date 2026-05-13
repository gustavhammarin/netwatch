# LLM Job Queue Plan

## Idea

Add an LLM job queue to Netwatch so scan data can be analyzed asynchronously by a local Ollama model.

Target flow:

```text
Client
  -> REST API (Go)
  -> Queue (first in-memory, later Redis)
  -> Worker (Go)
  -> Ollama
  -> Database
  -> Client polls status or receives events
```

The project already has a good starting point in `internal/api/server.go`: REST handlers, bearer auth, async scan execution, scan state, and SSE events. The LLM job queue should build beside that instead of becoming a separate toy project.

## Recommended Product Shape

The first useful feature should be:

```text
Analyze current scan with local LLM
```

The LLM can summarize:

- vulnerabilities from image scanning
- syscall behavior
- network flows
- container logs
- errors from the scan
- suggested mitigations

Example user flow:

1. User runs a normal Netwatch scan.
2. User clicks "Analyze current scan".
3. API creates an LLM analysis job.
4. Worker sends scan context to Ollama.
5. Result is stored.
6. UI shows status and final analysis.

## Phase 1: In-Memory Prototype

Start without Redis or a database. Keep the first version small and easy to reason about.

Add:

```text
internal/jobs/
  types.go
  manager.go
  ollama.go
```

The queue can initially be a buffered Go channel:

```go
jobs := make(chan Job, 100)
```

Job states:

```text
queued -> processing -> done
queued -> processing -> failed
```

Add API routes:

```text
POST /api/llm/jobs
GET  /api/llm/jobs
GET  /api/llm/jobs/{id}
```

First request shape:

```json
{
  "type": "scan_summary",
  "prompt": "Summarize the current scan and suggest mitigations."
}
```

First response shape:

```json
{
  "id": "abc123",
  "status": "queued"
}
```

## Phase 2: Ollama Client

Add a small HTTP client for Ollama:

```text
POST http://localhost:11434/api/generate
```

Suggested config:

```text
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
```

The worker should build a compact prompt from the current scan state:

- image name
- package count
- highest severity findings
- selected vulnerability summaries
- recent syscalls
- network destinations
- errors
- container logs, bounded to a reasonable size

Avoid sending the entire scan state blindly. Keep the prompt bounded so large scans do not overload the local model.

## Phase 3: UI Integration

The current UI is embedded as `indexHTML` in `internal/api/server.go`. For the MVP, add a small LLM panel there:

```text
LLM Analysis
- Analyze current scan
- Job status
- Result text
- Retry failed job
```

The UI can poll:

```text
GET /api/llm/jobs/{id}
```

Later, LLM job updates can be added to the existing SSE event stream.

## Phase 4: Separate Worker Process

After the in-memory version works, split worker execution out of the API process.

Add:

```text
cmd/worker/main.go
internal/jobs/worker.go
internal/jobs/store.go
internal/jobs/queue.go
```

Target local development:

```bash
go run ./cmd/api
go run ./cmd/worker
go run ./cmd/worker
go run ./cmd/worker
```

This teaches the important parts:

- multiple workers
- concurrent job processing
- status races
- backpressure
- retries
- failed jobs

## Phase 5: Redis Queue

Use Redis before RabbitMQ. Redis is simpler and fits the current project size.

Suggested queue operations:

```text
LPUSH llm_jobs <job_id>
BRPOP llm_jobs 0
```

Suggested queues:

```text
llm_jobs
llm_jobs:retry
llm_jobs:dead
```

Retry behavior:

```text
attempt 1 -> fail -> retry
attempt 2 -> fail -> retry
attempt 3 -> fail -> dead-letter
```

Each job should store:

- attempt count
- last error
- timestamps
- status

## Phase 6: Database

The repo currently does not have a database layer. Start with SQLite if the goal is low friction. Use PostgreSQL if the goal is a more realistic Docker Compose setup.

Suggested table:

```sql
create table jobs (
  id text primary key,
  type text not null,
  status text not null,
  input_json text not null,
  result_json text,
  error text,
  attempts integer not null,
  created_at timestamp not null,
  updated_at timestamp not null,
  started_at timestamp,
  finished_at timestamp
);
```

Useful statuses:

```text
queued
processing
done
failed
dead
cancelled
```

## Phase 7: Docker Compose

Once Redis, database, Ollama, API, and worker are separated, add Compose.

Target services:

```text
api
worker
redis
postgres
ollama
```

This gives a realistic deployment shape:

```text
Client -> api -> redis -> worker -> ollama
              -> postgres
```

## Suggested Implementation Order

1. Add `internal/jobs` with in-memory queue and one background worker goroutine.
2. Add `POST /api/llm/jobs`.
3. Add `GET /api/llm/jobs/{id}`.
4. Feed the current scan state into an LLM prompt.
5. Add an Ollama HTTP client.
6. Add a simple UI panel for LLM analysis.
7. Add bounded prompt building and basic tests for job state transitions.
8. Replace in-memory queue with Redis.
9. Add persistent job storage.
10. Split worker into `cmd/worker`.
11. Add retry and dead-letter handling.
12. Add Docker Compose.

## Nice First MVP

The smallest useful milestone:

```text
Run scan -> click Analyze -> wait -> see LLM summary
```

No Redis. No database. No separate worker process.

Just:

- Go channel queue
- in-memory job map
- one worker goroutine
- Ollama client
- two API endpoints
- small UI panel

After that works, the project can evolve toward the full queue architecture without rewriting the core idea.

