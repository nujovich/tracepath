# Screenshots for README

Take these screenshots from `http://localhost:3000` after the stack is running with some data:

## Required Screenshots

| File | Tab | What to show |
|---|---|---|
| `dashboard-audit.png` | Audit | Events table with a few `web_search` and `read_file` events, showing signatures and policy decisions |
| `dashboard-incidents.png` | Incidents | Timeline with at least 1 denial_spike (CRITICAL) and 1 budget_exceeded (WARNING) |
| `dashboard-policies.png` | Policies | Version history with diff viewer open between two versions |
| `dashboard-reports.png` | Reports | Both FINRA and EU AI Act reports generated, showing the table |
| `dashboard-gemini-classification.png` | Gemini | Enabled status, model "google/gemini-2.5-flash", at least 1 cached classification showing severity refinement |
| `architecture.png` | — | Architecture diagram (see README ascii art — convert to a diagram using Excalidraw or similar) |

## How to take them

1. Make sure the stack is running: `docker compose up -d`
2. Open `http://localhost:3000` in your browser
3. Navigate to each tab and take a full-window screenshot
4. Save to `docs/screenshots/` with the filenames above

## How to populate data for screenshots

```bash
# Generate audit events (researcher agent doing legitimate work)
for i in $(seq 1 5); do
  curl -s -X POST http://localhost:9001/audit/step \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"research-demo\",\"agent_id\":\"researcher-1\",\"agent_type\":\"researcher\",\"step_number\":$i,\"tool_name\":\"web_search\",\"tool_input\":{\"q\":\"EU AI Act Article 50\"},\"tool_output\":{\"results\":3},\"cost_cents\":5,\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
done

# Generate a denial spike (coder using image_generate — not allowed)
for i in $(seq 1 8); do
  curl -s -X POST http://localhost:9001/audit/step \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"coder-demo\",\"agent_id\":\"coder-1\",\"agent_type\":\"coder\",\"step_number\":$i,\"tool_name\":\"image_generate\",\"tool_input\":{},\"tool_output\":{},\"cost_cents\":10,\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
done

# Generate reports
curl -s -X POST http://localhost:9001/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"type":"finra"}'
curl -s -X POST http://localhost:9001/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"type":"eu-ai-act"}'
```