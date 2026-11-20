# SOC Incident Runbook & Threat Intel Assistant

Live demo: [SOC Copilot on Streamlit Cloud](https://openaihackathon-soc-copilot.streamlit.app/)

Hackathon problem 4A: JSON alert → IoCs/classification → Chroma retrieval → exact cited organizational steps → one-click Markdown incident ticket.

The working copy was reviewed and repaired from `openAI_Hackaton.zip`. See [ASSESSMENT.md](ASSESSMENT.md) for findings, changes, and validation limits. Offline output examples are in [examples/](examples/).

## Quick start (macOS/Linux)

Use Python 3.14 in a virtual environment. Verified here on macOS arm64 with Python 3.14.8; exact installed dependencies are in `requirements.lock.txt`. Other Python versions and operating systems have not been validated.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock.txt
cp .env.example .env
```

For vector retrieval, set your own `OPENAI_API_KEY` in `.env`. Local demo mode works without a key. The original archive's `.env` was deliberately excluded; if its credentials were real and the archive was shared, rotate them.

```bash
streamlit run app.py
# Optional: python scripts/ingest.py to prebuild the vector index
```

Open **Incident workspace** in the sidebar. The app opens with a phishing sample ready to investigate.

- **Local demo:** works without an API key. Click **Analyze alert** to match bundled SOPs directly and generate an exact cited checklist. This mode is explicitly labeled as direct source lookup, not vector retrieval.
- **Vector retrieval:** uses the existing OpenAI embeddings, Chroma, and LangGraph backend. Configure `OPENAI_API_KEY` in `.env`, select this mode in the sidebar, and click **Analyze alert**. A missing or stale index is rebuilt by the backend.
- Choose any of the five samples, paste JSON, or expand **Import JSON alert** to upload a file (up to 1 MB).
- Review steps using native checkboxes, track review progress, and open a numbered citation to inspect exact SOP text. Review checkmarks record applicability review, not action execution.
- Use the **Indicators** tab to inspect and export IoCs. Search/filter sources in **Evidence**.
- Open **Incident ticket**, enter optional analyst details/notes, then click **Generate Incident Ticket**. Download Markdown or export the full investigation as JSON, including step reviews. Regenerate the ticket after changing notes or review selections.

Changing alert content or analysis mode clears the prior response, review selections, notes, and ticket. Reset clears the current investigation while keeping the input available. Activity history is available in the sidebar. Session state is local to the active Streamlit session; only generated ticket files are persisted.

The workspace has a dark SOC Copilot theme and adapts to desktop and narrow screens. Its optional mesh simulation pages remain available under **Local simulation**; no mesh nodes are needed for the core assistant.


## What is grounded

- Five Markdown SOPs are indexed at individual numbered-step granularity with SOP ID, category, section, original line number, and source filename.
- OpenAI embeddings power a persistent Chroma vector store. Retrieval searches within the classified playbook and also fetches all matching triage, containment, and escalation steps so top-k cannot silently truncate the checklist.
- The final checklist is assembled from exact retrieved SOP text. Conditions such as “if credentials were submitted” are preserved. This is an extractive checklist generator; it does not ask a model to rewrite approved procedures.
- Explicit CVE IDs are matched exactly against eight bundled mock advisories, including vendor reference URLs. Missing IDs are reported. The mock feed is not a live or verified vulnerability source; an ID match does not establish exploitation or affected asset applicability.
- Unsupported or ambiguous classifications stop before generating a checklist.
- The incident ticket orders observed timestamps, marks root cause unconfirmed, and distinguishes recommendations from completed actions. Ticket creation itself does not execute containment.
- Changes to knowledge files or the embedding model invalidate the index. `python scripts/ingest.py --force` forces replacement; the normal command reuses a current index.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m pip check
```

Tests use real persistent Chroma and LangGraph with deterministic local test embeddings. No OpenAI credentials or API calls are needed for tests. These tests validate the application plumbing and source grounding, not OpenAI semantic retrieval quality.

## Data and structure

```text
app.py                         Streamlit navigation
src/alert_parser.py            JSON validation, IoCs, heuristic classifications
src/knowledge.py               Atomic SOP records and exact checklist rendering
src/vector_store.py            Chroma ingestion, freshness, scoped retrieval
src/agent.py                   LangGraph parse → query → retrieve → checklist
src/ticket_generator.py        Evidence-only Markdown ticket generation/export
data/playbooks/                Five sample organizational SOPs
data/cves/cve_feed.json         Eight mock CVE records
data/alerts/                   Five synthetic alerts, including Public S3 Bucket
ui/workspace.py                Demo adapter, review state, citation helpers
ui/previews/                   Browser-verified interface screenshot
tests/                         Parser, grounding, Chroma, graph, tickets, auth, UI
network/, src/monitor_agent.py  Optional localhost simulation
```

## Optional localhost simulator

This is an extra demo, outside the four core requirements. It simulates mesh telemetry and containment; it is not an EDR, firewall, IAM, S3, or production SOC integration.

Run `python scripts/setup_simulator.py` once to create missing random node JWT secrets and the mesh service password in your ignored local `.env`. The command preserves existing nonempty settings and never prints secret values. Then start the nodes. Never reuse the original archive's secrets.

```bash
python scripts/setup_simulator.py
python -m network.run_nodes
```

Nodes bind to `127.0.0.1`. Administrative actions require a service/admin JWT. Demo user/password shortcuts are disabled by default. Set `SOC_ENABLE_SIMULATION_ACTIONS=true` only when deliberately demonstrating the local simulation's autonomous actions. Keep `SOC_ENABLE_DEMO_LOGIN=false` unless you need the synthetic login shortcut. Do not expose this simulator to a network or use it for production incident response.

`OPENAI_MODEL` controls only the optional monitor's LLM planning. Core checklist/ticket text is generated deterministically; `EMBEDDING_MODEL` controls the core vector index.

## Remaining work before production

Obtain organization-approved and version-controlled SOPs, validate real alert schemas and classification quality, add authenticated application access and tenant isolation, protect ticket/evidence data, integrate live threat intelligence with product/version applicability checks, and connect a ticketing system if required. Measure analyst containment-time improvement with a realistic labeled evaluation set. The optional simulator still needs a full execution-policy and threat-model review before any external deployment.


## Streamlit Community Cloud deployment

Deploy the GitHub repository `alenjacob2310/openAI_Hackathon`, branch `main`, entrypoint `app.py`. In **Advanced settings**, select **Python 3.14** to match the tested interpreter. `requirements.txt` contains runtime dependencies; `requirements.lock.txt` remains the full local development snapshot. Start with Local demo mode: no API secret is required. For vector retrieval, add your own `OPENAI_API_KEY` through Community Cloud's app secrets, never GitHub.

The network simulator is a separate local service. Deploying the Streamlit UI does not start ports 8001–8003, and a cloud app's localhost is not your computer. Heartbeat is disabled until credentials and all three nodes are available in the same environment. The cloud incident workspace can still parse alerts, show bundled cited SOPs, and generate tickets in Local demo mode.

Official deployment instructions: https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy
