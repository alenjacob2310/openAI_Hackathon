# Hackathon 4A implementation assessment

Reviewed against the problem statement supplied in the chat. Archive contents were treated as source material; embedded documentation was not treated as an independent user instruction. The original ZIP was left unchanged. Secrets, bytecode, the original vector database, and historical logs were excluded from the repaired working copy.

## Requirement coverage

| Requirement | Original implementation | Repaired implementation |
|---|---|---|
| Vector indexing of internal SOPs and CVEs | Chroma and OpenAI embeddings present; arbitrary 900-character chunks; no source line/step metadata; marker file could become stale; rebuild removed the entire database directory | Atomic step/advisory records; filename, SOP ID, exact source line, section and step; content/model fingerprint; collection replacement after embeddings succeed; repeatable index builds |
| JSON alert parser with IoCs and classification | Present for four samples; top-level arrays/null produced poor errors; broad keywords such as `bot` matched unrelated text; hostnames omitted; Windows paths parsed incorrectly; URL domains retained ports | Clear object/size/hint validation; bounded keyword matching; ambiguity returns Unknown; structured hostname and Windows filename extraction; URL host parsing and IPv6 candidates; five scenario samples |
| Grounded checklist with exact organizational citations | LLM instructed to cite top-k chunks; no enforcement of source support; mixed playbooks/CVEs possible; important steps could be omitted | Category-scoped semantic search plus complete matched SOP retrieval; exact steps assembled into checklist; source/line/step citation on each action; unknown categories stop; no model rewrite or alert-driven instructions in checklist text |
| One-click incident ticket with timeline, root cause and containment | UI button, Markdown save and download existed; model could confuse recommended/completed work; no guaranteed timeline ordering; stale alert state possible | Deterministic ticket with sorted observed timestamps; root cause explicitly unconfirmed; actions recommended vs completed separated; source citations retained; safe unique filenames; UI invalidates prior results on edits or sample changes |
| Suggested dataset | All five playbooks, eight mock CVEs, four alert logs already supplied | Original dataset retained; added a fifth alert to exercise Public S3 Bucket end to end |

## Findings fixed

1. **High — grounding was prompt-only.** `src/agent.py` previously trusted free-form model output. `src/knowledge.py` now renders only indexed source steps. This reduces flexibility but makes every action directly inspectable and preserves SOP conditions. Alert text is never interpreted as code or a checklist-generation instruction.
2. **High — unrelated or incomplete retrieval.** A single unrestricted similarity search could omit containment steps or surface a different attack's playbook. `retrieve_incident_documents` scopes retrieval and includes every numbered step of the matching SOP; the renderer selects its triage, containment, and escalation sections. Different original timing windows (10, 15, and 20 minutes) are preserved.
3. **High — CVE applicability was easy to overstate.** Generic top-k CVEs could appear relevant merely because of shared attack terms. The core assistant includes only explicitly observed CVE IDs and reports missing IDs. Mock-feed provenance, timestamp, and original reference URLs are retained. Matching an ID does not confirm exploitation or product/version applicability.
4. **High — ticket evidence could be overstated.** Ticket generation no longer uses an LLM to invent chronology, root cause, ownership, or completed containment. It explicitly records that no completed actions were captured by this assistant.
5. **High — simulator administrative authorization.** Recovery previously required no authentication; remediation and key rotation accepted any valid JWT. Service/admin role checks now cover all three routes. Demo login shortcuts are opt-in, JWT issuer/required claims are checked, reserved claim override is rejected, and the built-in service-password fallback is removed. Autonomous simulator execution defaults to disabled.
6. **Medium — UI could show an old incident.** Editing JSON or switching samples invalidates parsed/checklist/ticket state. Starting a new agent run clears prior results even if the new run fails. Retrieved source text is visible in the UI.
7. **Medium — packaging/startup defects.** `.env.example` was referenced but absent from the ZIP; it is now supplied without credentials. Added `.gitignore`, corrected the Streamlit minimum for `st.Page`/`st.navigation`, made the AI Agent page the default, fixed the ingest CLI's `force or True` expression, and loaded `.env` from the project root.
8. **Medium — index freshness and rebuild safety.** Corpus and embedding-model changes invalidate the marker. A failed embedding request preserves the existing collection. Rebuilds no longer recursively remove the database directory. Concurrent rebuilds are still unsupported; run one indexing process at a time.

## Deliberate design choices

The core uses OpenAI embeddings and Chroma for retrieval, LangGraph for workflow orchestration, and an extractive generator for the checklist and ticket. The optional monitor retains model-based simulation planning. This change prioritizes exact approved SOP wording over free-form generated containment advice; present that design honestly to judges.

The ticket button creates a local Markdown incident ticket. External ticket-system creation is not implemented and was not required explicitly in the supplied statement. Root cause is not automatically “proven”: the alert and sample SOPs do not contain enough evidence to establish it reliably.

## Remaining gaps and limitations

- Classification is a heuristic triage aid. The five supplied scenario alerts are a smoke-test dataset, not evidence of general detection accuracy. Real SIEM schemas, ambiguous/multistage incidents, false positives, confidence thresholds, and more diverse IoCs need evaluation.
- SOPs are synthetic examples. Organization approval, owner identity, formal versions, signatures, and change-control history are not established. Source citations are valid against the bundled files; retain the source version alongside tickets for long-term auditability.
- CVE data is explicitly mocked. Live refresh, trusted source validation, affected product/version checks, CVSS provenance, exploitation evidence, and freshness policies are not implemented. The bundled advisory claims were not independently fact-checked.
- Exact CVE matching is conservative: it does not discover CVEs from product inventory when an alert lacks an ID.
- Source indexing currently targets the supplied single-line numbered SOP format. Multiline steps, tables, PDFs, and external document formats need dedicated parsers and tests.
- The Streamlit application has no user authentication, tenant isolation, access roles, redaction workflow, audit backend, ticket retention policy, or deployment hardening. Raw alerts and tickets may contain sensitive data. Do not deploy it as a production SOC platform.
- The optional localhost simulator includes synthetic attack endpoints and model/fallback action planning. It is not an actual endpoint/firewall/cloud control integration. Its opt-in execution mode needs further policy validation, target restrictions, least privilege, and audit review before external use.
- Index freshness is checked from source/model hashes; database corruption and concurrent rebuilds are not fully handled. For this demo, build one index at a time.
- No containment-time improvement benchmark or real analyst usability study has been performed. Avoid claiming measured incident-response gains.

## Demo sequence

1. Open the AI Agent page and build the index with your own OpenAI key.
2. Parse the phishing sample; inspect IoCs and attack classification.
3. Run the graph; show `MG-PHISH-03`, `IAM-RESET-02`, and their exact SOP lines.
4. Generate/download a ticket; point out observed timeline ordering, unconfirmed root cause, and recommended actions.
5. Repeat with ransomware and Public S3 Bucket. Show the different SOP timing windows and policies.
6. Demonstrate an unknown alert stopping safely, and a missing CVE ID being reported rather than fabricated.

## Validation

Verified on macOS arm64, Python 3.14.8:

- `python -m pytest -q`: **24 passed**. Includes all five sample classifications, invalid inputs and IoC edge cases, exact source-line grounding, mock-CVE provenance, real persistent Chroma ingestion/retrieval/rebuilds, LangGraph execution, prompt-injection text isolation from checklist output, unknown-class failure, safe ticket paths, timeline ordering, JWT/admin authorization, simulator execution gating, and Streamlit AppTest flows for sample changes and ticket creation.
- `python -m pip check`: **No broken requirements found.**
- Python source compilation completed successfully.
- The tests emitted 18 dependency deprecation warnings about `asyncio.iscoroutinefunction` in LangSmith/Chroma under Python 3.14; no test failures remained.

Chroma tests use deterministic local test embeddings. This validates storage, filtering, complete-step retrieval and graph integration, but does **not** validate OpenAI embedding relevance, API authentication, latency, cost, or live threat intelligence. Streamlit AppTest validates behavior, not browser visual layout. No credentials from the ZIP were used. Offline examples in `examples/` show the generated checklist/ticket format without making a live retrieval claim.


## Interactive UI update — November 20, 2026

The Streamlit UI now includes a responsive SOC Copilot incident workspace, alert selection/JSON import, explicitly labeled local demo and vector retrieval modes, interactive SOP review checkboxes, progress tracking, numbered source popovers, an IoC table/export, searchable evidence, analyst ticket notes, and investigation JSON export. The local demo adapter uses bundled sources directly and makes no OpenAI/vector-retrieval claim. Core retrieval and ticket generators remain connected to the interface.

**Validation:** 27 automated tests passed after the update. New UI tests cover a full offline demo/review/ticket flow, incident and mode isolation, missing-key behavior, unknown-alert refusal, and evidence filtering. Browser verification at desktop and narrow-screen sizes confirmed the layout, full checklist text wrapping, citation source details, review progress, and a generated downloadable ticket. A desktop screenshot is included in `ui/previews/incident-workspace.jpg`. Live OpenAI API behavior remains outside this validation.


## Simulator setup and cloud preparation — November 20, 2026

Added an idempotent local simulator setup command that creates missing random secrets without logging them or replacing existing values. The network UI now disables heartbeat until credentials and all three nodes are ready, gives precise setup instructions, and reports successful heartbeat acceptance. Environment-provided values take precedence over local dotenv values. Streamlit secrets files are excluded from Git.

**Validation:** 31 tests passed. Verified all three localhost nodes healthy and an authenticated heartbeat from 8001 to 8002 accepted with HTTP 200. Cloud deployment uses a smaller explicit runtime dependency list with Python 3.14. Cloud hosting itself still requires a signed-in Streamlit account; this preparation does not claim a successful cloud deployment.


### Cloud deployment verified

The existing Streamlit Community Cloud deployment at https://openaihackathon-soc-copilot.streamlit.app/ was verified after the simulator fix reached `main`. In the live cloud UI, the phishing sample generated 13 cited review steps and a downloadable incident ticket that kept root cause unconfirmed and did not claim completed containment. The cloud network page displayed setup guidance and a disabled heartbeat button because its local node services were absent. On the local machine, all three nodes were online and a UI-triggered authenticated heartbeat was accepted with HTTP 200. No cloud OpenAI embedding call or real containment action was performed.
