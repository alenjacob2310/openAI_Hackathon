"""LangGraph RAG agent for grounded containment checklist generation."""

from __future__ import annotations

from typing import Any, TypedDict

from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph

from src.alert_parser import ParsedAlert, parse_alert, parse_alert_json_string
from src.config import OPENAI_API_KEY, OPENAI_MODEL, RETRIEVER_K
from src.vector_store import retrieve_incident_documents
from src.knowledge import render_grounded_checklist


class AgentState(TypedDict, total=False):
    alert_json: str
    parsed_alert: dict[str, Any]
    retrieval_query: str
    retrieved_docs: list[dict[str, Any]]
    containment_checklist: str
    citations: list[str]
    error: str


def _require_api_key() -> None:
    if not OPENAI_API_KEY:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Copy .env.example to .env and add your key."
        )


def get_llm(temperature: float = 0.1) -> ChatOpenAI:
    _require_api_key()
    return ChatOpenAI(model=OPENAI_MODEL, temperature=temperature, api_key=OPENAI_API_KEY)


def _doc_to_dict(doc: Document) -> dict[str, Any]:
    return {
        "content": doc.page_content,
        "metadata": dict(doc.metadata or {}),
    }


def node_parse_alert(state: AgentState) -> AgentState:
    """Node 1: Parse raw alert JSON into structured IoCs + classification."""
    try:
        parsed: ParsedAlert = parse_alert_json_string(state["alert_json"])
        return {
            **state,
            "parsed_alert": parsed.model_dump(),
            "error": "",
        }
    except Exception as exc:  # noqa: BLE001
        return {**state, "error": f"Alert parse failed: {exc}"}


def node_build_query(state: AgentState) -> AgentState:
    """Node 2: Build a retrieval query from classification, IoCs, and CVEs."""
    if state.get("error"):
        return state
    parsed = state.get("parsed_alert") or {}
    classification = parsed.get("attack_classification", "Unknown")
    iocs = parsed.get("iocs") or {}
    cves = parsed.get("related_cves") or []
    mitre = parsed.get("mitre_techniques") or []
    rule = parsed.get("rule_name", "")

    ioc_flat = []
    for vals in iocs.values():
        ioc_flat.extend(vals[:5])

    query = (
        f"SOC incident response playbook for {classification}. "
        f"Rule: {rule}. MITRE: {', '.join(mitre)}. "
        f"IoCs: {', '.join(ioc_flat)}. "
        f"Related CVEs: {', '.join(cves)}. "
        f"Containment checklist SOP steps and CVE mitigations."
    )
    return {**state, "retrieval_query": query}


def node_retrieve(state: AgentState) -> AgentState:
    """Node 3: Retrieve grounded playbook + CVE chunks from ChromaDB."""
    if state.get("error"):
        return state
    try:
        parsed = state.get("parsed_alert") or {}
        docs = retrieve_incident_documents(state["retrieval_query"], parsed.get("attack_classification", "Unknown"), parsed.get("related_cves", []), k=RETRIEVER_K)
        return {**state, "retrieved_docs": [_doc_to_dict(d) for d in docs]}
    except Exception as exc:  # noqa: BLE001
        return {**state, "error": f"Retrieval failed: {exc}"}


def node_generate_checklist(state: AgentState) -> AgentState:
    """Node 4: Generate a grounded containment checklist with SOP citations."""
    if state.get("error"):
        return state

    parsed = state.get("parsed_alert") or {}
    docs = state.get("retrieved_docs") or []

    try:
        text, citations = render_grounded_checklist(parsed, docs)
        return {**state, "containment_checklist": text, "citations": citations}
    except ValueError as exc:
        return {**state, "error": str(exc)}


def build_agent_graph():
    """Compile the LangGraph state machine for the SOC RAG assistant."""
    graph = StateGraph(AgentState)
    graph.add_node("parse_alert", node_parse_alert)
    graph.add_node("build_query", node_build_query)
    graph.add_node("retrieve", node_retrieve)
    graph.add_node("generate_checklist", node_generate_checklist)

    graph.set_entry_point("parse_alert")
    graph.add_edge("parse_alert", "build_query")
    graph.add_edge("build_query", "retrieve")
    graph.add_edge("retrieve", "generate_checklist")
    graph.add_edge("generate_checklist", END)
    return graph.compile()


_GRAPH = None


def get_agent():
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_agent_graph()
    return _GRAPH


def run_incident_assistant(alert: dict[str, Any] | str) -> dict[str, Any]:
    """
    Run the full LangGraph pipeline on a raw alert (dict or JSON string).

    Returns state including parsed_alert, retrieved_docs, containment_checklist.
    """
    if isinstance(alert, dict):
        import json

        alert_json = json.dumps(alert)
        # Validate early
        parse_alert(alert)
    else:
        alert_json = alert

    agent = get_agent()
    result = agent.invoke({"alert_json": alert_json})
    return result
