"""Knowledge Base — browse ChromaDB, manage sources, configure chunking, rebuild index."""

from __future__ import annotations

import streamlit as st

from src.config import CHROMA_DIR, OPENAI_API_KEY, PLAYBOOKS_DIR
from src.vector_store import (
    UPLOADS_DIR,
    build_vector_store,
    collection_count,
    index_stats,
    list_source_files,
    load_chunk_config,
    knowledge_editing_enabled,
    peek_chunks,
    save_chunk_config,
    save_uploaded_file,
    search_chunks,
)
from ui.styles import banner, inject_styles, stat_card

STRATEGIES = {
    "recursive_markdown": "Recursive (Markdown-aware) — split on ## / ### then paragraphs",
    "fixed": "Fixed-size character chunks",
    "sop_steps": "SOP steps — one chunk per numbered playbook step",
}


def page() -> None:
    inject_styles()
    banner(
        "Knowledge Base",
        "Explore ChromaDB · manage source files · choose chunking · rebuild the index",
    )

    stats = index_stats()
    cfg = load_chunk_config()
    sources = list_source_files()
    can_edit = knowledge_editing_enabled()
    if not can_edit:
        st.info("Knowledge management is read-only. A server administrator can enable SOC_ENABLE_KB_EDITING for a trusted local session.")
    n_chunks = collection_count() if stats.get("indexed") else 0

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        stat_card(
            "Index status",
            "Ready" if stats.get("indexed") else "Empty",
            f"{CHROMA_DIR.name}/ persistent store",
        )
    with c2:
        stat_card("Chunks in Chroma", str(n_chunks).zfill(2), "Embedded vectors")
    with c3:
        stat_card("Source files", str(len(sources)).zfill(2), "Playbooks · CVE · uploads")
    with c4:
        strategy = cfg.get("strategy", "recursive_markdown")
        stat_card(
            "Chunk strategy",
            strategy.replace("_", " "),
            f"size={cfg.get('chunk_size')} · overlap={cfg.get('chunk_overlap')}",
        )

    if not OPENAI_API_KEY:
        st.warning("Set `OPENAI_API_KEY` in `.env` to build or query the vector index.")

    tab_browse, tab_files, tab_chunk, tab_rebuild = st.tabs(
        ["Browse ChromaDB", "Source files", "Chunking strategy", "Rebuild index"]
    )

    # ----- Browse -----
    with tab_browse:
        st.markdown("### Indexed content")
        st.caption("Inspect vectors currently stored in ChromaDB.")
        if not stats.get("indexed"):
            st.info("No index yet. Use **Rebuild index** after configuring chunking.")
        else:
            q = st.text_input(
                "Semantic search",
                placeholder="e.g. ransomware containment EDR isolation",
                key="kb_search",
            )
            if q.strip():
                if not OPENAI_API_KEY:
                    st.error("OPENAI_API_KEY required for search.")
                else:
                    with st.spinner("Searching…"):
                        hits = search_chunks(q.strip(), k=8)
                    if not hits:
                        st.caption("No matches.")
                    for i, hit in enumerate(hits, 1):
                        meta = hit.get("metadata") or {}
                        with st.expander(
                            f"[{i}] {meta.get('doc_type', '?')} · {meta.get('source', '')}"
                        ):
                            st.json(meta)
                            st.code(hit.get("content", ""), language="markdown")
            else:
                limit = st.slider("Chunks to show", 10, 100, 25, 5)
                offset = st.number_input("Offset", min_value=0, value=0, step=limit)
                rows = peek_chunks(limit=int(limit), offset=int(offset))
                st.caption(f"Showing {len(rows)} of ~{n_chunks} chunks (offset {offset})")
                for row in rows:
                    meta = row.get("metadata") or {}
                    label = (
                        f"{meta.get('doc_type', '?')} · {meta.get('source', row.get('id'))}"
                    )
                    with st.expander(label):
                        st.json(meta)
                        st.code(row.get("content", "")[:4000], language="markdown")

            with st.expander("Index marker metadata"):
                st.json({k: v for k, v in stats.items() if k != "indexed"})

    # ----- Source files -----
    with tab_files:
        st.markdown("### Currently processed files")
        st.caption("Playbooks, CVE feed, and uploaded documents that feed the index.")
        if sources:
            st.dataframe(
                [
                    {
                        "File": s["name"],
                        "Kind": s["kind"],
                        "Size (bytes)": s["bytes"],
                        "Path": s["path"],
                    }
                    for s in sources
                ],
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No source files found.")

        indexed_sources = stats.get("sources") or []
        if indexed_sources:
            st.markdown("**Last indexed source list**")
            st.write(", ".join(indexed_sources))

        st.divider()
        st.markdown("### Add new files")
        dest = st.radio(
            "Store uploaded file as",
            options=["uploads", "playbooks"],
            horizontal=True,
            help="Playbooks go to data/playbooks/*.md. Other docs go to data/uploads/.",
        )
        uploads = st.file_uploader(
            "Upload Markdown, text, or JSON",
            type=["md", "txt", "json"],
            accept_multiple_files=True,
            key="kb_uploader",
            disabled=not can_edit,
        )
        if uploads and st.button("Save uploads", type="primary", disabled=not can_edit):
            saved = []
            for f in uploads:
                try:
                    path = save_uploaded_file(f.name, f.getvalue(), destination=dest)
                    saved.append(str(path))
                except (ValueError, OSError) as exc:
                    st.error(f"{f.name}: {exc}")
            if saved:
                st.success("Saved:\n" + "\n".join(f"- `{p}`" for p in saved))
            st.info("Click **Rebuild index** to embed the new files into ChromaDB.")

        st.caption("Uploads are supplementary material; existing SOP filenames cannot be replaced. New playbooks require explicit category mapping before becoming actionable SOPs.")
        st.caption(f"Playbooks dir: `{PLAYBOOKS_DIR}` · Uploads dir: `{UPLOADS_DIR}`")

    # ----- Chunking -----
    with tab_chunk:
        st.markdown("### Chunking strategy")
        st.caption("Controls contextual and uploaded document chunks. Approved SOP steps and CVE advisories remain intact in every strategy.")
        current = load_chunk_config()
        strategy = st.selectbox(
            "Strategy",
            options=list(STRATEGIES.keys()),
            format_func=lambda k: STRATEGIES[k],
            index=list(STRATEGIES.keys()).index(current.get("strategy", "recursive_markdown"))
            if current.get("strategy") in STRATEGIES
            else 0,
        )
        col_a, col_b = st.columns(2)
        with col_a:
            chunk_size = st.number_input(
                "Chunk size",
                min_value=200,
                max_value=4000,
                value=int(current.get("chunk_size", 900)),
                step=50,
                disabled=strategy == "sop_steps",
            )
        with col_b:
            chunk_overlap = st.number_input(
                "Chunk overlap",
                min_value=0,
                max_value=1000,
                value=int(current.get("chunk_overlap", 150)),
                step=25,
                disabled=strategy == "sop_steps",
            )
        if strategy == "sop_steps":
            st.info("SOP-step strategy preserves complete numbered items, including indented conditions. Documents without numbered steps use recursive chunks.")

        valid_window = int(chunk_overlap) < int(chunk_size)
        if not valid_window:
            st.error("Chunk overlap must be smaller than chunk size.")
        if st.button("Save chunking settings", disabled=not can_edit or not valid_window):
            saved = save_chunk_config(
                {
                    "strategy": strategy,
                    "chunk_size": int(chunk_size),
                    "chunk_overlap": int(chunk_overlap),
                }
            )
            st.success(f"Saved: {saved}")
            st.caption("Rebuild the index to apply the new strategy to all files.")

        st.markdown("**Preview split on one playbook**")
        pb_files = sorted(PLAYBOOKS_DIR.glob("*.md"))
        if pb_files:
            pick = st.selectbox("Sample file", options=[p.name for p in pb_files])
            if st.button("Preview chunks", disabled=not valid_window):
                from langchain_core.documents import Document
                from src.vector_store import split_documents

                text = (PLAYBOOKS_DIR / pick).read_text(encoding="utf-8")
                doc = Document(
                    page_content=text,
                    metadata={"source": pick, "doc_type": "playbook"},
                )
                preview = split_documents(
                    [doc],
                    strategy=strategy,
                    chunk_size=int(chunk_size),
                    chunk_overlap=int(chunk_overlap),
                )
                st.write(f"{len(preview)} chunks")
                for i, chunk in enumerate(preview[:12], 1):
                    with st.expander(f"Chunk {i} · {len(chunk.page_content)} chars"):
                        st.code(chunk.page_content[:2000], language="markdown")
                if len(preview) > 12:
                    st.caption(f"…and {len(preview) - 12} more")

    # ----- Rebuild -----
    with tab_rebuild:
        st.markdown("### Rebuild / re-process")
        st.caption(
            "Re-reads all playbooks, CVE feed, and uploads; re-chunks with the saved strategy; "
            "stages a versioned Chroma collection and switches it into use only after success."
        )
        st.json(
            {
                "sources": len(sources),
                "strategy": load_chunk_config().get("strategy"),
                "chunk_size": load_chunk_config().get("chunk_size"),
                "chunk_overlap": load_chunk_config().get("chunk_overlap"),
                "embedding_model": stats.get("embedding_model") or "text-embedding-3-small",
            }
        )
        force = st.checkbox("Force full rebuild (stage a new index version)", value=True)
        if st.button("Rebuild ChromaDB index", type="primary", disabled=not (bool(OPENAI_API_KEY) and can_edit)):
            try:
                with st.spinner("Embedding sources into ChromaDB…"):
                    build_vector_store(force_rebuild=force)
                st.success("Index rebuilt successfully.")
                st.json(index_stats())
                st.rerun()
            except Exception as exc:  # noqa: BLE001
                st.error(str(exc))

        if st.button("Re-process with current files only (same as rebuild)", disabled=not (can_edit and bool(OPENAI_API_KEY))):
            try:
                with st.spinner("Re-processing…"):
                    build_vector_store(force_rebuild=True)
                st.success("Re-processed all source files.")
                st.rerun()
            except Exception as exc:  # noqa: BLE001
                st.error(str(exc))


page()
