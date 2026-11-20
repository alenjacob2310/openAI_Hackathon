"""Persistent vector indexing with exact source locations and corpus freshness checks."""
from __future__ import annotations
import hashlib
import json
from typing import Any
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings
from src.config import CHROMA_DIR, COLLECTION_NAME, CVES_PATH, EMBEDDING_MODEL, OPENAI_API_KEY, PLAYBOOKS_DIR, RETRIEVER_K
from src.knowledge import playbook_records, cve_records, corpus_fingerprint


def get_embeddings():
    if not OPENAI_API_KEY:
        raise RuntimeError('Set OPENAI_API_KEY in .env (see .env.example).')
    return OpenAIEmbeddings(model=EMBEDDING_MODEL, api_key=OPENAI_API_KEY)


def _documents(records):
    return [Document(page_content=r['content'], metadata=r['metadata']) for r in records]


def load_playbook_documents(playbooks_dir=PLAYBOOKS_DIR):
    return _documents(playbook_records(playbooks_dir))


def load_cve_documents(cves_path=CVES_PATH):
    return _documents(cve_records(cves_path))


def split_documents(docs):
    # Steps and advisories are atomic: arbitrary character splitting loses SOP conditions.
    return docs


def _fingerprint():
    return corpus_fingerprint(PLAYBOOKS_DIR, CVES_PATH, EMBEDDING_MODEL)


def build_vector_store(force_rebuild=False):
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    store = Chroma(collection_name=COLLECTION_NAME, persist_directory=str(CHROMA_DIR), embedding_function=get_embeddings())
    stats = index_stats()
    if stats.get('indexed') and not force_rebuild:
        if store._collection.count() == stats.get('chunks'):
            return store
    docs = load_playbook_documents() + load_cve_documents()
    if not docs:
        raise ValueError('Knowledge base is empty')
    # Embed first, before replacing an existing collection. A failed API call preserves the old index.
    vectors = get_embeddings().embed_documents([d.page_content for d in docs])
    marker = CHROMA_DIR / '.indexed'
    marker.unlink(missing_ok=True)
    store.reset_collection()
    ids = [hashlib.sha256((json.dumps(d.metadata, sort_keys=True) + d.page_content).encode()).hexdigest() for d in docs]
    store._collection.upsert(ids=ids, documents=[d.page_content for d in docs],
                             metadatas=[d.metadata for d in docs], embeddings=vectors)
    metadata = dict(playbooks=len(list(PLAYBOOKS_DIR.glob('*.md'))), cves=len(load_cve_documents()),
                    chunks=len(docs), fingerprint=_fingerprint(), embedding_model=EMBEDDING_MODEL)
    temp = marker.with_suffix('.tmp')
    temp.write_text(json.dumps(metadata), encoding='utf-8')
    temp.replace(marker)
    return store


def get_vector_store():
    return build_vector_store()


def get_retriever(k=RETRIEVER_K):
    return get_vector_store().as_retriever(search_kwargs={'k': k})


def similarity_search(query, k=RETRIEVER_K):
    return get_vector_store().similarity_search(query, k=k)


def retrieve_incident_documents(query, classification, cve_ids, k=RETRIEVER_K):
    if classification == 'Unknown':
        return []
    store = get_vector_store()
    # Semantic search selects relevant context within the matched SOP, never a different SOP.
    docs = store.similarity_search(query, k=k, filter={'classification': classification})
    # Include every approved triage/containment/escalation step, not just top-k fragments.
    exact = store.get(where={'classification': classification})
    docs += [Document(page_content=text, metadata=meta) for text, meta in zip(exact['documents'], exact['metadatas'])]
    if cve_ids:
        cves = store.get(where={'cve_id': {'$in': cve_ids}})
        docs += [Document(page_content=text, metadata=meta) for text, meta in zip(cves['documents'], cves['metadatas'])]
    unique = {}
    for doc in docs:
        unique[(doc.page_content, json.dumps(doc.metadata, sort_keys=True))] = doc
    return list(unique.values())


def index_stats() -> dict[str, Any]:
    marker = CHROMA_DIR / '.indexed'
    try:
        stats = json.loads(marker.read_text(encoding='utf-8'))
        return {**stats, 'indexed': stats.get('fingerprint') == _fingerprint() and (CHROMA_DIR / 'chroma.sqlite3').exists()}
    except (OSError, ValueError, TypeError):
        return {'indexed': False}
