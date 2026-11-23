"""Versioned Chroma indexes, exact SOP steps, and configurable contextual document chunks."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

from src.config import CHROMA_DIR, COLLECTION_NAME, CVES_PATH, DATA_DIR, EMBEDDING_MODEL, OPENAI_API_KEY, PLAYBOOKS_DIR, RETRIEVER_K
from src.knowledge import CATEGORIES, playbook_records, cve_records, corpus_fingerprint, numbered_steps

UPLOADS_DIR = DATA_DIR / 'uploads'
DEFAULT_CHUNK_CONFIG = dict(strategy='recursive_markdown', chunk_size=900, chunk_overlap=150)
_INDEX_LOCK = threading.RLock()


def knowledge_editing_enabled() -> bool:
    return os.getenv('SOC_ENABLE_KB_EDITING', 'false').strip().lower() == 'true'


def get_embeddings():
    if not OPENAI_API_KEY:
        raise RuntimeError('Set OPENAI_API_KEY in .env or Streamlit app secrets (see .env.example).')
    return OpenAIEmbeddings(model=EMBEDDING_MODEL, api_key=OPENAI_API_KEY)


def _documents(records):
    return [Document(page_content=r['content'], metadata=r['metadata']) for r in records]


def load_playbook_documents(playbooks_dir=None):
    return _documents(playbook_records(playbooks_dir or PLAYBOOKS_DIR))


def load_cve_documents(cves_path=None):
    return _documents(cve_records(cves_path or CVES_PATH))


def _validate_config(config):
    result = {**DEFAULT_CHUNK_CONFIG, **config}
    if result['strategy'] not in {'recursive_markdown', 'fixed', 'sop_steps'}:
        raise ValueError('Unsupported chunk strategy')
    result['chunk_size'] = int(result['chunk_size'])
    result['chunk_overlap'] = int(result['chunk_overlap'])
    if not 200 <= result['chunk_size'] <= 4000:
        raise ValueError('Chunk size must be between 200 and 4000 characters')
    if not 0 <= result['chunk_overlap'] < result['chunk_size']:
        raise ValueError('Chunk overlap must be nonnegative and smaller than chunk size')
    return result


def load_chunk_config():
    path = CHROMA_DIR / '.chunk_config.json'
    if not path.exists():
        return dict(DEFAULT_CHUNK_CONFIG)
    return _validate_config(json.loads(path.read_text(encoding='utf-8')))


def _write_config(config):
    validated = _validate_config(config)
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    target = CHROMA_DIR / '.chunk_config.json'
    temporary = target.with_name(f'.chunk-config-{uuid4().hex}.tmp')
    temporary.write_text(json.dumps(validated), encoding='utf-8')
    temporary.replace(target)
    return validated


def save_chunk_config(config):
    if not knowledge_editing_enabled():
        raise PermissionError('Knowledge editing is disabled. Enable SOC_ENABLE_KB_EDITING only for a trusted local/admin session.')
    return _write_config(config)


def split_documents(docs, *, strategy=None, chunk_size=None, chunk_overlap=None):
    cfg = load_chunk_config()
    cfg.update({key: value for key, value in dict(strategy=strategy, chunk_size=chunk_size, chunk_overlap=chunk_overlap).items() if value is not None})
    cfg = _validate_config(cfg)
    splitter = RecursiveCharacterTextSplitter(chunk_size=cfg['chunk_size'], chunk_overlap=cfg['chunk_overlap'],
        separators=['\n\n', '\n', ' ', ''] if cfg['strategy'] == 'fixed' else ['\n## ', '\n### ', '\n\n', '\n', ' ', ''])
    chunks = []
    for doc in docs:
        if doc.metadata.get('doc_type') == 'cve':
            chunks.append(doc)
            continue
        steps = numbered_steps(doc.page_content) if cfg['strategy'] == 'sop_steps' else []
        if steps:
            pieces = [Document(page_content=step['content'], metadata={**doc.metadata,
                      **{key: value for key, value in step.items() if key != 'content'}}) for step in steps]
        else:
            # Ordinary text still gets indexed when the selected strategy is SOP steps.
            pieces = splitter.split_documents([doc])
        for piece in pieces:
            piece.metadata.update(chunk_strategy=cfg['strategy'], chunk_size=cfg['chunk_size'], chunk_overlap=cfg['chunk_overlap'])
        chunks.extend(pieces)
    return chunks


def load_upload_documents(uploads_dir=None):
    folder = uploads_dir or UPLOADS_DIR
    return [Document(page_content=p.read_text(encoding='utf-8'), metadata=dict(source=p.name, title=p.stem, doc_type='upload', approved=False))
            for p in sorted(folder.glob('*')) if p.is_file() and not p.is_symlink() and p.suffix.lower() in {'.md', '.txt', '.json'}]


def list_source_files():
    rows = []
    for folder, kind in [(PLAYBOOKS_DIR, 'playbook'), (UPLOADS_DIR, 'upload')]:
        if folder.exists():
            rows += [dict(name=p.name, kind=kind, path=str(p), bytes=p.stat().st_size) for p in sorted(folder.glob('*'))
                     if p.is_file() and not p.is_symlink() and p.suffix.lower() in ({'.md'} if kind == 'playbook' else {'.md', '.txt', '.json'})]
    if CVES_PATH.exists():
        rows.append(dict(name=CVES_PATH.name, kind='cve_feed', path=str(CVES_PATH), bytes=CVES_PATH.stat().st_size))
    return rows


def save_uploaded_file(filename, data, *, destination='uploads'):
    if not knowledge_editing_enabled():
        raise PermissionError('Knowledge editing is disabled on this server.')
    safe = Path(filename.replace('\\', '/')).name
    if safe in {'', '.', '..'} or Path(safe).suffix.lower() not in {'.md', '.txt', '.json'}:
        raise ValueError('Upload a Markdown, text, or JSON file with a valid name.')
    if destination not in {'uploads', 'playbooks'}:
        raise ValueError('Unsupported destination')
    if destination == 'playbooks' and Path(safe).suffix.lower() != '.md':
        raise ValueError('Playbooks must be Markdown files.')
    if len(data) > 1_000_000:
        raise ValueError('Knowledge file exceeds 1 MB limit')
    text = data.decode('utf-8-sig')
    if Path(safe).suffix.lower() == '.json':
        json.loads(text)
    folder = PLAYBOOKS_DIR if destination == 'playbooks' else UPLOADS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / safe
    # Exclusive creation rejects collisions and symlinks. Existing approved SOPs are never overwritten.
    with target.open('xb') as file:
        file.write(text.encode('utf-8'))
    return target


def _fingerprint():
    digest = hashlib.sha256(('versioned-index-v3:' + corpus_fingerprint(PLAYBOOKS_DIR, CVES_PATH, EMBEDDING_MODEL)).encode())
    digest.update(json.dumps(load_chunk_config(), sort_keys=True).encode())
    if UPLOADS_DIR.exists():
        for path in sorted(UPLOADS_DIR.glob('*')):
            if path.is_file() and not path.is_symlink() and path.suffix.lower() in {'.md', '.txt', '.json'}:
                digest.update(path.name.encode()); digest.update(path.read_bytes())
    return digest.hexdigest()


def _open_store(collection):
    return Chroma(collection_name=collection, persist_directory=str(CHROMA_DIR), embedding_function=get_embeddings())


def build_vector_store(force_rebuild=False, *, strategy=None, chunk_size=None, chunk_overlap=None):
    with _INDEX_LOCK:
        overrides = {key: value for key, value in dict(strategy=strategy, chunk_size=chunk_size, chunk_overlap=chunk_overlap).items() if value is not None}
        if overrides:
            save_chunk_config({**load_chunk_config(), **overrides})
        CHROMA_DIR.mkdir(parents=True, exist_ok=True)
        stats = index_stats()
        if stats.get('indexed') and not force_rebuild:
            existing = _open_store(stats['collection_name'])
            if existing._collection.count() == stats.get('chunks'):
                return existing
        fingerprint = _fingerprint()
        playbooks = load_playbook_documents()
        cves = load_cve_documents()
        uploads = load_upload_documents()
        context = [Document(page_content=p.read_text(encoding='utf-8'), metadata=dict(source=p.name,
                   doc_type='playbook_context', classification=CATEGORIES.get(p.stem, 'Unknown')))
                   for p in sorted(PLAYBOOKS_DIR.glob('*.md'))]
        docs = playbooks + cves + split_documents(context + uploads)
        if not docs:
            raise ValueError('Knowledge base is empty')
        embeddings = get_embeddings().embed_documents([d.page_content for d in docs])
        if fingerprint != _fingerprint():
            raise RuntimeError('Sources changed during indexing. Retry the rebuild.')
        # Stage a separate collection. Readers retain the previous collection until the marker is switched.
        name = f'{COLLECTION_NAME}_{uuid4().hex}'
        staged = _open_store(name)
        try:
            ids = [hashlib.sha256((json.dumps(d.metadata, sort_keys=True) + d.page_content).encode()).hexdigest() for d in docs]
            staged._collection.upsert(ids=ids, documents=[d.page_content for d in docs],
                                      metadatas=[d.metadata for d in docs], embeddings=embeddings)
            metadata = dict(playbooks=len(list(PLAYBOOKS_DIR.glob('*.md'))), cves=len(cves), uploads=len(uploads),
                source_docs=len(list(PLAYBOOKS_DIR.glob('*.md'))) + len(cves) + len(uploads), chunks=len(set(ids)),
                collection_name=name, fingerprint=fingerprint, embedding_model=EMBEDDING_MODEL,
                chunk_config=load_chunk_config(), sources=[row['name'] for row in list_source_files()])
            temporary = CHROMA_DIR / f'.indexed-{uuid4().hex}.tmp'
            temporary.write_text(json.dumps(metadata), encoding='utf-8')
            temporary.replace(CHROMA_DIR / '.indexed')
        except Exception:
            staged.delete_collection()
            raise
        # Keep earlier versions so in-flight readers remain valid; explicit rebuilds can be serialized safely.
        return staged


def index_stats() -> dict[str, Any]:
    try:
        stats = json.loads((CHROMA_DIR / '.indexed').read_text(encoding='utf-8'))
        return {**stats, 'indexed': bool(stats.get('collection_name')) and stats.get('fingerprint') == _fingerprint()
                and (CHROMA_DIR / 'chroma.sqlite3').exists()}
    except (OSError, ValueError, TypeError):
        return {'indexed': False, 'chunk_config': dict(DEFAULT_CHUNK_CONFIG)}


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
    docs = store.similarity_search(query, k=k, filter={'classification': classification})
    exact = store.get(where={'$and': [{'classification': classification}, {'doc_type': 'playbook'}]})
    docs += [Document(page_content=text, metadata=meta) for text, meta in zip(exact['documents'], exact['metadatas'])]
    if cve_ids:
        cves = store.get(where={'cve_id': {'$in': cve_ids}})
        docs += [Document(page_content=text, metadata=meta) for text, meta in zip(cves['documents'], cves['metadatas'])]
    unique = {(d.page_content, json.dumps(d.metadata, sort_keys=True)): d for d in docs}
    return list(unique.values())


def _read_only_store():
    if not index_stats().get('indexed'):
        return None
    stats = index_stats()
    # Browsing existing records does not require embedding calls or an API key.
    return Chroma(collection_name=stats['collection_name'], persist_directory=str(CHROMA_DIR), embedding_function=None)


def collection_count():
    store = _read_only_store()
    return store._collection.count() if store else 0


def peek_chunks(limit=50, offset=0):
    store = _read_only_store()
    if store is None:
        return []
    result = store.get(limit=min(max(int(limit), 1), 100), offset=max(int(offset), 0))
    return [dict(id=id_, content=content, metadata=meta) for id_, content, meta in zip(result['ids'], result['documents'], result['metadatas'])]


def search_chunks(query, k=8):
    return [dict(content=d.page_content, metadata=dict(d.metadata)) for d in similarity_search(query, k=k)]
