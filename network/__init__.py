"""Multi-node FastAPI mesh with JWT auth and attack-scenario simulation."""

NODE_PORTS = (8001, 8002, 8003)
NODE_URLS = {p: f"http://127.0.0.1:{p}" for p in NODE_PORTS}
