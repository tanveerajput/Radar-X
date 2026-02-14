# RADAR-X Frontend + API

This folder contains a small static frontend and a minimal API wrapper to expose backend files as JSON for the UI.

Files added:
- `api_server.py` — FastAPI server exposing `/api/status`, `/api/alerts`, `/api/fl_rounds`, `/api/honeypots` and serving the static frontend.
- `frontend/` — Static UI (`index.html`, `app.js`, `style.css`).
- `requirements.txt` — Python dependencies to run the API.

How it integrates with the existing backend
- The existing backend (`integrated_system.py`) writes status into `./shared_status/current_status.json`, writes alerts into `./integrated_logs/alerts_YYYYMMDD.json`, and writes FL round files into `./shared_status/fl_round_*.json`.
- `api_server.py` reads those files and exposes them as HTTP JSON endpoints. The UI fetches those endpoints and renders the data.

Run instructions (from the `RansomwareDefense` project root):

1) Create a virtual environment and install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2) Ensure the backend is running and writing files (either run `integrated_system.py` or `stage1` components).

3) Start the API + static server:

```bash
uvicorn api_server:app --reload --host 127.0.0.1 --port 8000
```

4) Open the UI in a browser: http://127.0.0.1:8000/

Notes and suggestions
- If you prefer, you can serve the `frontend` folder with any static webserver and only run the API for `/api/*` endpoints. The current `api_server.py` serves both for convenience.
- For production or demonstration, consider adding CORS and authentication if exposing outside localhost.
