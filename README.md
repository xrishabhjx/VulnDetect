# VulnDetect

`VulnDetect` is an AI-assisted vulnerability risk-scoring and prompt-injection detection platform. It combines public vulnerability intelligence (NVD, CISA KEV, and EPSS) with locally run, transparent scoring and detection models.

Core risk scoring is designed to work without paid LLM APIs. Machine-learning and rule-based components can support analysis, while any future optional language-model integrations remain outside the core scoring path.

## Project layout

- `ingestion/` — NVD, CISA KEV, and EPSS ingestion, dataset building, and GitHub manifest parsing
- `models/` — risk-model training, prompt-injection classification, embeddings, and OSV lookup
- `api/` — FastAPI assessment API, repository scanner, and risk engine
- `frontend/` — React + TypeScript dashboard using Vite
- `demo_app.py` — Streamlit demonstration app for repository scans, CVE assessment, and model evaluation
- `data/` — local data storage; contents are ignored by Git except `.gitkeep`
- `notebooks/` — exploratory analysis
- `tests/` — automated tests

## Dependencies

The Python dependencies are listed in `requirements.txt`. I chose this straightforward format over Poetry because this initial project is a small scaffold with no package or publishing configuration; a plain requirements file is easy to install and extend. The frontend uses npm and its dependencies are declared in `frontend/package.json`.

## Getting started

Create and activate a Python virtual environment, then install the Python dependencies:

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Install the frontend dependencies when you are ready to work on the UI:

```bash
cd frontend
npm install
npm run dev
```

## Run the interactive demo locally

First prepare the datasets and model artifacts using the commands in the Docker demo section below. Start the API from the project root in one terminal:

```bash
uvicorn api.main:app --reload
```

In a second terminal, activate the same virtual environment and start the Streamlit interface:

```bash
streamlit run demo_app.py
```

The demo defaults to the API at `http://127.0.0.1:8000`. Set `VULNDETECT_API_URL` if the API is hosted elsewhere. Repository scans require network access to GitHub and OSV.dev.

## Full-stack local demo with Docker Compose

Docker images contain application code and runtime dependencies only. Datasets, evaluation reports, and trained model artifacts stay on the host and are mounted read-only into the API container.

### 1. Prepare data and models on the host

Run these commands from the project root (the directory containing this README) in an activated Python environment with `requirements.txt` installed. The feed downloads and pretrained-model downloads require network access the first time.

```bash
python ingestion/fetch_nvd.py
python ingestion/fetch_kev.py
python ingestion/fetch_epss.py
python ingestion/build_dataset.py
python models/build_labels.py
python models/baseline_models.py
python models/train_risk_model.py
python models/injection_classifier/prepare_data.py
python models/injection_classifier/train_classifier.py
python models/injection_classifier/evaluate_classifier.py
python models/embeddings/build_index.py
```

The risk label builder writes a primary `data/processed/labeled_sample.parquet` balanced for KEV catalog membership and a distinct supplementary `data/processed/weak_proxy_sample.parquet` based on EPSS thresholds. Only the KEV-membership cohort is used for primary metrics. A CVE absent from KEV is not thereby confirmed unexploited. The risk trainer creates matched XGBoost variants at `models/artifacts/risk_model.joblib` (with EPSS) and `models/artifacts/risk_model_no_epss.joblib` (without EPSS and its interaction), evaluated on the same holdout. The supplementary labels are exploratory and their EPSS baseline is circular by construction. Injection splits, injection artifacts, embeddings, and evaluation outputs are also saved under `data/processed/`, `models/`, and `results/`.

The primary target and model comparison are KEV catalog membership; a non-listed CVE must not be interpreted as confirmed unexploited. The trained models share the same 80/20 stratified holdout: one uses EPSS and one excludes EPSS and its CVSS interaction. `baseline_models.py` also writes an isolated supplementary set of metrics for the weak-proxy cohort when it exists; those figures are exploratory and are never combined into the primary results. The API healthcheck waits until the dataset and risk model can initialize the startup CVE cache; the frontend starts after the API is healthy.

### 2. Build and start the stack

From the same project root:

```bash
docker-compose up --build
```

Open the frontend at [http://localhost:5173](http://localhost:5173). The API is available at [http://localhost:8000](http://localhost:8000), with interactive docs at [http://localhost:8000/docs](http://localhost:8000/docs). Stop the stack with `Ctrl+C`, or run `docker-compose down` in another terminal.

The Compose mounts are read-only and keep local datasets and model weights out of the images. If an artifact is regenerated, restart the API container to load the updated files and rebuild its cached CVE scores.
