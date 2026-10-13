"""FastAPI endpoints for structured risk assessment and cached CVE browsing."""

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

from api.risk_engine import RiskEngine
from api.repo_scanner import scan_repository
from models.embeddings.query import find_similar_cves

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = PROJECT_ROOT / "data/processed/vuln_dataset.parquet"
RESULTS_DIR = PROJECT_ROOT / "results"
RISK_EVALUATION_PATH = RESULTS_DIR / "risk_model_evaluation.json"
INJECTION_EVALUATION_PATH = RESULTS_DIR / "injection_classifier_evaluation.json"


def _api_value(value):
    """Convert pandas/numpy scalars and missing values into JSON-safe values."""
    if value is None or pd.isna(value):
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, np.generic):
        return value.item()
    return value


class CVEStructured(BaseModel):
    """Known structured CVE attributes used by the risk model."""

    model_config = ConfigDict(extra="allow")

    cve_id: str | None = None
    cvss_v3_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    published_date: str | None = None
    cwe_id: str | None = None
    description: str | None = None


class AssessRequest(BaseModel):
    cve_data: CVEStructured
    free_text_fields: dict[str, str] = Field(default_factory=dict)


class SimilarCVE(BaseModel):
    cve_id: str
    similarity_score: float
    description: str


class AssessResponse(BaseModel):
    risk_probability: float
    risk_rating: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    security_flag: str
    similar_cves: list[SimilarCVE]
    model_version: str
    explanation: str
    requires_human_review: bool


class RepoScanRequest(BaseModel):
    repo_url: str = Field(min_length=1)


class RepoScanResponse(BaseModel):
    repo: str
    dependencies_scanned: int
    vulnerabilities_found: int
    findings: list[dict[str, Any]]
    error: str | None = None


class CVEListItem(BaseModel):
    cve_id: str
    risk_probability: float
    risk_rating: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    cvss_v3_score: float | None = None
    epss_score: float | None = None
    published_date: Any = None
    cwe_id: str | None = None
    description: str | None = None


class CVEsPage(BaseModel):
    total: int
    offset: int
    limit: int
    items: list[CVEListItem]


class CVEDetail(CVEListItem):
    cvss_vector: str | None = None
    similar_cves: list[SimilarCVE]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    cve_cache_ready: bool


class EvaluationResponse(BaseModel):
    risk_model: dict[str, Any] | None = None
    injection_classifier: dict[str, Any] | None = None


def _build_cve_cache(engine: RiskEngine) -> list[dict[str, Any]]:
    """Load the parquet source and score rows in bounded, vectorized batches."""
    if not DATASET_PATH.is_file():
        raise FileNotFoundError(f"CVE dataset not found: {DATASET_PATH}")
    frame = pd.read_parquet(DATASET_PATH)
    if "cve_id" not in frame or "description" not in frame:
        raise ValueError("CVE dataset must contain cve_id and description columns")
    model = engine._load_risk_model()
    if frame.empty:
        return []
    version = engine._model_version(model)
    cache = []
    # Avoid constructing hundreds of thousands of one-row DataFrames. Use the
    # same neutral text-length feature and allowlisted structured fields as
    # RiskEngine.assess, but vectorize preparation within bounded chunks.
    include_epss = getattr(model, "vulnintel_include_epss", True)
    neutral = engine._structured_features({}, model)["description_length"].iloc[0]
    for start in range(0, len(frame), 10000):
        chunk = frame.iloc[start:start + 10000]
        features = pd.DataFrame(index=chunk.index)
        features["cvss_v3_score"] = pd.to_numeric(chunk.get("cvss_v3_score"), errors="coerce")
        if include_epss:
            features["epss_score"] = pd.to_numeric(chunk.get("epss_score"), errors="coerce")
        published = pd.to_datetime(chunk.get("published_date"), errors="coerce", utc=True)
        features["days_since_published"] = (
            (pd.Timestamp.now(tz="UTC") - published).dt.total_seconds() / 86400
        ).clip(lower=0)
        features["description_length"] = neutral
        if include_epss:
            features["cvss_epss_interaction"] = features["cvss_v3_score"] * features["epss_score"]
        features["cwe_id"] = chunk.get("cwe_id", pd.Series("Unknown", index=chunk.index)).fillna("Unknown").astype(str)
        features = features[engine._structured_features({}, model).columns]
        probabilities = np.asarray(model.predict_proba(features))[:, 1]
        for record, probability in zip(chunk.to_dict(orient="records"), probabilities):
            probability = min(1.0, max(0.0, float(probability)))
            cache.append({
                "cve_id": str(record["cve_id"]),
                "risk_probability": probability,
                "risk_rating": engine._rating(probability),
                "cvss_v3_score": _api_value(record.get("cvss_v3_score")),
                "cvss_vector": record.get("cvss_vector"),
                "epss_score": _api_value(record.get("epss_score")),
                "published_date": _api_value(record.get("published_date")),
                "cwe_id": _api_value(record.get("cwe_id")),
                "description": _api_value(record.get("description")),
                "model_version": version,
            })
    return cache


@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.engine = RiskEngine()
    application.state.cve_cache = []
    application.state.cache_error = None
    try:
        application.state.cve_cache = _build_cve_cache(application.state.engine)
    except Exception as exc:
        # Keep health and assessment endpoints available when optional model/data
        # artifacts have not yet been generated; cache-backed routes return 503.
        application.state.cache_error = str(exc)
        logger.warning("CVE risk cache initialization failed: %s", exc)
    yield


app = FastAPI(title="VulnDetect Risk API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _cache_or_503() -> list[dict[str, Any]]:
    error = getattr(app.state, "cache_error", None)
    if error:
        raise HTTPException(status_code=503, detail=f"CVE risk cache unavailable: {error}")
    return getattr(app.state, "cve_cache", [])


@app.get("/health", response_model=HealthResponse)
def health():
    return {"status": "ok", "cve_cache_ready": getattr(app.state, "cache_error", None) is None}


@app.post("/assess", response_model=AssessResponse)
def assess(request: AssessRequest):
    engine = getattr(app.state, "engine", None) or RiskEngine()
    try:
        return engine.assess(
            request.cve_data.model_dump(exclude_unset=True),
            request.free_text_fields,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/scan-repo", response_model=RepoScanResponse)
def scan_repo(request: RepoScanRequest):
    """Scan repository manifests and score OSV matches with the shared engine."""
    try:
        return scan_repository(request.repo_url)
    except (FileNotFoundError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"Repository scan failed: {exc}") from exc


@app.get("/cves", response_model=CVEsPage)
def list_cves(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    sort_by: Literal["cve_id", "risk_probability", "risk_rating", "cvss_v3_score", "epss_score"] = "risk_probability",
    sort_order: Literal["asc", "desc"] = "desc",
):
    cache = _cache_or_503()
    if sort_by in {"risk_probability", "cvss_v3_score", "epss_score"}:
        def key(record):
            value = record.get(sort_by)
            try:
                return (value is None, float(value) if value is not None else 0.0)
            except (TypeError, ValueError):
                return (True, 0.0)
    else:
        key = lambda record: str(record.get(sort_by) or "").casefold()
    sorted_cache = sorted(cache, key=key, reverse=sort_order == "desc")
    items = sorted_cache[offset: offset + limit]
    return {"total": len(cache), "offset": offset, "limit": limit, "items": items}


@app.get("/cves/{cve_id}", response_model=CVEDetail)
def get_cve(cve_id: str):
    cache = _cache_or_503()
    record = next((item for item in cache if item["cve_id"].casefold() == cve_id.casefold()), None)
    if record is None:
        raise HTTPException(status_code=404, detail=f"CVE not found: {cve_id}")
    similar = []
    if isinstance(record.get("description"), str) and record["description"].strip():
        try:
            similar = find_similar_cves(record["description"], top_k=5)
        except FileNotFoundError:
            similar = []
    return {**record, "similar_cves": similar}


def _read_evaluation(path: Path):
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not read evaluation report {path.name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail=f"Evaluation report {path.name} must contain a JSON object")
    return payload


@app.get("/evaluation", response_model=EvaluationResponse)
def get_evaluation():
    return {
        "risk_model": _read_evaluation(RISK_EVALUATION_PATH),
        "injection_classifier": _read_evaluation(INJECTION_EVALUATION_PATH),
    }
