import { useEffect, useMemo, useState } from 'react';
import './styles.css';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';
const PAGE_SIZE = 50;
type Rating = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
type SimilarCVE = { cve_id: string; similarity_score: number; description: string };
type CVE = {
  cve_id: string; risk_probability: number; risk_rating: Rating;
  cvss_v3_score?: number | null; epss_score?: number | null; published_date?: string | null;
  cwe_id?: string | null; description?: string | null; cvss_vector?: string | null;
  similar_cves?: SimilarCVE[];
};
type CVEPage = { total: number; offset: number; limit: number; items: CVE[] };
type Assessment = {
  risk_probability: number; risk_rating: Rating; security_flag: string;
  similar_cves: SimilarCVE[]; model_version: string; explanation: string;
  requires_human_review: boolean;
};
type Metrics = { precision?: number | null; recall?: number | null; f1?: number | null; roc_auc?: number | null; pr_auc?: number | null };
type RiskEvaluation = { target_interpretation?: string; model_metrics?: Metrics; models?: Record<string, { metrics?: Metrics }>; same_test_baselines?: Record<string, Metrics> };
type InjectionEvaluation = { trained_classifier?: Metrics; regex_baseline?: Metrics };
type Evaluation = { risk_model?: RiskEvaluation | null; injection_classifier?: InjectionEvaluation | null };
type MetricRow = { group: string; name: string; metrics: Metrics };

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail ?? `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

function useHashRoute() {
  const [route, setRoute] = useState(window.location.hash || '#/');
  useEffect(() => {
    const update = () => setRoute(window.location.hash || '#/');
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  return route;
}

function RatingBadge({ rating }: { rating: Rating }) {
  return <span className={`badge rating-${rating.toLowerCase()}`}>{rating}</span>;
}

function App() {
  const route = useHashRoute();
  const detailMatch = route.match(/^#\/cves\/(.+)$/);
  const view = route === '#/evaluation' ? 'evaluation' : detailMatch ? 'detail' : 'list';
  const cveId = detailMatch ? decodeURIComponent(detailMatch[1]) : '';
  return <div className="app-shell">
    <header className="topbar">
      <a className="brand" href="#/">VulnDetect</a>
      <nav aria-label="Main navigation">
        <a className={view !== 'evaluation' ? 'active' : ''} href="#/">CVE explorer</a>
        <a className={view === 'evaluation' ? 'active' : ''} href="#/evaluation">Evaluation</a>
      </nav>
      <span className="api-label"><i /> API · localhost:8000</span>
    </header>
    <main className="page-content">
      {view === 'list' && <CVEListView />}
      {view === 'detail' && <CVEDetailView cveId={cveId} />}
      {view === 'evaluation' && <EvaluationView />}
    </main>
    <footer>Recommendations only · Every assessment requires human review</footer>
  </div>;
}

type SortField = 'risk_probability' | 'cve_id' | 'cvss_v3_score' | 'epss_score';

function CVEListView() {
  const [page, setPage] = useState(0);
  const [sortBy, setSortBy] = useState<SortField>('risk_probability');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [result, setResult] = useState<CVEPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError('');
    api<CVEPage>(`/cves?offset=${page * PAGE_SIZE}&limit=${PAGE_SIZE}&sort_by=${sortBy}&sort_order=${sortOrder}`, { signal: controller.signal })
      .then(setResult)
      .catch((reason: Error) => { if (reason.name !== 'AbortError') setError(reason.message); })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, [page, sortBy, sortOrder]);
  const sort = (field: SortField) => {
    if (field === sortBy) setSortOrder((order) => order === 'asc' ? 'desc' : 'asc');
    else { setSortBy(field); setSortOrder(field === 'cve_id' ? 'asc' : 'desc'); }
    setPage(0);
  };
  const mark = (field: SortField) => field === sortBy ? (sortOrder === 'asc' ? ' ↑' : ' ↓') : '';
  const pages = Math.max(1, Math.ceil((result?.total ?? 0) / PAGE_SIZE));
  return <section>
    <div className="page-heading"><div><p className="eyebrow">VULNERABILITY INTELLIGENCE</p><h1>CVE explorer</h1>
      <p className="muted">Prioritize vulnerabilities with structured risk signals and review context.</p></div>
      <span className="count-pill">{result ? `${result.total.toLocaleString()} records` : 'Loading records'}</span></div>
    {error && <div className="notice error">{error}. Check that the API is running and the risk cache is ready.</div>}
    <div className="table-card">
      {loading && <div className="loading">Loading CVEs…</div>}
      {!loading && !error && result?.items.length === 0 && <div className="empty">No CVEs found in the dataset.</div>}
      {result && result.items.length > 0 && <>
        <div className="table-wrap"><table><thead><tr>
          <th><button className="sort-button" onClick={() => sort('cve_id')}>CVE{mark('cve_id')}</button></th>
          <th><button className="sort-button" onClick={() => sort('risk_probability')}>Risk{mark('risk_probability')}</button></th>
          <th><button className="sort-button" onClick={() => sort('cvss_v3_score')}>CVSS{mark('cvss_v3_score')}</button></th>
          <th><button className="sort-button" onClick={() => sort('epss_score')}>EPSS{mark('epss_score')}</button></th>
          <th>Published</th><th>Description</th>
        </tr></thead><tbody>{result.items.map((item) => <tr key={item.cve_id}>
          <td><a className="cve-link" href={`#/cves/${encodeURIComponent(item.cve_id)}`}>{item.cve_id}</a></td>
          <td><div className="risk-cell"><RatingBadge rating={item.risk_rating} /><span>{(item.risk_probability * 100).toFixed(0)}%</span></div></td>
          <td>{item.cvss_v3_score?.toFixed(1) ?? '—'}</td><td>{item.epss_score?.toFixed(3) ?? '—'}</td>
          <td>{item.published_date ? new Date(item.published_date).toLocaleDateString() : '—'}</td>
          <td className="description-cell">{item.description ?? 'No description available'}</td>
        </tr>)}</tbody></table></div>
        <div className="pagination"><span>Page {page + 1} of {pages}</span><div>
          <button disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous</button>
          <button disabled={page + 1 >= pages} onClick={() => setPage((value) => value + 1)}>Next</button>
        </div></div>
      </>}
    </div>
  </section>;
}

function CVEDetailView({ cveId }: { cveId: string }) {
  const [detail, setDetail] = useState<CVE | null>(null);
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [assessmentError, setAssessmentError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    setDetail(null); setAssessment(null); setError(''); setAssessmentError(''); setLoading(true);
    api<CVE>(`/cves/${encodeURIComponent(cveId)}`, { signal: controller.signal })
      .then(async (record) => {
        setDetail(record);
        try {
          const assessed = await api<Assessment>('/assess', {
            method: 'POST', signal: controller.signal,
            body: JSON.stringify({
              cve_data: {
                cve_id: record.cve_id, cvss_v3_score: record.cvss_v3_score,
                cvss_vector: record.cvss_vector, epss_score: record.epss_score,
                published_date: record.published_date, cwe_id: record.cwe_id,
                description: record.description,
              },
              free_text_fields: record.description ? { cve_description: record.description } : {},
            }),
          });
          setAssessment(assessed);
        } catch (reason) { if ((reason as Error).name !== 'AbortError') setAssessmentError((reason as Error).message); }
      })
      .catch((reason: Error) => { if (reason.name !== 'AbortError') setError(reason.message); })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, [cveId]);
  if (loading) return <div className="loading">Loading {cveId}…</div>;
  if (error) return <div><a className="back-link" href="#/">← Back to CVEs</a><div className="notice error">{error}</div></div>;
  if (!detail) return null;
  const similar = assessment?.similar_cves ?? detail.similar_cves ?? [];
  return <section>
    <a className="back-link" href="#/">← Back to CVEs</a>
    <div className="page-heading detail-heading"><div><p className="eyebrow">VULNERABILITY DETAIL</p><h1>{detail.cve_id}</h1>
      <p className="muted">{detail.description ?? 'No description available'}</p></div>
      <RatingBadge rating={assessment?.risk_rating ?? detail.risk_rating} /></div>
    {assessmentError && <div className="notice warning">Showing cached dataset risk. Full assessment unavailable: {assessmentError}</div>}
    <div className="detail-grid">
      <article className="panel"><h2>Risk assessment</h2>
        <div className="probability">{((assessment?.risk_probability ?? detail.risk_probability) * 100).toFixed(1)}<small>%</small></div>
        <div className="detail-pairs">
          <span>CVSS v3</span><strong>{detail.cvss_v3_score?.toFixed(1) ?? '—'}</strong>
          <span>EPSS</span><strong>{detail.epss_score?.toFixed(3) ?? '—'}</strong>
          <span>CWE</span><strong>{detail.cwe_id ?? '—'}</strong>
          <span>Published</span><strong>{detail.published_date ? new Date(detail.published_date).toLocaleDateString() : '—'}</strong>
          <span>Model version</span><strong>{assessment?.model_version ?? 'Cached score'}</strong>
          <span>Human review</span><strong>{assessment?.requires_human_review ? 'Required' : '—'}</strong>
        </div>
      </article>
      <article className="panel"><h2>Security screening</h2>
        {assessment?.security_flag === 'INJECTION_DETECTED'
          ? <div className="notice error">Prompt injection detected in a text field.</div>
          : <div className="notice success">{assessment ? 'No prompt injection detected.' : 'Awaiting full assessment.'}</div>}
        <h3>Model explanation</h3><p className="explanation">{assessment?.explanation ?? 'An explanation is available after the trained risk model is loaded.'}</p>
      </article>
    </div>
    <article className="panel similar-panel"><div className="panel-heading"><div><h2>Similar CVEs</h2>
      <p className="muted">Retrieved by description similarity for additional review context.</p></div></div>
      {similar.length === 0 ? <p className="empty-inline">No similar CVEs available.</p> : <ul className="similar-list">
        {similar.map((item) => <li key={item.cve_id}><a href={`#/cves/${encodeURIComponent(item.cve_id)}`}>{item.cve_id}</a>
          <span className="similar-score">Similarity {(item.similarity_score * 100).toFixed(1)}%</span><p>{item.description}</p></li>)}
      </ul>}
    </article>
  </section>;
}

const metricLabels: Record<keyof Metrics, string> = { precision: 'Precision', recall: 'Recall', f1: 'F1', roc_auc: 'ROC-AUC', pr_auc: 'PR-AUC' };
const metricKeys: (keyof Metrics)[] = ['precision', 'recall', 'f1', 'roc_auc', 'pr_auc'];

function EvaluationView() {
  const [evaluation, setEvaluation] = useState<Evaluation | null>(null);
  const [metric, setMetric] = useState<keyof Metrics>('f1');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  useEffect(() => {
    api<Evaluation>('/evaluation').then(setEvaluation).catch((reason: Error) => setError(reason.message)).finally(() => setLoading(false));
  }, []);
  const rows = useMemo<MetricRow[]>(() => {
    if (!evaluation) return [];
    const output: MetricRow[] = [];
    const risk = evaluation.risk_model;
    if (risk?.models?.with_epss?.metrics) output.push({ group: 'KEV membership', name: 'XGBoost with EPSS', metrics: risk.models.with_epss.metrics });
    else if (risk?.model_metrics) output.push({ group: 'KEV membership', name: 'XGBoost with EPSS', metrics: risk.model_metrics });
    if (risk?.models?.without_epss?.metrics) output.push({ group: 'KEV membership', name: 'XGBoost without EPSS', metrics: risk.models.without_epss.metrics });
    Object.entries(risk?.same_test_baselines ?? {}).forEach(([name, metrics]) => output.push({ group: 'KEV membership', name: readableModelName(name), metrics }));
    const injection = evaluation.injection_classifier;
    if (injection?.trained_classifier) output.push({ group: 'Prompt injection', name: 'Trained DistilBERT', metrics: injection.trained_classifier });
    if (injection?.regex_baseline) output.push({ group: 'Prompt injection', name: 'Regex baseline', metrics: injection.regex_baseline });
    return output;
  }, [evaluation]);
  if (loading) return <div className="loading">Loading evaluation reports…</div>;
  return <section>
    <div className="page-heading"><div><p className="eyebrow">MODEL QUALITY</p><h1>Evaluation dashboard</h1>
      <p className="muted">Compare risk models for KEV catalog membership, including the EPSS ablation, and the injection detector baselines.</p></div></div>
    {error && <div className="notice error">{error}</div>}
    {rows.length === 0 && !error && <div className="notice warning">No evaluation reports have been generated yet. Run the model evaluation scripts first.</div>}
    {rows.length > 0 && <>
      <div className="notice info">The primary risk target is KEV catalog membership. A CVE absent from KEV is not confirmed unexploited. With-EPSS and without-EPSS models use the same held-out CVEs. Supplementary EPSS-threshold proxy metrics are not part of this primary comparison.</div>
      <article className="panel metric-table-panel"><h2>Metric comparison</h2><div className="table-wrap"><table className="metrics-table">
        <thead><tr><th>Task</th><th>Model</th>{metricKeys.map((key) => <th key={key}>{metricLabels[key]}</th>)}</tr></thead>
        <tbody>{rows.map((row) => <tr key={`${row.group}-${row.name}`}><td>{row.group}</td><td>{row.name}</td>
          {metricKeys.map((key) => <td key={key}>{formatMetric(row.metrics[key])}</td>)}</tr>)}</tbody>
      </table></div></article>
      <article className="panel chart-panel"><div className="panel-heading"><div><h2>Baseline comparison</h2><p className="muted">Higher is better. Missing metrics are not plotted.</p></div>
        <label className="metric-select">Metric<select value={metric} onChange={(event) => setMetric(event.target.value as keyof Metrics)}>
          {metricKeys.map((key) => <option key={key} value={key}>{metricLabels[key]}</option>)}
        </select></label></div>
        <div className="bar-chart">{rows.map((row) => {
          const value = row.metrics[metric];
          return <div className="bar-row" key={`${row.group}-${row.name}-${metric}`}>
            <div className="bar-label"><span>{row.group}</span><strong>{row.name}</strong></div>
            <div className="bar-track"><div className={`bar-fill ${row.name.toLowerCase().includes('trained') ? 'trained' : ''}`} style={{ width: `${Math.max(0, Math.min(100, (value ?? 0) * 100))}%` }} /></div>
            <b>{formatMetric(value)}</b>
          </div>;
        })}</div>
      </article>
    </>}
  </section>;
}

function readableModelName(name: string) {
  return name.replace(/_test$/, '').replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}
function formatMetric(value?: number | null) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(3) : '—';
}

export default App;
