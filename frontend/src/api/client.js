// Centralized API client for the APEIRON backend.

const API_BASE = import.meta.env.VITE_API_BASE || '/api';
const WS_BASE = import.meta.env.VITE_WS_BASE || '/ws';

// Optional API key persisted in localStorage (matches backend X-API-Key).
export function getApiKey() {
  return localStorage.getItem('apeiron_api_key') || '';
}
export function setApiKey(key) {
  if (key) localStorage.setItem('apeiron_api_key', key);
  else localStorage.removeItem('apeiron_api_key');
}

function headers(extra = {}) {
  const h = { ...extra };
  const key = getApiKey();
  if (key) h['X-API-Key'] = key;
  return h;
}

async function handle(res) {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch (_e) { /* ignore */ }
    throw new Error(`${res.status}: ${detail}`);
  }
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

function qs(params = {}) {
  const usp = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') usp.append(k, v);
  });
  const s = usp.toString();
  return s ? `?${s}` : '';
}

export const api = {
  base: API_BASE,

  health: () => fetch(`${API_BASE}/health`).then(handle),
  stats: () => fetch(`${API_BASE}/stats`, { headers: headers() }).then(handle),

  uploadSample: (file) => {
    const fd = new FormData();
    fd.append('file', file);
    return fetch(`${API_BASE}/samples`, {
      method: 'POST',
      headers: headers(),
      body: fd,
    }).then(handle);
  },

  listSamples: (params) =>
    fetch(`${API_BASE}/samples${qs(params)}`, { headers: headers() }).then(handle),

  getSample: (id) =>
    fetch(`${API_BASE}/samples/${id}`, { headers: headers() }).then(handle),

  deleteSample: (id) =>
    fetch(`${API_BASE}/samples/${id}`, { method: 'DELETE', headers: headers() }).then(handle),

  getTrace: (id, params) =>
    fetch(`${API_BASE}/samples/${id}/trace${qs(params)}`, { headers: headers() }).then(handle),

  searchIocs: (params) =>
    fetch(`${API_BASE}/iocs${qs(params)}`, { headers: headers() }).then(handle),

  listRules: (params) =>
    fetch(`${API_BASE}/rules${qs(params)}`, { headers: headers() }).then(handle),

  reportUrl: (id, kind) => `${API_BASE}/samples/${id}/report.${kind}`,
  ruleDownloadUrl: (ruleId) => `${API_BASE}/rules/${ruleId}/download`,
  dumpDownloadUrl: (sampleId, dumpId) => `${API_BASE}/samples/${sampleId}/dumps/${dumpId}`,
};

export function traceSocketUrl(sampleId) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}${WS_BASE}/trace/${sampleId}`;
}

export function eventsSocketUrl() {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}${WS_BASE}/events`;
}
