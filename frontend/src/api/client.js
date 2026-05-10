/**
 * client.js — Basis HTTP-Client mit JWT-Auth
 */

const API_BASE = "/api/v1";

function getToken() {
  return localStorage.getItem("easm_token") || "";
}

export async function apiFetch(path, opts = {}) {
  const token = getToken();
  const res = await fetch(API_BASE + path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}
