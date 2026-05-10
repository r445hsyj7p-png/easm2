/**
 * search.js — Search API wrapper
 */
import { apiFetch } from "./client.js";

/**
 * Führt eine globale Suche aus.
 *
 * @param {string}  query  - Query-String z.B. "severity:critical has:kev"
 * @param {object}  opts   - { scope, limit, offset, sort, order }
 * @returns {Promise<SearchResult>}
 */
export async function search(query, opts = {}) {
  const params = new URLSearchParams({
    q:      query,
    scope:  opts.scope  ?? "all",
    limit:  opts.limit  ?? 50,
    offset: opts.offset ?? 0,
    sort:   opts.sort   ?? "relevance",
    order:  opts.order  ?? "desc",
  });
  return apiFetch(`/search?${params}`);
}

/**
 * Lädt die Query-Syntax-Referenz.
 * Wird einmalig gecached.
 */
let _syntaxCache = null;
export async function fetchSyntax() {
  if (_syntaxCache) return _syntaxCache;
  _syntaxCache = await apiFetch("/search/syntax");
  return _syntaxCache;
}
