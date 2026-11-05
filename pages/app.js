// The registry's explorer. It reads the same signed index a Stoker instance reads, checks it in the browser, and
// searches it in memory.
//
// Trust runs one way: the registry key in this page's <meta> (from registry.yaml) verifies timestamp.json; that file
// pins plugins.json.zst by size and SHA-256; the index lists each publisher's key and namespaces, which verify each
// version's signature. Nothing the index says about its own key is trusted.
//
// Everything taken from the index reaches the page as text (textContent and text nodes), never as HTML, and only
// https links are made into anchors.

import { decompress } from './vendor/fzstd.mjs';

const PAGE = 60;
const KINDS = {
  hook: 'Hook plugin',
  mod: 'Mod',
  integration: 'Integration',
  server: 'Server extension',
  unpacker: 'Unpacker',
};

const meta = name => document.querySelector(`meta[name="${name}"]`)?.content ?? '';
const REGISTRY = {
  name: meta('stoker-registry-name'),
  title: meta('stoker-registry-title'),
  url: meta('stoker-registry-url'),
  key: meta('stoker-registry-key'),
};

const state = {
  index: null,
  timestamp: null,
  trust: null,
  entries: [],
  byKey: new Map(),
  query: '',
  filters: { kind: new Set(), platform: new Set(), host: new Set() },
  limit: PAGE,
  versionChecks: new Map(),
};

// ---- Small helpers -------------------------------------------------------------------------------------------------

function h(tag, attrs, ...children) {
  const element = document.createElement(tag);
  if (attrs) {
    for (const [name, value] of Object.entries(attrs)) {
      if (value == null || value === false) continue;
      if (name === 'class') element.className = value;
      else if (name.startsWith('on')) element.addEventListener(name.slice(2), value);
      else element.setAttribute(name, value === true ? '' : String(value));
    }
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    element.append(child instanceof Node ? child : String(child));
  }
  return element;
}

function safeUrl(value) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

function link(href, text, attrs = {}) {
  const url = safeUrl(href);
  return url ? h('a', { href: url, rel: 'noopener noreferrer', ...attrs }, text) : h('span', null, text);
}

const base64 = text => Uint8Array.from(atob(text.trim()), c => c.charCodeAt(0));
const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
const sha256 = async bytes => hex(await crypto.subtle.digest('SHA-256', bytes));
const keyId = async spkiBase64 => (await sha256(base64(spkiBase64))).slice(0, 16);

function size(bytes) {
  if (!Number.isFinite(bytes)) return '';
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${unit === 0 ? value : value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

function date(iso) {
  const time = Date.parse(iso);
  return Number.isNaN(time) ? String(iso ?? '') : new Date(time).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function copyButton(value, label = 'Copy') {
  const button = h('button', { type: 'button', class: 'copy', title: `Copy ${value}` }, label);
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = 'Copied';
    } catch {
      button.textContent = 'Copy failed';
    }
    setTimeout(() => { button.textContent = label; }, 1500);
  });
  return button;
}

function hash(value) {
  return h('span', { class: 'hash' }, h('code', { title: value }, `${value.slice(0, 12)}…`), copyButton(value));
}

const ordinal = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// ---- Loading and checking the index --------------------------------------------------------------------------------

async function fetchBytes(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function importKey(spkiBase64) {
  return crypto.subtle.importKey('spki', base64(spkiBase64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

const verify = (key, signatureBase64, data) =>
  crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, base64(signatureBase64), data);

async function load() {
  const trust = { problems: [] };
  const [timestampBytes, signatureBytes, compressed] = await Promise.all([
    fetchBytes('index/v1/timestamp.json'),
    fetchBytes('index/v1/timestamp.json.sig').catch(() => null),
    fetchBytes('index/v1/plugins.json.zst'),
  ]);

  trust.keyId = await keyId(REGISTRY.key);
  const registryKey = await importKey(REGISTRY.key);
  trust.signed = signatureBytes != null
    && await verify(registryKey, new TextDecoder().decode(signatureBytes), timestampBytes).catch(() => false);
  if (!trust.signed) trust.problems.push(signatureBytes ? 'timestamp.json does not verify against the registry key' : 'timestamp.json has no signature');

  const timestamp = JSON.parse(new TextDecoder().decode(timestampBytes));
  trust.expired = Date.parse(timestamp.expires) < Date.now();
  if (trust.expired) trust.problems.push(`the index expired on ${date(timestamp.expires)}`);

  trust.pinned = compressed.length === timestamp.index?.size && await sha256(compressed) === timestamp.index?.sha256;
  if (!trust.pinned) trust.problems.push('plugins.json.zst is not the file timestamp.json pins');

  const index = JSON.parse(new TextDecoder().decode(decompress(compressed)));
  if (index.registry !== timestamp.registry || index.serial !== timestamp.serial || index.registry !== REGISTRY.name)
    trust.problems.push('the index and its timestamp name different registries or serials');

  trust.ok = trust.problems.length === 0;
  state.trust = trust;
  state.timestamp = timestamp;
  state.index = index;
  state.publishers = new Map((index.publishers ?? []).map(p => [p.id, p]));
  state.entries = (index.plugins ?? []).map(prepare);
  state.entries.sort((a, b) => ordinal(a.nameLc, b.nameLc) || ordinal(a.key, b.key));
  state.byKey = new Map(state.entries.map(e => [e.key, e]));
}

// Precomputes everything a search compares, once, so a keystroke is string tests over arrays and nothing else.
function prepare({ plugin, versions = [] }) {
  const live = versions.filter(v => !v.retired);
  const latest = (live.length ? live : versions).at(-1) ?? null;
  const name = plugin.name || plugin.key;
  const platforms = [...new Set((latest?.files ?? []).map(f => `${f.os} ${f.architecture}`))].sort();
  const hosts = [...new Set(latest?.hosts ?? [])].sort();
  const nameLc = name.toLowerCase();
  const keyLc = plugin.key.toLowerCase();
  return {
    plugin,
    versions,
    latest,
    key: plugin.key,
    name,
    kind: plugin.kind,
    platforms,
    hosts,
    retired: live.length === 0 && versions.length > 0,
    nameLc,
    nameWords: nameLc.split(/[^\p{L}\p{N}]+/u).filter(Boolean),
    keyLc,
    keyParts: keyLc.split(/[.\-_]+/).filter(Boolean),
    textLc: [plugin.description, plugin.notes, ...(plugin.authors ?? []), plugin.license, ...hosts, ...platforms,
      ...versions.map(v => v.version)].filter(Boolean).join(' ').toLowerCase(),
  };
}

// ---- Search ----------------------------------------------------------------------------------------------------------

const terms = query => query.toLowerCase().split(/\s+/).filter(Boolean);

// Every term must match somewhere; a word start in the name counts most, then the name, the key, and the rest.
function score(entry, queryTerms) {
  let total = 0;
  for (const term of queryTerms) {
    let best = 0;
    if (entry.nameLc === term || entry.keyLc === term) best = 20;
    else if (entry.nameWords.some(w => w.startsWith(term))) best = 10;
    else if (entry.keyParts.some(p => p.startsWith(term))) best = 8;
    else if (entry.nameLc.includes(term)) best = 6;
    else if (entry.keyLc.includes(term)) best = 5;
    else if (entry.textLc.includes(term)) best = 2;
    if (best === 0) return 0;
    total += best;
  }
  return total;
}

const facetValues = {
  kind: entry => [entry.kind],
  platform: entry => entry.platforms,
  host: entry => entry.hosts,
};

function passes(entry, except) {
  for (const [facet, selected] of Object.entries(state.filters)) {
    if (facet === except || selected.size === 0) continue;
    if (!facetValues[facet](entry).some(v => selected.has(v))) return false;
  }
  return true;
}

function search() {
  const queryTerms = terms(state.query);
  const matched = [];
  for (const entry of state.entries) {
    const s = queryTerms.length ? score(entry, queryTerms) : 1;
    if (s > 0) matched.push({ entry, score: s });
  }
  // Facet counts are over what the query matches and the other facets allow, so every count is what a click yields.
  const counts = {};
  for (const facet of Object.keys(state.filters)) {
    const tally = new Map();
    for (const { entry } of matched) {
      if (!passes(entry, facet)) continue;
      for (const value of facetValues[facet](entry)) tally.set(value, (tally.get(value) ?? 0) + 1);
    }
    for (const value of state.filters[facet]) if (!tally.has(value)) tally.set(value, 0);
    counts[facet] = tally;
  }
  const results = matched.filter(m => passes(m.entry));
  if (queryTerms.length) results.sort((a, b) => b.score - a.score || ordinal(a.entry.nameLc, b.entry.nameLc));
  return { results: results.map(r => r.entry), counts, queryTerms };
}

// The text with every occurrence of a term marked, as nodes.
function highlight(text, queryTerms) {
  const value = String(text ?? '');
  if (!queryTerms.length || !value) return value;
  const lower = value.toLowerCase();
  const ranges = [];
  for (const term of queryTerms) {
    for (let at = lower.indexOf(term); at !== -1; at = lower.indexOf(term, at + term.length)) ranges.push([at, at + term.length]);
  }
  if (!ranges.length) return value;
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [ranges[0]];
  for (const [start, end] of ranges.slice(1)) {
    const last = merged.at(-1);
    if (start <= last[1]) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }
  const nodes = [];
  let at = 0;
  for (const [start, end] of merged) {
    if (start > at) nodes.push(value.slice(at, start));
    nodes.push(h('mark', null, value.slice(start, end)));
    at = end;
  }
  if (at < value.length) nodes.push(value.slice(at));
  return nodes;
}

// ---- Routing -------------------------------------------------------------------------------------------------------

function route() {
  const hash = location.hash.replace(/^#/, '') || '/';
  const [path, queryString = ''] = hash.split('?');
  return { path, params: new URLSearchParams(queryString) };
}

function exploreHash() {
  const params = new URLSearchParams();
  if (state.query) params.set('q', state.query);
  for (const [facet, selected] of Object.entries(state.filters)) for (const value of selected) params.append(facet, value);
  const text = params.toString();
  return `#/${text ? `?${text}` : ''}`;
}

function render() {
  const { path, params } = route();
  const main = document.getElementById('main');
  if (path.startsWith('/plugins/')) {
    const key = decodeURIComponent(path.slice('/plugins/'.length));
    main.replaceChildren(renderPlugin(key));
    document.title = `${state.byKey.get(key)?.name ?? key} · ${REGISTRY.title} plugins`;
    window.scrollTo(0, 0);
  } else if (path === '/registry') {
    main.replaceChildren(renderRegistry());
    document.title = `Use this registry · ${REGISTRY.title} plugins`;
    window.scrollTo(0, 0);
  } else {
    state.query = params.get('q') ?? '';
    for (const facet of Object.keys(state.filters)) state.filters[facet] = new Set(params.getAll(facet));
    state.limit = PAGE;
    main.replaceChildren(renderExplore());
    document.title = `${REGISTRY.title} plugins`;
  }
}

// ---- Explore -------------------------------------------------------------------------------------------------------

let resultsHost = null;
let facetsHost = null;
let summaryHost = null;
let input = null;

function renderExplore() {
  input = h('input', {
    type: 'search',
    id: 'q',
    placeholder: `Search ${state.entries.length} plugin${state.entries.length === 1 ? '' : 's'} by name, key, game, author, host…`,
    autocomplete: 'off',
    spellcheck: 'false',
    'aria-label': 'Search plugins',
    value: state.query,
  });
  input.value = state.query;
  input.addEventListener('input', () => {
    state.query = input.value;
    state.limit = PAGE;
    scheduleUpdate();
  });
  input.addEventListener('keydown', event => {
    if (event.key === 'Escape' && input.value) { input.value = ''; state.query = ''; scheduleUpdate(); event.preventDefault(); }
    if (event.key === 'Enter') {
      const first = resultsHost?.querySelector('a.card');
      if (first) first.click();
    }
  });

  summaryHost = h('p', { class: 'summary', 'aria-live': 'polite' });
  facetsHost = h('div', { class: 'facets' });
  resultsHost = h('div', { class: 'results' });

  const view = h('section', { class: 'explore' },
    h('div', { class: 'hero' },
      h('h1', null, 'Plugins for Stoker'),
      h('p', null, 'Hook plugins that run inside games, mods, integrations and server extensions. Every version is signed by its publisher, and its source is linked.'),
      h('div', { class: 'search' },
        searchIcon(),
        input,
        h('kbd', { title: 'Press / to search' }, '/'))),
    h('div', { class: 'layout' },
      h('aside', null, facetsHost),
      h('div', null, summaryHost, resultsHost)));
  update();
  queueMicrotask(() => { if (!matchMedia('(pointer: coarse)').matches) input.focus({ preventScroll: true }); });
  return view;
}

function searchIcon() {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('class', 'search-icon');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const circle = document.createElementNS(ns, 'circle');
  circle.setAttribute('cx', '11'); circle.setAttribute('cy', '11'); circle.setAttribute('r', '7');
  const handle = document.createElementNS(ns, 'path');
  handle.setAttribute('d', 'm20 20-3.5-3.5');
  svg.append(circle, handle);
  return svg;
}

let pending = false;
function scheduleUpdate() {
  if (pending) return;
  pending = true;
  requestAnimationFrame(() => { pending = false; update(); });
}

function update() {
  const { results, counts, queryTerms } = search();
  history.replaceState(null, '', exploreHash());

  facetsHost.replaceChildren(
    facetGroup('Kind', 'kind', counts.kind, value => KINDS[value] ?? value),
    facetGroup('Platform', 'platform', counts.platform, value => value.replace(' ', ' · ')),
    facetGroup('Runs under', 'host', counts.host, value => value));

  const total = state.entries.length;
  summaryHost.textContent = results.length === total
    ? `${total} plugin${total === 1 ? '' : 's'}`
    : `${results.length} of ${total} plugin${total === 1 ? '' : 's'}`;

  if (!results.length) {
    resultsHost.replaceChildren(h('div', { class: 'empty' },
      h('p', null, 'Nothing matches.'),
      h('button', { type: 'button', class: 'ghost', onclick: clearAll }, 'Clear the search and filters')));
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const entry of results.slice(0, state.limit)) fragment.append(card(entry, queryTerms));
  if (results.length > state.limit) {
    fragment.append(h('button', {
      type: 'button',
      class: 'more',
      onclick: () => { state.limit += PAGE * 2; update(); },
    }, `Show more (${results.length - state.limit} left)`));
  }
  resultsHost.replaceChildren(fragment);
}

function clearAll() {
  state.query = '';
  for (const facet of Object.keys(state.filters)) state.filters[facet].clear();
  if (input) input.value = '';
  update();
}

function facetGroup(title, facet, tally, label) {
  if (!tally || tally.size === 0) return null;
  const values = [...tally.entries()].sort((a, b) => b[1] - a[1] || ordinal(a[0], b[0]));
  return h('fieldset', { class: 'facet' },
    h('legend', null, title),
    values.map(([value, count]) => {
      const on = state.filters[facet].has(value);
      return h('button', {
        type: 'button',
        class: 'chip',
        'aria-pressed': on ? 'true' : 'false',
        disabled: !on && count === 0,
        onclick: () => {
          if (on) state.filters[facet].delete(value); else state.filters[facet].add(value);
          state.limit = PAGE;
          update();
        },
      }, h('span', null, label(value)), h('span', { class: 'count' }, count));
    }));
}

function card(entry, queryTerms) {
  const { plugin, latest } = entry;
  return h('a', { class: 'card', href: `#/plugins/${encodeURIComponent(entry.key)}` },
    h('div', { class: 'card-head' },
      h('h2', null, highlight(entry.name, queryTerms)),
      h('span', { class: `kind kind-${entry.kind}` }, KINDS[entry.kind] ?? entry.kind)),
    h('p', { class: 'key' }, highlight(entry.key, queryTerms)),
    plugin.description ? h('p', { class: 'description' }, highlight(plugin.description, queryTerms)) : null,
    h('div', { class: 'card-meta' },
      latest ? h('span', { class: 'version' }, `v${latest.version}`) : null,
      entry.retired ? h('span', { class: 'retired' }, 'retired') : null,
      entry.platforms.map(p => h('span', { class: 'tag' }, p.replace(' ', ' · '))),
      entry.hosts.map(x => h('span', { class: 'tag' }, x)),
      plugin.license ? h('span', { class: 'muted' }, plugin.license) : null));
}

// ---- One plugin ------------------------------------------------------------------------------------------------------

function renderPlugin(key) {
  const entry = state.byKey.get(key);
  const back = h('a', { class: 'back', href: exploreHash() }, '← All plugins');
  if (!entry) return h('section', null, back, h('h1', null, 'Not in this registry'), h('p', null, key));

  const { plugin } = entry;
  const publisher = publisherFor(entry.key);
  const versions = [...entry.versions].reverse();

  return h('section', { class: 'plugin' },
    back,
    h('header', { class: 'plugin-head' },
      h('div', null,
        h('span', { class: `kind kind-${entry.kind}` }, KINDS[entry.kind] ?? entry.kind),
        h('h1', null, entry.name),
        h('p', { class: 'key' }, h('code', null, entry.key), copyButton(entry.key))),
      h('dl', { class: 'facts' },
        fact('Latest', entry.latest ? `v${entry.latest.version}` : '—'),
        fact('Licence', plugin.license ?? '—'),
        fact('Authors', (plugin.authors ?? []).join(', ') || '—'),
        fact('Publisher', publisher ? `${publisher.name ?? publisher.id}` : 'none — no publisher may sign this key'))),
    plugin.description ? h('p', { class: 'lead' }, plugin.description) : null,
    h('p', { class: 'links' },
      plugin.homepage ? link(plugin.homepage, 'Homepage') : null,
      plugin.sourceCode ? link(plugin.sourceCode, 'Source code') : null,
      h('a', { href: `index/v1/plugins/${encodeURIComponent(entry.key)}.json` }, 'Index entry (JSON)')),
    plugin.notes ? h('div', { class: 'notes' }, plugin.notes) : null,
    h('h2', null, versions.length === 1 ? 'Version' : `Versions (${versions.length})`),
    versions.map(v => renderVersion(entry, v, publisher)));
}

function fact(name, value) {
  return [h('dt', null, name), h('dd', null, value)];
}

// The publisher whose namespace covers a key: the longest prefix wins, as it does on an instance.
function publisherFor(key) {
  let best = null;
  let length = -1;
  for (const publisher of state.publishers.values()) {
    for (const prefix of publisher.namespaces ?? []) {
      if (key.startsWith(prefix) && prefix.length > length) { best = publisher; length = prefix.length; }
    }
  }
  return best;
}

function statement(version) {
  const files = [...(version.files ?? [])]
    .sort((a, b) => ordinal(`${a.os}\t${a.architecture}\t${a.fileName}`, `${b.os}\t${b.architecture}\t${b.fileName}`));
  let text = `stoker-plugin-v1\n${version.key}\n${version.version}\n${version.kind}\n`;
  for (const f of files) text += `${f.os}\t${f.architecture}\t${f.fileName}\t${f.size}\t${f.sha256.toLowerCase()}\t${f.blake3.toLowerCase()}\n`;
  return new TextEncoder().encode(text);
}

async function checkVersion(entry, version) {
  const id = `${version.key}@${version.version}`;
  if (state.versionChecks.has(id)) return state.versionChecks.get(id);
  const check = (async () => {
    const signature = version.signature;
    if (!signature) return { ok: false, text: 'Not signed' };
    const publisher = state.publishers.get(signature.publisher);
    if (!publisher) return { ok: false, text: `Signed by “${signature.publisher}”, whom this registry does not list` };
    if (!(publisher.namespaces ?? []).some(prefix => version.key.startsWith(prefix)))
      return { ok: false, text: `${publisher.name ?? publisher.id} may not publish under this key` };
    if (signature.algorithm !== 'ecdsa-p256-sha256') return { ok: false, text: `Unknown signature algorithm ${signature.algorithm}` };
    try {
      const key = await importKey(publisher.publicKey);
      const ok = await verify(key, signature.value, statement(version));
      const id8 = await keyId(publisher.publicKey);
      return ok
        ? { ok: true, text: `Signed by ${publisher.name ?? publisher.id}`, detail: `key ${id8}` }
        : { ok: false, text: `The signature does not verify against ${publisher.name ?? publisher.id}'s key ${id8}` };
    } catch {
      return { ok: false, text: 'The signature could not be checked' };
    }
  })();
  state.versionChecks.set(id, check);
  return check;
}

function renderVersion(entry, version, publisher) {
  const seal = h('span', { class: 'seal pending' }, 'Checking signature…');
  checkVersion(entry, version).then(result => {
    seal.className = `seal ${result.ok ? 'good' : 'bad'}`;
    seal.replaceChildren(result.ok ? '✓ ' : '✗ ', result.text, result.detail ? h('span', { class: 'muted' }, ` · ${result.detail}`) : null);
  });

  const release = version.release;
  const releaseUrl = release && safeUrl(release.repository)
    ? `${release.repository.replace(/\/$/, '')}/releases/tag/${encodeURIComponent(release.tag)}` : null;
  const source = version.source;
  const sourceUrl = source && safeUrl(source.repository)
    ? `${source.repository.replace(/\/$/, '')}/tree/${encodeURIComponent(source.commit)}` : null;

  return h('article', { class: `version-card${version.retired ? ' is-retired' : ''}`, id: `v${version.version}` },
    h('header', null,
      h('h3', null, `v${version.version}`),
      version.released ? h('span', { class: 'muted' }, date(version.released)) : null,
      version.retired ? h('span', { class: 'retired' }, 'retired') : null,
      seal),
    version.retired && version.retiredReason ? h('p', { class: 'notice' }, version.retiredReason) : null,
    version.description ? h('p', null, version.description) : null,
    h('dl', { class: 'facts' },
      releaseUrl ? fact('Release', link(releaseUrl, `${release.tag}`)) : null,
      sourceUrl ? fact('Source', link(sourceUrl, source.commit.slice(0, 12))) : null,
      version.abi != null ? fact('Hook ABI', String(version.abi)) : null,
      version.hosts?.length ? fact('Runs under', version.hosts.join(', ')) : null,
      version.loader ? fact('Loader', JSON.stringify(version.loader)) : null,
      version.integration ? fact('Integration', JSON.stringify(version.integration)) : null,
      version.requires?.length ? fact('Requires', version.requires.map(r => (typeof r === 'string' ? r : `${r.key} ${r.version ?? ''}`)).join(', ')) : null,
      version.manifestSha256 ? fact('Manifest', hash(version.manifestSha256)) : null),
    filesTable(version.files ?? []),
    version.config ? configTable(version.config) : null,
    version.notes ? h('div', { class: 'notes' }, version.notes) : null);
}

function filesTable(files) {
  if (!files.length) return null;
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, ['Platform', 'File', 'Size', 'SHA-256', 'BLAKE3'].map(t => h('th', null, t)))),
    h('tbody', null, files.map(f => h('tr', null,
      h('td', null, `${f.os} · ${f.architecture}`),
      h('td', null, link(f.url, f.fileName)),
      h('td', { class: 'num' }, size(f.size)),
      h('td', null, hash(f.sha256)),
      h('td', null, hash(f.blake3)))))));
}

function configTable(config) {
  const rows = [];
  const walk = (properties, required, prefix) => {
    for (const [name, field] of Object.entries(properties ?? {})) {
      if (field.type === 'object') { walk(field.properties, new Set(field.required ?? []), `${prefix}${name}.`); continue; }
      const limits = [
        field.enum ? `one of ${field.enum.join(', ')}` : null,
        field.minimum != null || field.maximum != null ? `${field.minimum ?? '…'} – ${field.maximum ?? '…'}` : null,
        field.maxLength != null ? `at most ${field.maxLength} characters` : null,
        field.items ? `list of ${field.items.type}` : null,
      ].filter(Boolean).join('; ');
      rows.push(h('tr', null,
        h('td', null, h('code', null, `${prefix}${name}`), required.has(name) ? h('span', { class: 'muted' }, ' required') : null),
        h('td', null, field.title ? h('strong', null, field.title) : null, field.description ? h('div', { class: 'muted' }, field.description) : null),
        h('td', null, field.enum ? 'enum' : field.type ?? ''),
        h('td', null, field.default !== undefined ? h('code', null, JSON.stringify(field.default)) : '—'),
        h('td', { class: 'muted' }, limits)));
    }
  };
  walk(config.properties, new Set(config.required ?? []), '');
  if (!rows.length) return null;
  return h('details', { class: 'config' },
    h('summary', null, `Options (${rows.length})`),
    h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, ['Option', '', 'Type', 'Default', 'Limits'].map(t => h('th', null, t)))),
      h('tbody', null, rows))));
}

// ---- The registry --------------------------------------------------------------------------------------------------

function renderRegistry() {
  const { trust, timestamp, index } = state;
  const policy = index.policy ?? {};
  return h('section', { class: 'registry' },
    h('a', { class: 'back', href: exploreHash() }, '← All plugins'),
    h('h1', null, 'Use this registry'),
    h('p', { class: 'lead' }, 'Add it to a Stoker instance\'s plugin registries with this URL and key. Stoker trusts the registry by its key and its publishers only for their namespaces, and an administrator still approves every version before it runs.'),
    h('dl', { class: 'facts wide' },
      fact('URL', h('span', { class: 'hash' }, h('code', null, REGISTRY.url), copyButton(REGISTRY.url))),
      fact('Key', h('span', { class: 'hash' }, h('code', { class: 'wrap-anywhere' }, REGISTRY.key), copyButton(REGISTRY.key))),
      fact('Key id', h('code', null, trust.keyId)),
      fact('Name', h('code', null, REGISTRY.name))),
    h('h2', null, 'This index'),
    h('dl', { class: 'facts wide' },
      fact('Serial', String(timestamp.serial)),
      fact('Generated', date(timestamp.generated)),
      fact('Current until', date(timestamp.expires)),
      fact('Checked here', trust.ok ? '✓ signature, pin and expiry' : trust.problems.join('; '))),
    h('p', null, 'To check it yourself: ', h('code', null, `stoker-registry verify-index <folder with index/v1> --key registry.yaml`), ' (the .NET tool StokerHQ.PluginRegistry.Tool).'),
    h('h2', null, 'Publishers'),
    h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, ['Publisher', 'Namespaces', 'Key id'].map(t => h('th', null, t)))),
      h('tbody', null, [...state.publishers.values()].map(p => {
        const id = h('code', null, '…');
        keyId(p.publicKey).then(v => { id.textContent = v; }).catch(() => { id.textContent = 'invalid key'; });
        return h('tr', null,
          h('td', null, p.homepage ? link(p.homepage, p.name ?? p.id) : (p.name ?? p.id)),
          h('td', null, (p.namespaces ?? []).map(n => h('code', { class: 'tag' }, `${n}*`))),
          h('td', null, id));
      })))),
    h('h2', null, 'Policy'),
    h('ul', null,
      policy.refusedKinds?.length ? h('li', null, 'Refused kinds: ', policy.refusedKinds.join(', ')) : null,
      policy.refusedIntegrationProviders?.length ? h('li', null, 'Refused integrations: ', policy.refusedIntegrationProviders.join(', ')) : null,
      !policy.refusedKinds?.length && !policy.refusedIntegrationProviders?.length ? h('li', null, 'None') : null),
    index.mirrors?.length ? [h('h2', null, 'Mirrors'), h('ul', null, index.mirrors.map(m => h('li', null, link(m.url ?? m, m.url ?? m))))] : null);
}

// ---- Trust banner and start ----------------------------------------------------------------------------------------

function renderTrust() {
  const banner = document.getElementById('trust');
  const { trust, timestamp } = state;
  banner.className = `trust wrap ${trust.ok ? 'ok' : 'bad'}`;
  banner.replaceChildren(...(trust.ok
    ? [h('span', { class: 'dot' }), 'Index verified in your browser: serial ', String(timestamp.serial), ', signed by ',
      h('code', null, trust.keyId), ', current until ', date(timestamp.expires), '.']
    : [h('strong', null, 'This index does not check out: '), trust.problems.join('; '), '. Stoker would refuse it.']));
}

document.addEventListener('keydown', event => {
  if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
  const target = event.target;
  if (target instanceof HTMLElement && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))) return;
  event.preventDefault();
  if (route().path !== '/') location.hash = exploreHash();
  requestAnimationFrame(() => document.getElementById('q')?.focus());
});

try {
  await load();
  renderTrust();
  render();
  window.addEventListener('hashchange', render);
} catch (error) {
  const banner = document.getElementById('trust');
  banner.className = 'trust wrap bad';
  banner.textContent = `The index could not be read: ${error.message}`;
  document.getElementById('main').replaceChildren();
}
