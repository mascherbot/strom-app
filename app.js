'use strict';
// Strom-App: liest ausschließlich data.json (von Strom Bot gepflegt) und zeigt sie an.
const $ = id => document.getElementById(id);
const nf = (v, d = 0) => v == null ? '–' : new Intl.NumberFormat('de-DE', {minimumFractionDigits: d, maximumFractionDigits: d}).format(v);
const eur = (v, d = 2) => v == null ? '–' : nf(v, d) + ' €';
const kwh = (v, d = 0) => v == null ? '–' : nf(v, d) + ' kWh';
const pct = v => v == null ? '–' : nf(v * 100, 1) + ' %';
const fmtDate = s => { const [y, m, d] = s.split('-'); return `${d}.${m}.${y}`; };
const fmtDateShort = s => { const [, m, d] = s.split('-'); return `${d}.${m}.`; };
const fmtTs = s => new Date(s).toLocaleString('de-DE', {timeZone: 'Europe/Berlin', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'});
const monthName = ym => { const [y, m] = ym.split('-').map(Number); return new Date(y, m - 1, 15).toLocaleString('de-DE', {month: 'long'}); };
const hex2rgba = (h, a) => { const n = parseInt(h.slice(1), 16); return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`; };

let D = null, charts = {}, built = {}, current = 'ueberblick', lastStamp = null;
const est = i => !!(D.estimated && D.estimated[i]);
const yl = i => D.years[i] + (est(i) ? '*' : '');
const ca = (i, v, d = 2) => v == null ? '–' : est(i) ? 'ca. ' + nf(v, 0) : nf(v, d);   // geschätzte € ohne Cent
const L = () => D.years.length - 1;
const quote = () => D.self_kwh.map((s, i) => s == null || !D.pv_kwh[i] ? null : s / D.pv_kwh[i]);
const sum2 = (a, b) => a.map((v, i) => v == null && b[i] == null ? null : (v || 0) + (b[i] || 0));

// ---------- Verschlüsselte Daten laden ----------
// data.enc.json: {v, kdf, iter, salt, iv, ct} – AES-256-GCM, Schlüssel per PBKDF2-SHA256 aus dem Passwort.
// Der abgeleitete Schlüssel wird nicht-exportierbar (CryptoKey) in IndexedDB gespeichert.
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const idb = (mode, fn) => new Promise((res, rej) => {
  const o = indexedDB.open('strom-app', 1);
  o.onupgradeneeded = () => o.result.createObjectStore('keys');
  o.onerror = () => rej(o.error);
  o.onsuccess = () => { const tx = o.result.transaction('keys', mode); const r = fn(tx.objectStore('keys'));
    tx.oncomplete = () => res(r && r.result); tx.onerror = () => rej(tx.error); };
});
const getStored = () => idb('readonly', st => st.get('k')).catch(() => null);
const setStored = v => idb('readwrite', st => st.put(v, 'k'));
const clearStored = () => idb('readwrite', st => st.delete('k')).catch(() => {});
let memKey = null, enc = null;
async function deriveKey(pw, enc) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256', salt: b64(enc.salt), iterations: enc.iter}, base, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
}
async function decrypt(enc, key) {
  const pt = await crypto.subtle.decrypt({name: 'AES-GCM', iv: b64(enc.iv)}, key, b64(enc.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
function showLock(msg = '') {
  $('lock').hidden = false; $('logout').hidden = true; $('lockerr').textContent = msg;
  setTimeout(() => $('pw').focus(), 50);
}
async function useData(data) {
  $('lock').hidden = true; $('logout').hidden = false; $('error').hidden = true;
  if (data.updated_at === lastStamp && D) return;
  lastStamp = data.updated_at; D = data; render();
}
async function load() {
  try {
    if (!window.crypto || !crypto.subtle) throw new Error('WebCrypto nicht verfügbar – App bitte über HTTPS öffnen');
    const r = await fetch('data.enc.json', {cache: 'no-store'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    enc = await r.json();
  } catch (e) {
    $('error').hidden = false;
    $('error').textContent = 'Daten konnten nicht geladen werden (' + e.message + ').' + (D ? ' Angezeigt wird der letzte Stand.' : '');
    return;
  }
  let st = memKey && memKey.salt === enc.salt && memKey.iter === enc.iter ? memKey : await getStored();
  if (st && st.salt === enc.salt && st.iter === enc.iter) {
    let data = null;
    try { data = await decrypt(enc, st.key); } catch { /* Schlüssel passt nicht mehr */ }
    if (data) { memKey = st; return useData(data); }
  }
  memKey = null;
  showLock(st ? 'Das Passwort wurde geändert. Bitte neu eingeben.' : '');
}
$('lockform').addEventListener('submit', async ev => {
  ev.preventDefault();
  const pw = $('pw').value;
  if (!pw || !enc) return;
  $('unlock').disabled = true; $('unlock').textContent = 'Prüfe …'; $('lockerr').textContent = '';
  try {
    const key = await deriveKey(pw, enc);
    let data;
    try { data = await decrypt(enc, key); } catch { throw new Error('wrong'); }
    memKey = {key, salt: enc.salt, iter: enc.iter};
    try { await setStored(memKey); } catch { /* z. B. privater Modus: nur für diese Sitzung */ }
    $('pw').value = '';
    await useData(data);
  } catch (e) {
    $('lockerr').textContent = e.message === 'wrong' ? 'Falsches Passwort. Bitte erneut versuchen.' : 'Fehler beim Entschlüsseln: ' + e.message;
    $('pw').select();
  } finally { $('unlock').disabled = false; $('unlock').textContent = 'Entsperren'; }
});
async function logout() {
  if (!confirm('Abmelden? Das Passwort muss danach erneut eingegeben werden.')) return;
  await clearStored(); memKey = null; D = null; lastStamp = null;
  Object.values(charts).forEach(c => c.destroy()); charts = {}; built = {};
  showLock();
}
$('logout').addEventListener('click', logout);
$('logout2').addEventListener('click', logout);

// ---------- Rendering ----------
function render() {
  const l = L(), q = quote();
  $('meta').innerHTML = `Stand ${fmtDate(D.stand)}<br>aktualisiert ${fmtTs(D.updated_at)}`;
  const estYears = D.years.filter((_, i) => est(i));
  $('notice').innerHTML = estYears.length
    ? `<b>${estYears.join(', ')} = Teiljahr / Schätzung</b> (Stand ${fmtDate(D.stand)}). In Diagrammen und Tabellen mit <b>*</b> und hellerer/gestrichelter Darstellung gekennzeichnet.`
    : `Alle Werte aus Jahresrechnungen (Stand ${fmtDate(D.stand)}).`;
  $('notice').hidden = false;

  // KPI-Karten (wie Dashboard)
  const prev = (fn) => D.years.slice(0, l).map((y, i) => `<div><span>${yl(i)}</span><b>${fn(i)}</b></div>`).join('');
  $('kl-net').textContent = `Netto-Stromkosten ${yl(l)}`;
  $('k-net').textContent = (est(l) ? 'ca. ' : '') + eur(D.net_eur[l], est(l) ? 0 : 2);
  $('k-net').classList.toggle('neg', D.net_eur[l] < 0);
  $('kr-net').innerHTML = prev(i => eur(D.net_eur[i]));
  $('kl-q').textContent = `PV-Eigenverbrauchsquote ${yl(l)}`;
  $('k-q').textContent = pct(q[l]);
  $('kr-q').innerHTML = prev(i => pct(q[i]));
  $('kl-pv').textContent = `PV-Erzeugung ${yl(l)}`;
  $('k-pv').textContent = kwh(D.pv_kwh[l]);
  $('kr-pv').innerHTML = prev(i => kwh(D.pv_kwh[i]));
  const wb = D.wallbox_monthly || [];
  const wbRange = wb.length ? (wb.length > 1 ? monthName(wb[0].month) + '–' + monthName(wb[wb.length - 1].month) : monthName(wb[0].month)) : '';
  const rate = D.ev_rate_eur_per_kwh != null ? nf(D.ev_rate_eur_per_kwh, 4) + ' €/kWh' : '';
  $('kl-ev').textContent = `Ladestromvergütung Model Y ${D.years[l]}`;
  $('k-ev').textContent = eur(D.income_ev_eur[l]);
  $('kh-ev').textContent = [wbRange, kwh(D.ev_kwh[l]), rate].filter(Boolean).join(' · ');
  const inc = sum2(D.income_feed_eur, D.income_ev_eur);
  $('kr-ev').innerHTML = `<div><span>Einspeisevergütung ${yl(l)}</span><b>${(est(l) ? 'ca. ' : '') + eur(D.income_feed_eur[l], est(l) ? 0 : 2)}</b></div>`
    + `<div><span>Einnahmen ges. ${yl(l)}</span><b>${(est(l) ? 'ca. ' : '') + eur(inc[l])}</b></div>`;

  // Tabellen
  const head = (first = 'Kennzahl') => `<tr><th>${first}</th>` + D.years.map((_, i) => `<th${est(i) ? ' class="est"' : ''}>${yl(i)}</th>`).join('') + '</tr>';
  const row = (name, vals, f, c, cls = '') => `<tr${cls ? ` class="${cls}"` : ''}><td>${c ? `<span class="dot" style="background:${c}"></span>` : ''}${name}</td>`
    + vals.map((v, i) => `<td${est(i) ? ' class="est"' : ''}>${f(v, i)}</td>`).join('') + '</tr>';
  const sec = t => `<tr class="sec"><td colspan="${D.years.length + 1}">${t}</td></tr>`;
  const n0 = v => nf(v), c2 = (v, i) => ca(i, v);

  $('th-grid').innerHTML = head('kWh');
  $('tb-grid').innerHTML = row('Haus Netz', D.house_grid_kwh, n0, '#3b82f6') + row('Wärmepumpe Netz', D.wp_grid_kwh, n0, '#8b5cf6')
    + row('Summe Haus + WP', sum2(D.house_grid_kwh, D.wp_grid_kwh), n0, null, 'total');
  $('th-pv').innerHTML = head('kWh');
  $('tb-pv').innerHTML = row('PV-Erzeugung', D.pv_kwh, n0, '#f59e0b') + row('Eigenverbrauch', D.self_kwh, n0, '#16a34a')
    + row('Einspeisung', D.feed_kwh, n0, '#f5a524') + row('Eigenverbrauchsquote', q, pct, null, 'total');
  $('th-wp').innerHTML = head('Wärmepumpe');
  $('tb-wp').innerHTML = row('Netzbezug (kWh)', D.wp_grid_kwh, n0, '#8b5cf6') + row('Kosten (€)', D.cost_wp_eur, c2, '#0d9488');

  $('h-wb').textContent = `Wallbox Model Y ${D.years[l]} – monatlich`;
  $('d-wb').textContent = `Ladestrom kWh (Balken) und Vergütung € (Linie)${rate ? ' · ' + rate : ''}`;
  $('tb-wb').innerHTML = wb.map(m => `<tr><td>${monthName(m.month)} ${m.month.slice(0, 4)}</td><td>${nf(m.kwh, 2)}</td><td>${eur(m.eur)}</td></tr>`).join('')
    + `<tr class="total"><td>Summe ${wbRange}</td><td>${nf(D.ev_kwh[l], 2)}</td><td>${eur(D.income_ev_eur[l])}</td></tr>`;

  $('d-table').textContent = `Alle Werte wie erfasst${estYears.length ? `; ${estYears.join(', ')} bis ${fmtDate(D.stand)} (Schätzung)` : ''}`;
  $('th-detail').innerHTML = `<tr><th>Kennzahl</th>` + D.years.map((_, i) => `<th${est(i) ? ' class="est"' : ''}>${yl(i)}${est(i) ? `<br><small>(bis ${fmtDateShort(D.stand)})</small>` : ''}</th>`).join('') + '</tr>';
  $('tb-detail').innerHTML = sec('Energie (kWh)')
    + row('PV-Erzeugung (SolarEdge)', D.pv_kwh, n0, '#f59e0b')
    + row('Einspeisung PV', D.feed_kwh, n0, '#f5a524')
    + row('Eigenverbrauch PV', D.self_kwh, n0, '#16a34a')
    + row('Eigenverbrauchsquote', q, pct, null)
    + row('Haus Netz', D.house_grid_kwh, n0, '#3b82f6')
    + row('Wärmepumpe Netz', D.wp_grid_kwh, n0, '#8b5cf6')
    + row('Ladestrom Model Y' + (wbRange ? ` (${wbRange})` : ''), D.ev_kwh, n0, '#e11d48')
    + sec('Kosten &amp; Einnahmen (€)')
    + row('Haus Kosten', D.cost_house_eur, c2, '#3b82f6')
    + row('Wärmepumpe Kosten', D.cost_wp_eur, c2, '#8b5cf6')
    + row('Einspeisevergütung', D.income_feed_eur, c2, '#f5a524')
    + row('Ladestromvergütung Model Y', D.income_ev_eur, v => v == null ? '–' : nf(v, 2), '#e11d48')
    + row('Stromkosten Gesamtjahr (Haus + WP − Einspeisung − Ladestrom)', D.net_eur, c2, null, 'total');
  $('notes').innerHTML = (D.notes || []).map(n => `<li>${n.replace(/[&<>]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;'}[c]))}</li>`).join('');

  // Diagramme neu aufbauen (lazy pro Tab, weil versteckte Canvas keine Größe haben)
  Object.values(charts).forEach(c => c.destroy());
  charts = {}; built = {};
  buildCharts(current);
}

// ---------- Diagramme (aus dem Dashboard übernommen) ----------
Chart.defaults.font.family = '-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif';
Chart.defaults.color = '#4b5468';
Chart.defaults.animation = false;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.register({id: 'labels', afterDatasetsDraw(chart, args, opts) { if (!opts || !opts.fn) return; const {ctx} = chart; ctx.save(); opts.fn(chart, ctx); ctx.restore(); }});
const fills = c => D.years.map((_, i) => est(i) ? hex2rgba(c, .45) : c);
const base = (c, extra = {}) => ({backgroundColor: fills(c), borderColor: c, borderWidth: D.years.map((_, i) => est(i) ? 2 : 0), borderRadius: 6, borderSkipped: false, ...extra});
const yAx = fmt => ({grid: {color: '#eef1f6'}, ticks: {callback: v => fmt(v)}});
const dashEst = {segment: {borderDash: c => est(c.p1DataIndex) ? [6, 4] : undefined}};
const labelsYears = () => D.years.map((_, i) => yl(i));

const builders = {
  verbrauch() {
    const tot = sum2(D.house_grid_kwh, D.wp_grid_kwh);
    charts.grid = new Chart($('cGrid'), {type: 'bar', data: {labels: labelsYears(), datasets: [
      {label: 'Haus', data: D.house_grid_kwh, ...base('#3b82f6')},
      {label: 'Wärmepumpe', data: D.wp_grid_kwh, ...base('#8b5cf6')}]},
      options: {maintainAspectRatio: false, scales: {x: {stacked: true, grid: {display: false}}, y: {stacked: true, ...yAx(v => nf(v)), suggestedMax: Math.max(...tot) * 1.15, title: {display: true, text: 'kWh'}}},
        plugins: {tooltip: {callbacks: {label: c => `${c.dataset.label}: ${kwh(c.raw)}`}},
          labels: {fn: (ch, ctx) => { ctx.textAlign = 'center';
            [0, 1].forEach(d => ch.getDatasetMeta(d).data.forEach((b, i) => { ctx.fillStyle = '#fff'; ctx.font = '600 12px sans-serif'; ctx.fillText(nf(ch.data.datasets[d].data[i]), b.x, (b.y + b.base) / 2 + 4); }));
            ch.getDatasetMeta(1).data.forEach((b, i) => { ctx.fillStyle = '#1d2433'; ctx.font = '600 12px sans-serif'; ctx.fillText('Σ ' + kwh(tot[i]), b.x, b.y - 8); });
          }}}}});
  },
  pv() {
    const q = quote();
    charts.pv = new Chart($('cPV'), {type: 'bar', data: {labels: labelsYears(), datasets: [
      {label: 'Eigenverbrauch', data: D.self_kwh, ...base('#16a34a')},
      {label: 'Einspeisung', data: D.feed_kwh, ...base('#f5a524')}]},
      options: {maintainAspectRatio: false, scales: {x: {stacked: true, grid: {display: false}}, y: {stacked: true, ...yAx(v => nf(v)), suggestedMax: Math.max(...D.pv_kwh) * 1.13, title: {display: true, text: 'kWh'}}},
        plugins: {tooltip: {callbacks: {label: c => `${c.dataset.label}: ${kwh(c.raw)}`, footer: it => 'Erzeugung: ' + kwh(D.pv_kwh[it[0].dataIndex])}},
          labels: {fn: (ch, ctx) => { ctx.textAlign = 'center';
            ch.getDatasetMeta(1).data.forEach((b, i) => { ctx.fillStyle = '#1d2433'; ctx.font = '600 12px sans-serif'; ctx.fillText(kwh(D.pv_kwh[i]), b.x, b.y - 8); });
            ch.getDatasetMeta(0).data.forEach((b, i) => { ctx.fillStyle = '#fff'; ctx.font = '700 13px sans-serif'; ctx.fillText(pct(q[i]), b.x, (b.y + b.base) / 2 + 5); });
          }}}}});
  },
  wp() {
    charts.wp = new Chart($('cWP'), {data: {labels: labelsYears(), datasets: [
      {type: 'bar', label: 'Netzbezug (kWh)', data: D.wp_grid_kwh, ...base('#8b5cf6'), yAxisID: 'y'},
      {type: 'line', label: 'Kosten (€)', data: D.cost_wp_eur, borderColor: '#0d9488', backgroundColor: '#0d9488', borderWidth: 3, pointRadius: 6, yAxisID: 'y1', order: -1, ...dashEst}]},
      options: {maintainAspectRatio: false, scales: {x: {grid: {display: false}},
        y: {...yAx(v => nf(v)), beginAtZero: true, suggestedMax: Math.max(...D.wp_grid_kwh) * 1.25, title: {display: true, text: 'kWh'}},
        y1: {position: 'right', beginAtZero: true, suggestedMax: Math.max(...D.cost_wp_eur) * 1.6, grid: {display: false}, ticks: {callback: v => nf(v) + ' €'}}},
        plugins: {tooltip: {callbacks: {label: c => c.dataset.yAxisID === 'y1' ? `Kosten: ${eur(c.raw)}` : `Netzbezug: ${kwh(c.raw)}`}},
          labels: {fn: (ch, ctx) => { ctx.textAlign = 'center';
            ch.getDatasetMeta(0).data.forEach((b, i) => { ctx.fillStyle = '#fff'; ctx.font = '700 12px sans-serif'; ctx.fillText(kwh(D.wp_grid_kwh[i]), b.x, b.base - 12); });
            ch.getDatasetMeta(1).data.forEach((p, i) => { ctx.font = '700 12px sans-serif'; const t = (est(i) ? 'ca. ' : '') + eur(D.cost_wp_eur[i], est(i) ? 0 : 2); const w = ctx.measureText(t).width + 10;
              ctx.fillStyle = 'rgba(255,255,255,.95)'; ctx.fillRect(p.x - w / 2, p.y - 30, w, 19); ctx.fillStyle = '#0f766e'; ctx.fillText(t, p.x, p.y - 16); });
          }}}}});
  },
  wallbox() {
    const wb = D.wallbox_monthly || [];
    const kw = wb.map(m => m.kwh), eu = wb.map(m => m.eur);
    charts.wb = new Chart($('cWB'), {data: {labels: wb.map(m => monthName(m.month)), datasets: [
      {type: 'bar', label: 'Ladestrom (kWh)', data: kw, backgroundColor: 'rgba(225,29,72,.8)', borderRadius: 8, yAxisID: 'y'},
      {type: 'line', label: 'Vergütung (€)', data: eu, borderColor: '#0d9488', backgroundColor: '#0d9488', borderWidth: 3, pointRadius: 6, yAxisID: 'y1', order: -1}]},
      options: {maintainAspectRatio: false, scales: {x: {grid: {display: false}},
        y: {...yAx(v => nf(v)), beginAtZero: true, suggestedMax: Math.max(...kw, 0) * 1.25, title: {display: true, text: 'kWh'}},
        y1: {position: 'right', beginAtZero: true, suggestedMax: Math.max(...eu, 0) * 2, grid: {display: false}, ticks: {callback: v => nf(v) + ' €'}}},
        plugins: {tooltip: {callbacks: {label: c => c.dataset.yAxisID === 'y1' ? `Vergütung: ${eur(c.raw)}` : `Ladestrom: ${kwh(c.raw, 2)}`}},
          labels: {fn: (ch, ctx) => { ctx.textAlign = 'center';
            ch.getDatasetMeta(0).data.forEach((b, i) => { ctx.fillStyle = '#fff'; ctx.font = '700 12px sans-serif'; ctx.fillText(nf(kw[i], 2) + ' kWh', b.x, b.base - 12); });
            ch.getDatasetMeta(1).data.forEach((p, i) => { ctx.font = '700 12px sans-serif'; const t = eur(eu[i]); const w = ctx.measureText(t).width + 10;
              ctx.fillStyle = 'rgba(255,255,255,.95)'; ctx.fillRect(p.x - w / 2, p.y - 30, w, 19); ctx.fillStyle = '#0f766e'; ctx.fillText(t, p.x, p.y - 16); });
          }}}}});
  },
  kosten() {
    const neg = a => a.map(v => v == null ? null : -v);
    charts.cost = new Chart($('cCost'), {data: {labels: labelsYears(), datasets: [
      {type: 'bar', label: 'Haus Kosten', data: D.cost_house_eur, stack: 'k', ...base('#3b82f6')},
      {type: 'bar', label: 'WP Kosten', data: D.cost_wp_eur, stack: 'k', ...base('#8b5cf6')},
      {type: 'bar', label: 'Einspeisevergütung', data: neg(D.income_feed_eur), stack: 'e', ...base('#f5a524')},
      {type: 'bar', label: 'Ladestromvergütung', data: neg(D.income_ev_eur), stack: 'e', ...base('#e11d48')},
      {type: 'line', label: 'Netto-Stromkosten', data: D.net_eur, borderColor: '#0f2747', backgroundColor: '#0f2747', borderWidth: 3, pointRadius: 6, pointHoverRadius: 8, order: -1, ...dashEst}]},
      options: {maintainAspectRatio: false, scales: {x: {stacked: true, grid: {display: false}}, y: {stacked: true, ...yAx(v => nf(v) + ' €'), suggestedMin: -2000, suggestedMax: 1800}},
        plugins: {legend: {labels: {boxWidth: 10, font: {size: 11}}}, tooltip: {callbacks: {label: c => `${c.dataset.label}: ${eur(c.raw)}`}},
          labels: {fn: (ch, ctx) => { const m = ch.getDatasetMeta(4); ctx.font = '700 12px sans-serif'; ctx.textAlign = 'center';
            m.data.forEach((p, i) => { const t = (est(i) ? 'ca. ' : '') + eur(D.net_eur[i], est(i) ? 0 : 2); const w = ctx.measureText(t).width + 10;
              ctx.fillStyle = 'rgba(255,255,255,.92)'; ctx.fillRect(p.x - w / 2, p.y - 30, w, 19); ctx.fillStyle = D.net_eur[i] < 0 ? '#15803d' : '#0f2747'; ctx.fillText(t, p.x, p.y - 16); });
          }}}}});
  }
};
function buildCharts(v) { if (!D || built[v] || !builders[v]) return; built[v] = true; builders[v](); }

// ---------- Navigation ----------
function show(v) {
  current = v;
  document.querySelectorAll('.view').forEach(s => s.classList.toggle('active', s.id === 'v-' + v));
  document.querySelectorAll('#tabbar button').forEach(b => b.classList.toggle('active', b.dataset.v === v));
  buildCharts(v);
  window.scrollTo(0, 0);
  if (location.hash !== '#' + v) history.replaceState(null, '', '#' + v);
}
document.querySelectorAll('#tabbar button').forEach(b => b.addEventListener('click', () => show(b.dataset.v)));
const tabs = [...document.querySelectorAll('#tabbar button')].map(b => b.dataset.v);
show(tabs.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'ueberblick');

// Neue Daten automatisch: beim Start, beim Zurückkehren in die App und alle 5 Minuten
load();
document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
setInterval(load, 5 * 60 * 1000);
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
