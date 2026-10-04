/* OpenBOM Console — React 18 + Arco Design, no build step (htm tagged templates).
 * Security: all agent-supplied data is rendered through React (auto-escaped); never inject raw HTML.
 */
"use strict";
(function () {
  const { useState, useEffect, useCallback, useMemo, useRef } = React;
  const html = htm.bind(React.createElement);
  const {
    Layout, Menu, Card, Grid, Statistic, Table, Tag, Progress, Tabs, Descriptions, Drawer, Modal, Message,
    Button, Space, Input, Select, Switch, Slider, Empty, Spin, Result, Alert, Typography, Tooltip, Badge,
    Breadcrumb, Upload, Popconfirm, Divider, Form, Radio, Link, Skeleton,
  } = arco;
  const I = arcoicon;
  const { Row, Col } = Grid;
  const { Sider, Header, Content } = Layout;
  const TabPane = Tabs.TabPane;

  // ------------------------------------------------------------------ helpers
  const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const SEV_COLOR = { CRITICAL: "red", HIGH: "orangered", MEDIUM: "gold", LOW: "green", UNKNOWN: "gray" };
  const SEV_HEX = { CRITICAL: "rgb(var(--red-6))", HIGH: "rgb(var(--orangered-6))", MEDIUM: "rgb(var(--gold-6))",
                    LOW: "rgb(var(--green-6))", UNKNOWN: "var(--color-fill-4)" };
  const TRIAGE_STATES = ["in_triage", "exploitable", "not_affected", "false_positive", "resolved"];
  const TRIAGE_COLOR = { in_triage: "arcoblue", exploitable: "red", not_affected: "green", false_positive: "gray", resolved: "cyan" };
  const JUSTIFICATIONS = ["component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                          "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"];
  const enc = encodeURIComponent;
  const RESOLVED_HINT = "Marked resolved, but the latest scan of this asset still contains the vulnerable version. Upgrade it at the path shown, then re-run the agent on the same target. (Only not_affected / false_positive hide a finding.)";
  const NO_PATH_HINT = "No path recorded: OS packages live in the package-manager database, and scans from agents older than this release did not send paths — re-run the agent to record them.";

  const store = {
    get(k, d = "") { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
    set(k, v) { try { v ? localStorage.setItem(k, v) : localStorage.removeItem(k); } catch { /* private mode */ } },
  };

  async function api(path, opts = {}) {
    const headers = Object.assign({ Accept: "application/json" }, opts.headers || {});
    const key = store.get("openbom_api_key");
    if (key) headers["X-API-Key"] = key;
    if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts = { ...opts, body: JSON.stringify(opts.json) }; }
    const res = await fetch(path, { ...opts, headers });
    if (res.status === 401) { const e = new Error("Unauthorized — set a valid API key in Settings."); e.status = 401; throw e; }
    if (!res.ok) {
      let detail = res.statusText;
      try { const b = await res.json(); detail = typeof b.detail === "string" ? b.detail : JSON.stringify(b.detail); } catch { /* not json */ }
      const e = new Error(`${res.status} — ${detail}`); e.status = res.status; throw e;
    }
    return res.status === 204 ? null : res.json();
  }

  function useApi(path, deps = []) {
    const [state, setState] = useState({ data: null, error: null, loading: !!path });
    const [tick, setTick] = useState(0);
    useEffect(() => {
      if (!path) { setState({ data: null, error: null, loading: false }); return; }
      let alive = true;
      setState((s) => ({ ...s, loading: true, error: null }));
      api(path).then((data) => alive && setState({ data, error: null, loading: false }))
        .catch((error) => alive && setState({ data: null, error, loading: false }));
      return () => { alive = false; };
    }, [path, tick, ...deps]);
    return { ...state, reload: useCallback(() => setTick((t) => t + 1), []) };
  }

  function parseHash() {
    const raw = location.hash.replace(/^#/, "") || "/overview";
    const [p, q = ""] = raw.split("?");
    return { parts: p.split("/").filter(Boolean).map(decodeURIComponent), params: new URLSearchParams(q) };
  }
  function useRoute() {
    const [route, setRoute] = useState(parseHash());
    useEffect(() => { const f = () => setRoute(parseHash()); window.addEventListener("hashchange", f); return () => window.removeEventListener("hashchange", f); }, []);
    return route;
  }
  const go = (h) => { location.hash = h; };
  const safeUrl = (u) => (/^https?:\/\//i.test(String(u || "")) ? String(u) : undefined);

  function ago(ts) {
    if (!ts) return "—";
    const d = (Date.now() - new Date(ts).getTime()) / 1000;
    if (d < 90) return "just now"; if (d < 5400) return `${Math.round(d / 60)}m ago`;
    if (d < 172800) return `${Math.round(d / 3600)}h ago`; return `${Math.round(d / 86400)}d ago`;
  }
  function download(name, data, type = "application/json") {
    const blob = new Blob([typeof data === "string" ? data : JSON.stringify(data, null, 2)], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function toCsv(rows, cols) {
    const esc = (v) => { const s = v == null ? "" : String(v); return /[",\n]/.test(s) || /^[=+\-@]/.test(s) ? `"${s.replace(/"/g, '""').replace(/^([=+\-@])/, "'$1")}"` : s; };
    return [cols.map((c) => c[0]).join(","), ...rows.map((r) => cols.map((c) => esc(c[1](r))).join(","))].join("\n");
  }
  const fileSafe = (s) => String(s).replace(/[^\w.-]+/g, "_");
  const reducedMotion = () => { try { return matchMedia("(prefers-reduced-motion: reduce)").matches; } catch { return false; } };

  // ------------------------------------------------------------------ small components
  const SevTag = ({ s }) => { s = (s || "UNKNOWN").toUpperCase(); if (!SEVS.includes(s)) s = "UNKNOWN"; return html`<${Tag} color=${SEV_COLOR[s]} bordered size="small">${s}<//>`; };
  function Intel({ v }) {
    const tags = [];
    if (v.is_malicious) tags.push(html`<${Tag} key="m" color="magenta" size="small" icon=${html`<${I.IconBug} />`}>MALWARE<//>`);
    if (v.is_kev) tags.push(html`<${Tooltip} key="k" content="CISA Known Exploited Vulnerability"><${Tag} color="red" size="small" icon=${html`<${I.IconFire} />`}>KEV<//><//>`);
    if (v.is_heuristic) tags.push(html`<${Tag} key="h" color="purple" size="small">${String(v.vuln_id).startsWith("TYPOSQUAT") ? "TYPOSQUAT" : "IOC"}<//>`);
    if (v.poc_links && v.poc_links.length) tags.push(html`<${Tag} key="p" color="gold" size="small">PoC ${v.poc_links.length}<//>`);
    if (v.triage_state === "resolved") tags.push(html`<${Tooltip} key="t" content=${RESOLVED_HINT}><${Tag} color="orange" size="small" icon=${html`<${I.IconExclamationCircle} />`}>resolved · still detected<//><//>`);
    else if (v.triage_state) tags.push(html`<${Tag} key="t" color=${TRIAGE_COLOR[v.triage_state] || "gray"} size="small">${v.triage_state}<//>`);
    return tags.length ? html`<${Space} size=${4} wrap>${tags}<//>` : html`<span class="ob-muted">—</span>`;
  }
  const Epss = ({ v }) => v == null ? html`<span class="ob-muted">—</span>`
    : html`<${Tag} size="small" color=${v >= 0.1 ? "red" : v >= 0.01 ? "orange" : "gray"}>${(v * 100).toFixed(1)}%<//>`;
  function Risk({ score }) {
    const n = Math.max(0, Math.min(100, Number(score) || 0));
    const color = n >= 70 ? "rgb(var(--red-6))" : n >= 40 ? "rgb(var(--orange-6))" : n >= 15 ? "rgb(var(--gold-6))" : "rgb(var(--green-6))";
    return html`<div class="ob-risk"><b>${n}</b><${Progress} percent=${n} showText=${false} color=${color} size="small" style=${{ flex: 1 }} /></div>`;
  }
  function SevBar({ counts }) {
    const total = SEVS.reduce((a, s) => a + (counts?.[s] || 0), 0);
    if (!total) return html`<${Empty} description="No vulnerabilities" />`;
    return html`<div>
      <div class="ob-stack">${SEVS.filter((s) => counts[s]).map((s) => html`<${Tooltip} key=${s} content=${`${s}: ${counts[s]}`}><div style=${{ width: `${(counts[s] / total) * 100}%`, background: SEV_HEX[s] }} /><//>`)}</div>
      <div class="ob-legend">${SEVS.map((s) => html`<span key=${s}><span class="ob-dot" style=${{ background: SEV_HEX[s] }} />${s} <b>${counts[s] || 0}</b></span>`)}</div>
    </div>`;
  }
  const TargetTag = ({ t }) => {
    const m = { host: ["arcoblue", "HOST"], image: ["purple", "IMAGE"], rootfs: ["cyan", "ROOTFS"], path: ["green", "REPO"], sbom: ["orange", "SBOM"] };
    const [c, l] = m[t || "host"] || ["gray", String(t).toUpperCase()];
    return html`<${Tag} size="small" color=${c}>${l}<//>`;
  };
  function EolTag({ eol }) {
    if (!eol || !eol.length) return null;
    const bad = eol.find((e) => e.is_eol);
    if (bad) return html`<${Tooltip} content=${`${bad.label} — EOL ${bad.eol}`}><${Tag} size="small" color="red">EOL<//><//>`;
    const soon = eol.find((e) => e.days_left != null && e.days_left <= 180);
    return soon ? html`<${Tooltip} content=${`${soon.label} — EOL ${soon.eol}`}><${Tag} size="small" color="orange">EOL ${soon.days_left}d<//><//>` : null;
  }
  function PageHead({ title, sub, extra, icon }) {
    return html`<div class="ob-page-head"><div><h1>${icon ? html`<span style=${{ marginRight: 8, color: "rgb(var(--primary-6))" }}>${icon}</span>` : null}${title}</h1>${sub ? html`<div class="ob-sub">${sub}</div>` : null}</div>${extra ? html`<${Space} wrap>${extra}<//>` : null}</div>`;
  }
  function Kpi({ title, value, tone = "blue", onClick, suffix, icon }) {
    return html`<${Card} className=${`ob-kpi t-${tone}${onClick ? " clickable" : ""}`} bordered hoverable=${!!onClick} onClick=${onClick}>
      <${Statistic} title=${html`<span>${icon ? html`<span style=${{ marginRight: 6 }}>${icon}</span>` : null}${title}</span>`} value=${value ?? 0} suffix=${suffix} groupSeparator countUp=${!reducedMotion()} countDuration=${900} />
    <//>`;
  }
  function Loader({ q, children }) {
    if (q.loading && !q.data) return html`<div class="ob-skeleton"><${Skeleton} animation text=${{ rows: 5, width: ["60%", "100%", "92%", "84%", "70%"] }} /></div>`;
    if (q.error) {
      if (q.error.status === 401) return html`<${Result} status="403" title="API key required" subTitle=${q.error.message} extra=${html`<${Button} type="primary" onClick=${() => go("#/settings")}>Open Settings<//>`} />`;
      if (q.error.status === 404) return html`<${Result} status="404" title="Not found" subTitle=${q.error.message} extra=${html`<${Button} onClick=${() => history.back()}>Back<//>`} />`;
      return html`<${Result} status="error" title="Request failed" subTitle=${q.error.message} extra=${html`<${Button} onClick=${q.reload}>Retry<//>`} />`;
    }
    if (q.data == null) return null;  // no path yet (e.g. a closing drawer) — never hand null to renderers
    return children(q.data);
  }
  const VulnLink = ({ id, onOpen }) => {
    const label = String(id).includes("::") ? String(id).split("::")[0] : id;  // heuristic ids are namespaced per package
    const link = html`<${Link} onClick=${(e) => { e.stopPropagation(); onOpen ? onOpen(id) : go(`#/vulns?open=${enc(id)}`); }}><span class="ob-mono">${label}</span><//>`;
    return label === id ? link : html`<${Tooltip} content=${id}>${link}<//>`;
  };
  const HostLink = ({ h }) => html`<${Link} onClick=${(e) => { e.stopPropagation(); go(`#/asset/${enc(h)}`); }}>${h}<//>`;
  // Where a package was found (path/rootfs/image scans) — answers "I fixed it, why is it still here?"
  // Shorten long paths without hiding what matters: the project/venv and the file. Uninformative segments
  // (lib, python3.x, site-packages) collapse first, then leading directories. The tooltip has the full path.
  const BORING_SEGMENT = /^(lib|lib64|python\d[\d.]*|site-packages|dist-packages)$/;
  function shortPath(path, max = 60) {
    const out = String(path).replace(/^\/home\/[^/]+/, "~").replace(/^\/root(?=\/|$)/, "~").split("/");
    if (out.length > 2 && out[out.length - 1] === "METADATA" && /\.(dist|egg)-info$/.test(out[out.length - 2])) out.pop();
    const render = () => out.filter((x, i) => !(x === "…" && out[i - 1] === "…")).join("/");
    while (render().length > max) {
      let i = out.findIndex((x, k) => k > 0 && k < out.length - 1 && BORING_SEGMENT.test(x));
      if (i < 0) i = out.findIndex((x, k) => k > 0 && k < out.length - 3 && x !== "…");
      if (i < 0) break;
      out[i] = "…";
    }
    return render();
  }
  const OS_ECOSYSTEM = /^(RPM|Debian|Ubuntu|Alpine)$|-(RPM|DEB|APK)$/;
  function FoundIn({ loc, placeholder, wrap, eco }) {
    if (!loc && placeholder && OS_ECOSYSTEM.test(eco || "")) return html`<span class="ob-muted">system package (package manager)</span>`;
    if (!loc) return placeholder ? html`<${Tooltip} content=${NO_PATH_HINT}><span class="ob-muted ob-hint">path not recorded</span><//>` : null;
    const all = String(loc).split("\n").filter(Boolean);
    const shown = all.slice(0, 2);
    return html`<div class=${`ob-loc${wrap ? " ob-loc-wrap" : ""}`}>${shown.map((l) => html`<${Tooltip} key=${l} content=${l}><div class="ob-loc-line"><${I.IconFolder} /> <span class="ob-mono">${wrap ? l.replace(/^\/home\/[^/]+/, "~") : shortPath(l)}</span></div><//>`)}
      ${all.length > shown.length ? html`<${Tooltip} content=${html`<div>${all.slice(2).map((l) => html`<div key=${l} class="ob-mono">${l}</div>`)}</div>`}><span class="ob-muted">+${all.length - shown.length} more location(s)</span><//>` : null}</div>`;
  }

  // ------------------------------------------------------------------ vulnerability drawer + triage
  function TriageModal({ visible, vuln, hostname, onClose, onSaved }) {
    const [form] = Form.useForm();
    const [busy, setBusy] = useState(false);
    useEffect(() => { if (visible) form.setFieldsValue({ state: vuln?.triage_state || "not_affected", scope: hostname ? "asset" : "fleet", justification: JUSTIFICATIONS[2], detail: "" }); }, [visible]);
    const submit = async () => {
      const v = await form.validate(); setBusy(true);
      try {
        await api("/api/v1/triage", { method: "PUT", json: { vuln_id: vuln.vuln_id, hostname: v.scope === "asset" ? hostname : null, state: v.state, justification: v.state === "not_affected" ? v.justification : null, detail: v.detail || null, author: "dashboard" } });
        Message.success(`Triage saved for ${vuln.vuln_id}`); onSaved && onSaved(); onClose();
      } catch (e) { Message.error(e.message); } finally { setBusy(false); }
    };
    return html`<${Modal} title=${html`<span>Triage <span class="ob-mono">${vuln?.vuln_id}</span></span>`} visible=${visible} onOk=${submit} confirmLoading=${busy} onCancel=${onClose} okText="Save decision" maskClosable=${false} unmountOnExit>
      <${Alert} type="info" style=${{ marginBottom: 14 }} content="not_affected and false_positive hide the finding (VEX semantics). Decisions are exportable as OpenVEX." />
      <${Form} form=${form} layout="vertical">
        <${Form.Item} label="State" field="state" rules=${[{ required: true }]}><${Select} options=${TRIAGE_STATES.map((s) => ({ label: s, value: s }))} /><//>
        <${Form.Item} shouldUpdate noStyle>${(values) => values.state === "not_affected" ? html`<${Form.Item} label="Justification (OpenVEX)" field="justification"><${Select} options=${JUSTIFICATIONS.map((s) => ({ label: s, value: s }))} /><//>` : null}<//>
        <${Form.Item} label="Scope" field="scope"><${Radio.Group} type="button" options=${[{ label: "Whole fleet", value: "fleet" }, ...(hostname ? [{ label: `Only ${hostname}`, value: "asset" }] : [])]} /><//>
        <${Form.Item} label="Analyst notes" field="detail"><${Input.TextArea} rows=${3} maxLength=${4000} placeholder="Why is this (not) exploitable here?" /><//>
      <//>
    <//>`;
  }

  function VulnDrawer({ id, onClose, onChanged }) {
    const q = useApi(id ? `/api/v1/vulnerabilities/${enc(id)}` : null);
    const [triage, setTriage] = useState(false);
    return html`<${Drawer} width=${Math.min(920, window.innerWidth - 24)} visible=${!!id} onCancel=${onClose} footer=${null} unmountOnExit
        title=${html`<${Space}><span class="ob-mono">${id}</span>${q.data ? html`<${SevTag} s=${q.data.vulnerability.severity} />` : null}<//>`}>
      <${Loader} q=${q}>${(d) => {
        const v = d.vulnerability;
        return html`<div class="ob-section-gap">
          ${v.triage_state === "resolved" && d.affected.length ? html`<${Alert} type="warning" showIcon title=${`Marked resolved, still detected on ${new Set(d.affected.map((a) => a.hostname)).size} asset(s)`} content=${RESOLVED_HINT} />` : null}
          ${v.is_malicious ? html`<${Alert} type="error" title="Known malicious package" content="Remove it immediately and treat affected hosts as compromised (rotate credentials, investigate)." />` : null}
          <${Space} wrap><${Intel} v=${v} />
            ${!v.is_heuristic ? html`<${Button} size="small" icon=${html`<${I.IconLaunch} />`} href=${`https://osv.dev/vulnerability/${enc(v.vuln_id)}`} target="_blank">OSV.dev<//>` : null}
            <${Button} size="small" type="primary" icon=${html`<${I.IconCheckCircle} />`} onClick=${() => setTriage(true)}>Triage<//>
          <//>
          <${Descriptions} column=${1} border size="small" labelStyle=${{ width: 150 }} data=${[
            { label: "Summary", value: v.summary || "—" },
            { label: "CVEs", value: v.cves.length ? html`<${Space} wrap>${v.cves.map((c) => html`<${Link} key=${c} href=${`https://nvd.nist.gov/vuln/detail/${enc(c)}`} target="_blank">${c}<//>`)}<//>` : "—" },
            { label: "CVSS v3", value: v.cvss_score ?? "—" },
            { label: "EPSS", value: html`<span><${Epss} v=${v.epss_score} /> ${v.epss_percentile != null ? html`<span class="ob-muted">percentile ${(v.epss_percentile * 100).toFixed(1)}%</span>` : null}</span>` },
            ...(v.kev_description ? [{ label: "CISA KEV", value: v.kev_description }] : []),
            { label: "Triage", value: v.triage_state ? html`<${Tag} color=${TRIAGE_COLOR[v.triage_state]}>${v.triage_state}<//>` : "untriaged" },
            { label: "PoC / exploits", value: v.poc_links.length ? html`<div>${v.poc_links.map((u) => html`<div key=${u}><${Link} href=${safeUrl(u)} target="_blank" status="warning">${u}<//></div>`)}</div>` : "—" },
            { label: "First seen", value: v.first_seen ? new Date(v.first_seen).toLocaleString() : "—" },
          ]} />
          <${Card} title=${`Affected assets (${d.affected.length})`} size="small" bordered>
            <${Table} size="small" rowKey=${(r) => `${r.hostname}|${r.package.id}`} data=${d.affected} pagination=${d.affected.length > 10 ? { pageSize: 10 } : false} columns=${[
              { title: "Host", dataIndex: "hostname", width: 150, render: (h) => html`<span class="ob-nowrap"><${HostLink} h=${h} /></span>` },
              { title: "Package", width: 170, render: (_, r) => html`<span class="ob-nowrap"><span class="ob-mono">${r.package.name}</span> <${Tag} size="small">${r.package.ecosystem}<//></span>` },
              { title: "Installed", width: 100, render: (_, r) => html`<span class="ob-mono ob-nowrap">${r.package.version}</span>` },
              { title: "Fix", width: 90, render: (_, r) => r.package.fixed_version ? html`<${Tag} color="green" size="small">${r.package.fixed_version}<//>` : html`<span class="ob-muted ob-nowrap">none</span>` },
              { title: "Found in", render: (_, r) => html`<${FoundIn} loc=${r.package.location} eco=${r.package.ecosystem} placeholder wrap />` },
            ]} noDataElement=${html`<${Empty} description="No longer installed anywhere" />`} />
          <//>
          <${TriageModal} visible=${triage} vuln=${v} onClose=${() => setTriage(false)} onSaved=${() => { q.reload(); onChanged && onChanged(); }} />
        </div>`;
      }}<//>
    <//>`;
  }

  const vulnColumns = (onOpen, withPkgs, onTriage) => [
    { title: "Vulnerability", dataIndex: "vuln_id", width: 210, render: (id) => html`<${VulnLink} id=${id} onOpen=${onOpen} />` },
    { title: "Severity", dataIndex: "severity", width: 105, render: (s) => html`<${SevTag} s=${s} />`,
      sorter: (a, b) => SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity) },
    { title: "CVSS", dataIndex: "cvss_score", width: 70, render: (c) => c ?? html`<span class="ob-muted">—</span>`, sorter: (a, b) => (a.cvss_score || 0) - (b.cvss_score || 0) },
    { title: "EPSS", dataIndex: "epss_score", width: 80, render: (e) => html`<${Epss} v=${e} />`, sorter: (a, b) => (a.epss_score || 0) - (b.epss_score || 0) },
    { title: "Intel", width: 150, render: (_, v) => html`<${Intel} v=${v} />` },
    ...(withPkgs ? [{ title: "Package → fix · path", width: 440, render: (_, v) => html`<div class="ob-occ">${(v.affected_packages || []).map((p) => html`<div key=${p.id} class="ob-occ-item">
      <div class="ob-nowrap"><span class="ob-mono">${p.name}</span> <span class="ob-muted">${p.version}</span>${p.fixed_version ? html` → <${Tag} size="small" color="green">${p.fixed_version}<//>` : null}</div>
      <${FoundIn} loc=${p.location} /></div>`)}</div>` }] : []),
    { title: "Summary", dataIndex: "summary", render: (s) => html`<${Tooltip} content=${s}><span class="ob-clamp">${s}</span><//>` },
    ...(onTriage ? [{ title: "", width: 80, render: (_, v) => html`<${Button} size="mini" onClick=${(e) => { e.stopPropagation(); onTriage(v); }}>Triage<//>` }] : []),
  ];

  function Occurrences({ v }) {
    const occ = v.occurrences || [];
    const extra = Math.max(0, (v.affected_packages || 0) - occ.length);
    return html`<div class="ob-occ">${occ.map((o) => html`<div key=${`${o.hostname}|${o.name}|${o.version}`} class="ob-occ-item">
        <div><span class="ob-mono">${o.name}</span> <span class="ob-muted">${o.version}</span>${o.fixed_version ? html` → <${Tag} size="small" color="green">${o.fixed_version}<//>` : null}
          <span class="ob-muted"> · </span><${HostLink} h=${o.hostname} /></div>
        <${FoundIn} loc=${o.location} eco=${o.ecosystem} placeholder /></div>`)}
      ${extra ? html`<span class="ob-muted">+${extra} more — open for full list</span>` : null}</div>`;
  }
  const vulnListColumns = (onOpen) => {
    const base = vulnColumns(onOpen, false).filter((c) => c.title !== "Summary");
    return [...base,
      { title: "Affected package · asset · path", width: 500, render: (_, v) => html`<${Occurrences} v=${v} />` },
      { title: "Summary", dataIndex: "summary", width: 300, render: (s) => html`<${Tooltip} content=${s}><span class="ob-clamp">${s}</span><//>` },
      { title: "Assets", dataIndex: "affected_assets", width: 80, sorter: (a, b) => a.affected_assets - b.affected_assets },
    ];
  };

  // ------------------------------------------------------------------ pages
  function Overview() {
    const q = useApi("/api/v1/threats/summary");
    return html`<${Loader} q=${q}>${(s) => html`<div>
      <${PageHead} title="Fleet overview" sub="Exposure currently installed across every managed asset, image, repository and imported SBOM." icon=${html`<${I.IconDashboard} />`}
        extra=${html`<${Button} icon=${html`<${I.IconRefresh} />`} onClick=${q.reload}>Refresh<//>`} />
      ${s.malicious_packages ? html`<${Alert} className="ob-hero-alert" type="error" showIcon title=${`${s.malicious_packages} known-malicious package(s) installed`} content="OpenSSF malicious-package advisories matched installed software. Treat affected hosts as compromised." action=${html`<${Button} size="small" status="danger" onClick=${() => go("#/threats/malicious")}>Investigate<//>`} />` : null}
      ${s.kev_vulnerabilities ? html`<${Alert} className="ob-hero-alert" type="warning" showIcon title=${`${s.kev_vulnerabilities} actively exploited vulnerabilit${s.kev_vulnerabilities === 1 ? "y" : "ies"} (CISA KEV)`} content="Already patched? Findings reflect each asset's last pushed scan — re-run the agent on that same target to clear them." action=${html`<${Button} size="small" onClick=${() => go("#/threats/kev")}>View<//>`} />` : null}
      <div class="ob-kpi-grid c5">
        ${[["Assets", s.total_assets, "blue", "#/assets", html`<${I.IconDesktop} />`],
           ["Packages", s.total_packages, "gray", "#/packages", html`<${I.IconApps} />`],
           ["Vulnerabilities", s.total_vulnerabilities, "orange", "#/vulns", html`<${I.IconBug} />`],
           ["Critical", s.critical_vulnerabilities, "red", "#/threats/critical", html`<${I.IconExclamationCircle} />`],
           ["CISA KEV", s.kev_vulnerabilities, "red", "#/threats/kev", html`<${I.IconFire} />`],
           ["Malicious", s.malicious_packages, "magenta", "#/threats/malicious", html`<${I.IconStop} />`],
           ["IOC / Typosquat", s.heuristic_detections, "purple", "#/threats/heuristics", html`<${I.IconScan} />`],
           ["End-of-life", s.eol_assets, "gold", "#/eol", html`<${I.IconCalendarClock} />`],
           ["License violations", s.license_violations, "orange", "#/licenses", html`<${I.IconFile} />`],
           ["Stale assets", s.stale_assets, "gray", "#/assets", html`<${I.IconClockCircle} />`],
          ].map(([t, v, tone, href, icon]) => html`<${Kpi} key=${t} title=${t} value=${v} tone=${tone} icon=${icon} onClick=${() => go(href)} />`)}
      </div>
      <${Row} gutter=${14} className="ob-eq" style=${{ marginTop: 14 }}>
        <${Col} xs=${24} xl=${15} xxl=${16}><${Card} title="Severity distribution" bordered extra=${html`<${Link} onClick=${() => go("#/vulns")}>All vulnerabilities<//>`}>
          <${SevBar} counts=${s.severity_breakdown} />
          <div class="ob-sev-tiles">${SEVS.map((sv) => html`<div key=${sv} class="ob-sev-tile" style=${{ "--tone": SEV_HEX[sv] }} onClick=${() => go(`#/vulns?severity=${sv}`)}>
            <span class="ob-muted">${sv}</span><b>${(s.severity_breakdown?.[sv] || 0).toLocaleString()}</b></div>`)}</div>
        <//><//>
        <${Col} xs=${24} xl=${9} xxl=${8}><${Card} title="Coverage" bordered>
          <${Descriptions} column=${1} size="small" data=${[
            { label: "Scan targets", value: html`<${Space} wrap>${Object.entries(s.target_breakdown || {}).map(([k, v]) => html`<span key=${k}><${TargetTag} t=${k} /> ${v}</span>`)}<//>` },
            { label: "Suppressing decisions", value: s.suppressed_decisions },
            { label: "Stale threshold", value: `${s.stale_after_days} days without a scan` },
          ]} />
        <//><//>
      <//>
      <${Row} gutter=${14} className="ob-eq" style=${{ marginTop: 14 }}>
        <${Col} xs=${24} xl=${14}><${Card} title="Highest-risk assets" bordered extra=${html`<${Link} onClick=${() => go("#/assets?sort=risk")}>All assets<//>`}>
          <${Table} className="ob-click-row" size="small" pagination=${false} rowKey="hostname" data=${s.top_risky_assets} scroll=${{ x: 500 }} onRow=${(r) => ({ onClick: () => go(`#/asset/${enc(r.hostname)}`) })} columns=${[
            { title: "Asset", dataIndex: "hostname", render: (h, r) => html`<${Space}><${TargetTag} t=${r.target_type} /><span class="ob-trunc ob-trunc-sm">${h}</span><//>` },
            { title: "Risk", dataIndex: "risk_score", width: 136, render: (r) => html`<${Risk} score=${r} />` },
            { title: "KEV", dataIndex: "kev_count", width: 58, align: "center", render: (n) => n ? html`<${Tag} color="red" size="small">${n}<//>` : 0 },
            { title: "Malware", dataIndex: "malicious_count", width: 84, align: "center", render: (n) => n ? html`<${Tag} color="magenta" size="small">${n}<//>` : 0 },
            { title: "Crit", dataIndex: "critical", width: 58, align: "center" }]} noDataElement=${html`<${Empty} description="No vulnerable assets" />`} />
        <//><//>
        <${Col} xs=${24} xl=${10}><${Card} title="Packages by ecosystem" bordered>
          ${(() => { const e = Object.entries(s.ecosystem_breakdown).sort((a, b) => b[1] - a[1]); const max = Math.max(1, ...e.map((x) => x[1]));
            return e.length ? html`<div class="ob-eco">${e.map(([k, v]) => html`<div key=${k} class="ob-eco-row"><span class="ob-eco-name">${k}</span>
              <div class="ob-eco-bar"><div style=${{ width: `${Math.max(2, (v / max) * 100)}%` }} /></div><b class="ob-mono">${v.toLocaleString()}</b></div>`)}</div>` : html`<${Empty} />`; })()}
        <//><//>
      <//>
      <${Card} title="Recent scans" bordered style=${{ marginTop: 14 }}>
        <${Table} className="ob-click-row" size="small" pagination=${false} rowKey=${(r) => r.hostname + r.received_at} data=${s.recent_scans} onRow=${(r) => ({ onClick: () => go(`#/asset/${enc(r.hostname)}`) })} columns=${[
          { title: "Asset", dataIndex: "hostname" }, { title: "When", dataIndex: "received_at", width: 120, render: ago },
          { title: "Source", dataIndex: "source", width: 120, render: (x) => html`<${Tag} size="small">${x}<//>` },
          { title: "Packages", dataIndex: "total_packages", width: 110, render: (n) => (n || 0).toLocaleString() },
          { title: "Critical", dataIndex: "critical", width: 90 }, { title: "High", dataIndex: "high", width: 80, render: (n) => n ?? "—" },
          { title: "KEV", dataIndex: "kev_hits", width: 70, render: (n) => n ? html`<${Tag} color="red" size="small">${n}<//>` : 0 }]}
          noDataElement=${html`<${Empty} description="No scans yet — run the agent with --server-url" />`} />
      <//>
    </div>`}<//>`;
  }

  function Assets({ params }) {
    const [q, setQ] = useState(params.get("q") || "");
    const [type, setType] = useState(params.get("type") || "");
    const sort = params.get("sort") || "risk";
    const res = useApi(`/api/v1/assets?limit=1000&sort=${enc(sort)}${params.get("q") ? `&q=${enc(params.get("q"))}` : ""}`);
    const apply = (next = {}) => go(`#/assets?q=${enc(next.q ?? q)}&sort=${enc(next.sort ?? sort)}&type=${enc(next.type ?? type)}`);
    return html`<div>
      <${PageHead} title="Assets" sub="Hosts, container images, repositories and imported SBOMs." icon=${html`<${I.IconDesktop} />`} extra=${html`
        <${Input.Search} allowClear placeholder="Filter by name" value=${q} onChange=${setQ} onSearch=${() => apply()} style=${{ width: 220 }} />
        <${Select} style=${{ width: 140 }} value=${type} onChange=${(v) => { setType(v); apply({ type: v }); }} options=${[{ label: "All types", value: "" }, ...["host", "image", "rootfs", "path", "sbom"].map((t) => ({ label: t, value: t }))]} />
        <${Select} style=${{ width: 150 }} value=${sort} onChange=${(v) => apply({ sort: v })} options=${["risk", "hostname", "last_seen", "packages"].map((s) => ({ label: `Sort: ${s}`, value: s }))} />`} />
      <${Card} bordered><${Loader} q=${res}>${(list) => {
        const rows = list.filter((a) => !type || (a.target_type || "host") === type);
        return html`<${Table} className="ob-click-row" rowKey="hostname" data=${rows} scroll=${{ x: 1100 }} pagination=${{ pageSize: 20, showTotal: true, sizeCanChange: true }}
          onRow=${(r) => ({ onClick: () => go(`#/asset/${enc(r.hostname)}`) })} columns=${[
            { title: "Asset", dataIndex: "hostname", fixed: "left", width: 260, render: (h, a) => html`<div><${Space} size=${6}><${TargetTag} t=${a.target_type} /><b>${h}</b>${a.stale ? html`<${Tag} size="small">STALE<//>` : null}<${EolTag} eol=${a.eol} /><//><div class="ob-muted" style=${{ fontSize: 12 }}>${a.os_name || a.target_ref || ""}</div></div>` },
            { title: "Risk", dataIndex: "risk_score", width: 150, render: (r) => html`<${Risk} score=${r} />` },
            { title: "Packages", dataIndex: "package_count", width: 95 },
            { title: "Crit", width: 65, render: (_, a) => a.severity_counts.CRITICAL || 0 },
            { title: "High", width: 65, render: (_, a) => a.severity_counts.HIGH || 0 },
            { title: "KEV", dataIndex: "kev_count", width: 65, render: (n) => n ? html`<${Tag} color="red" size="small">${n}<//>` : 0 },
            { title: "Malware", dataIndex: "malicious_count", width: 85, render: (n) => n ? html`<${Tag} color="magenta" size="small">${n}<//>` : 0 },
            { title: "IOC", dataIndex: "heuristic_count", width: 65, render: (n) => n ? html`<${Tag} color="purple" size="small">${n}<//>` : 0 },
            { title: "Licenses", dataIndex: "license_violation_count", width: 85, render: (n) => n ? html`<${Tag} color="orange" size="small">${n}<//>` : 0 },
            { title: "Last seen", dataIndex: "last_seen", width: 110, render: ago },
            { title: "Agent", dataIndex: "agent_version", width: 90, render: (v) => html`<span class="ob-mono ob-muted">${v || ""}</span>` },
          ]} noDataElement=${html`<${Empty} description="No assets yet" />`} />`; }}<//><//>
    </div>`;
  }

  function AssetDetail({ hostname, params }) {
    const tab = params.get("tab") || "vulns";
    const q = useApi(`/api/v1/assets/${enc(hostname)}`);
    const [busy, setBusy] = useState(false);
    const [open, setOpen] = useState(null);
    const setTab = (t) => go(`#/asset/${enc(hostname)}?tab=${t}`);
    const reanalyze = async () => {
      setBusy(true);
      try { const r = await api(`/api/v1/assets/${enc(hostname)}/reanalyze`, { method: "POST" }); Message.success(`Re-analysed ${r.packages_checked} packages — ${r.vulnerabilities_linked} vulnerability links`); q.reload(); }
      catch (e) { Message.error(e.message); } finally { setBusy(false); }
    };
    const sbom = async () => { try { download(`cyclonedx_${fileSafe(hostname)}.json`, await api(`/api/v1/assets/${enc(hostname)}/sbom`)); } catch (e) { Message.error(e.message); } };
    const decommission = () => Modal.confirm({
      title: `Decommission ${hostname}?`, content: "Its package links and scan history will be deleted. Packages shared with other assets are kept.",
      okButtonProps: { status: "danger" }, okText: "Decommission",
      onOk: async () => { await api(`/api/v1/assets/${enc(hostname)}`, { method: "DELETE" }); Message.success(`${hostname} removed`); go("#/assets"); },
    });
    return html`<${Loader} q=${q}>${(a) => html`<div>
      <${Breadcrumb} style=${{ marginBottom: 10 }}><${Breadcrumb.Item}><${Link} onClick=${() => go("#/assets")}>Assets<//><//><${Breadcrumb.Item}>${a.hostname}<//><//>
      <${PageHead} title=${html`<${Space}>${a.hostname}<${TargetTag} t=${a.target_type} />${a.stale ? html`<${Tag}>STALE<//>` : null}<${EolTag} eol=${a.eol} /><//>`}
        sub=${`${a.os_name || a.target_ref || "Unknown OS"} · last seen ${ago(a.last_seen)}${a.ip_address ? ` · ${a.ip_address}` : ""}${a.agent_version ? ` · agent ${a.agent_version}` : ""}`}
        extra=${html`<${Button} icon=${html`<${I.IconRefresh} />`} loading=${busy} onClick=${reanalyze}>Re-analyze<//>
          <${Button} icon=${html`<${I.IconDownload} />`} onClick=${sbom}>CycloneDX<//>
          <${Button} status="danger" icon=${html`<${I.IconDelete} />`} onClick=${decommission}>Decommission<//>`} />
      ${a.malicious_count ? html`<${Alert} className="ob-hero-alert" type="error" showIcon title="Known-malicious package installed" content="Remove it immediately and treat this asset as compromised." />` : null}
      <div class="ob-kpi-grid c4">
        <${Card} className="ob-kpi t-red" bordered><div class="arco-statistic-title" style=${{ fontSize: 12, textTransform: "uppercase", color: "var(--color-text-3)" }}>Risk score</div><div style=${{ marginTop: 8 }}><${Risk} score=${a.risk_score} /></div><//>
        ${[["Packages", a.package_count, "gray"], ["Vulnerabilities", a.vulnerability_count, "orange"], ["Critical", a.severity_counts.CRITICAL || 0, "red"],
           ["KEV", a.kev_count, "red"], ["Malware", a.malicious_count, "magenta"], ["IOC", a.heuristic_count, "purple"], ["License violations", a.license_violation_count, "gold"]]
          .map(([t, v, tone]) => html`<${Kpi} key=${t} title=${t} value=${v} tone=${tone} />`)}
      </div>
      <${Card} bordered style=${{ marginTop: 14 }}><${SevBar} counts=${a.severity_counts} /><//>
      <${Card} bordered style=${{ marginTop: 14 }}>
        <${Tabs} activeTab=${tab} onChange=${setTab} lazyload>
          <${TabPane} key="vulns" title="Vulnerabilities"><${AssetVulns} hostname=${hostname} onOpen=${setOpen} onChanged=${q.reload} /><//>
          <${TabPane} key="packages" title="Packages"><${AssetPackages} hostname=${hostname} ecosystems=${Object.keys(a.ecosystem_counts)} /><//>
          <${TabPane} key="licenses" title=${`Licenses${a.license_violation_count ? ` (${a.license_violation_count})` : ""}`}>
            ${a.license_violations.length ? html`<${Table} size="small" rowKey=${(r) => r.package + r.version} data=${a.license_violations} pagination=${{ pageSize: 20 }} columns=${[
              { title: "Package", dataIndex: "package", render: (p) => html`<span class="ob-mono">${p}</span>` }, { title: "Version", dataIndex: "version" },
              { title: "Ecosystem", dataIndex: "ecosystem" }, { title: "License", dataIndex: "license", render: (l) => html`<${Tag} color="orange">${l}<//>` }, { title: "Rule", dataIndex: "rule" }]} />`
              : html`<${Empty} description="No license policy violations reported (agent: --license-deny)" />`}
          <//>
          <${TabPane} key="eol" title="End-of-life">
            ${a.eol.length ? html`<${Table} size="small" rowKey="label" data=${a.eol} pagination=${false} columns=${eolColumns} />` : html`<${Empty} description="No EOL data (agent checks it with --check-osv)" />`}
          <//>
          <${TabPane} key="scans" title="Scan history"><${AssetScans} hostname=${hostname} /><//>
        <//>
      <//>
      <${VulnDrawer} id=${open} onClose=${() => setOpen(null)} onChanged=${q.reload} />
    </div>`}<//>`;
  }

  function AssetVulns({ hostname, onOpen, onChanged }) {
    const [sev, setSev] = useState("");
    const [supp, setSupp] = useState(false);
    const [triage, setTriage] = useState(null);
    const q = useApi(`/api/v1/assets/${enc(hostname)}/vulnerabilities?include_suppressed=${supp}${sev ? `&severity=${enc(sev)}` : ""}`);
    return html`<div>
      <${Space} style=${{ marginBottom: 12 }} wrap>
        <${Select} style=${{ width: 160 }} value=${sev} onChange=${setSev} options=${[{ label: "All severities", value: "" }, ...SEVS.map((s) => ({ label: s, value: s }))]} />
        <${Switch} checked=${supp} onChange=${setSupp} /> <span class="ob-muted">show suppressed (triaged not_affected / false_positive)</span>
      <//>
      <${Loader} q=${q}>${(rows) => html`<${Table} className="ob-click-row" size="small" rowKey="id" data=${rows} scroll=${{ x: 1300 }} pagination=${{ pageSize: 25, showTotal: true }}
        onRow=${(r) => ({ onClick: () => onOpen(r.vuln_id) })} columns=${vulnColumns(onOpen, true, setTriage)} noDataElement=${html`<${Empty} description="No open vulnerabilities" />`} />`}<//>
      <${TriageModal} visible=${!!triage} vuln=${triage} hostname=${hostname} onClose=${() => setTriage(null)} onSaved=${() => { q.reload(); onChanged(); }} />
    </div>`;
  }

  function AssetPackages({ hostname, ecosystems }) {
    const [text, setText] = useState(""); const [eco, setEco] = useState("");
    const q = useApi(`/api/v1/assets/${enc(hostname)}/packages?limit=100000${eco ? `&ecosystem=${enc(eco)}` : ""}`);
    return html`<div>
      <${Space} style=${{ marginBottom: 12 }} wrap>
        <${Input.Search} allowClear placeholder="Filter packages" value=${text} onChange=${setText} style=${{ width: 260 }} />
        <${Select} style=${{ width: 170 }} value=${eco} onChange=${setEco} options=${[{ label: "All ecosystems", value: "" }, ...ecosystems.map((e) => ({ label: e, value: e }))]} />
      <//>
      <${Loader} q=${q}>${(rows) => { const t = text.toLowerCase(); const f = t ? rows.filter((p) => p.name.toLowerCase().includes(t)) : rows;
        return html`<${Table} size="small" rowKey="id" data=${f} pagination=${{ pageSize: 25, showTotal: true, sizeCanChange: true }} columns=${[
          { title: "Name", dataIndex: "name", render: (n) => html`<${Link} onClick=${() => go(`#/packages?name=${enc(n)}&exact=1`)}><span class="ob-mono">${n}</span><//>`, sorter: (a, b) => a.name.localeCompare(b.name) },
          { title: "Version", dataIndex: "version", render: (v) => html`<span class="ob-mono">${v}</span>` },
          { title: "Ecosystem", dataIndex: "ecosystem", render: (e) => html`<${Tag} size="small">${e}<//>` },
          { title: "License", dataIndex: "license", render: (l) => l ? html`<${LicenseTag} l=${l} />` : html`<span class="ob-muted">unknown</span>` },
          { title: "Found in", dataIndex: "location", render: (l) => l ? html`<${FoundIn} loc=${l} />` : html`<span class="ob-muted">—</span>` },
          { title: "purl", dataIndex: "purl", render: (p) => html`<span class="ob-mono ob-muted ob-trunc ob-trunc-sm">${p || ""}</span>` }]} />`; }}<//>
    </div>`;
  }

  function AssetScans({ hostname }) {
    const q = useApi(`/api/v1/assets/${enc(hostname)}/scans?limit=60`);
    return html`<${Loader} q=${q}>${(scans) => { const ordered = scans.slice().reverse(); const max = Math.max(1, ...ordered.map((s) => s.critical + s.high));
      return html`<div>
        ${ordered.length > 1 ? html`<div><div class="ob-muted" style=${{ marginBottom: 6, fontSize: 12 }}>Critical + High per scan (oldest → newest)</div><div class="ob-spark">${ordered.map((s) => html`<${Tooltip} key=${s.id} content=${`${new Date(s.received_at).toLocaleString()}: ${s.critical + s.high}`}><div style=${{ height: `${Math.max(5, ((s.critical + s.high) / max) * 100)}%` }} /><//>`)}</div><${Divider} /></div>` : null}
        <${Table} size="small" rowKey="id" data=${scans} pagination=${{ pageSize: 15 }} scroll=${{ x: 900 }} columns=${[
          { title: "Received", dataIndex: "received_at", render: (t) => new Date(t).toLocaleString() },
          { title: "Source", dataIndex: "source", render: (s) => html`<${Tag} size="small">${s || "agent"}<//>` },
          { title: "Pkgs", dataIndex: "total_packages" }, { title: "Vuln pkgs", render: (_, s) => s.osv_checked ? s.vulnerable_packages : html`<span class="ob-muted">n/a</span>` },
          { title: "Crit", dataIndex: "critical" }, { title: "High", dataIndex: "high" }, { title: "KEV", dataIndex: "kev_hits" },
          { title: "Malware", dataIndex: "malicious_hits" }, { title: "IOC", dataIndex: "heuristic_hits" },
          { title: "+New", dataIndex: "diff_new", render: (v) => v ?? "—" }, { title: "−Removed", dataIndex: "diff_removed", render: (v) => v ?? "—" }]} />
      </div>`; }}<//>`;
  }

  const eolColumns = [
    { title: "Product", dataIndex: "label" },
    { title: "Cycle", dataIndex: "cycle", render: (c) => html`<span class="ob-mono">${c}</span>` },
    { title: "End of life", dataIndex: "eol" },
    { title: "Status", render: (_, e) => e.is_eol ? html`<${Tag} color="red">END OF LIFE<//>` : e.days_left != null && e.days_left <= 180 ? html`<${Tag} color="orange">${e.days_left} days left<//>` : html`<${Tag} color="green">supported<//>` },
    { title: "Latest", dataIndex: "latest", render: (l) => l || "—" },
  ];

  const rescanHint = (a) => {
    const t = a.target_type || "host";
    const target = t === "path" ? `--path ${a.target_ref || "<dir>"}` : t === "image" ? `--image ${a.target_ref || "<image>"}`
      : t === "rootfs" ? `--rootfs ${a.target_ref || "<dir>"}` : t === "sbom" ? `--sbom <file>` : "--check-osv";
    return `Fixed it? Findings stay until this target is scanned again: openbom_agent.py ${target} --server-url ${location.origin}`;
  };

  function Threats({ kind, params }) {
    const [minEpss, setMinEpss] = useState(Number(params.get("min") || 0.1));
    const [open, setOpen] = useState(null);
    const path = kind === "high-epss" ? `/api/v1/threats/high-epss?min_score=${minEpss}` : `/api/v1/threats/${enc(kind)}`;
    const q = useApi(path);
    const tabs = [["malicious", "Malicious packages", html`<${I.IconStop} />`], ["kev", "CISA KEV", html`<${I.IconFire} />`],
                  ["heuristics", "IOC & typosquat", html`<${I.IconScan} />`], ["critical", "Critical", html`<${I.IconExclamationCircle} />`],
                  ["high-epss", "High EPSS", html`<${I.IconThunderbolt} />`]];
    const desc = { malicious: "Packages matching OpenSSF malicious-package advisories (OSV MAL-*). Treat hosts as compromised.",
                   kev: "Vulnerabilities in CISA's Known Exploited Vulnerabilities catalog — being exploited in the wild.",
                   heuristics: "Agent-side detections: obfuscated exec, reverse shells, install-hook downloaders, typosquats.",
                   critical: "CVSS ≥ 9.0 or vendor-rated critical.", "high-epss": "Likely to be exploited in the next 30 days (FIRST EPSS)." };
    return html`<div>
      <${PageHead} title="Threat hunt" sub=${desc[kind]} icon=${html`<${I.IconSafe} />`} extra=${html`<${Button} icon=${html`<${I.IconRefresh} />`} onClick=${q.reload}>Refresh<//>`} />
      <${Tabs} type="card-gutter" activeTab=${kind} onChange=${(k) => go(`#/threats/${k}`)}>
        ${tabs.map(([k, t, icon]) => html`<${TabPane} key=${k} title=${html`<span>${icon} ${t}</span>`} />`)}
      <//>
      ${kind === "high-epss" ? html`<${Card} bordered style=${{ marginBottom: 14 }}><${Space} style=${{ width: "100%" }}><span>Minimum EPSS</span>
        <${Slider} style=${{ width: 260 }} min=${0} max=${1} step=${0.01} value=${minEpss} onChange=${setMinEpss} formatTooltip=${(v) => `${Math.round(v * 100)}%`} />
        <${Tag}>${Math.round(minEpss * 100)}%<//><//><//>` : null}
      <${Loader} q=${q}>${(data) => data.length ? data.map((t) => html`<${Card} key=${t.asset.hostname} bordered style=${{ marginBottom: 14 }}
          title=${html`<${Space}><${TargetTag} t=${t.asset.target_type} /><${HostLink} h=${t.asset.hostname} /><span class="ob-muted">${t.findings.length} finding(s)</span><//>`}
          extra=${html`<${Tooltip} content=${rescanHint(t.asset)}><span class="ob-muted ob-hint"><${I.IconHistory} /> last scan ${ago(t.asset.last_seen)}</span><//>`}>
          <${Table} className="ob-click-row" size="small" rowKey=${(r) => r.vuln_id} pagination=${t.findings.length > 10 ? { pageSize: 10 } : false} scroll=${{ x: 1300 }}
            data=${t.findings.map((f) => ({ ...f.vulnerability, affected_packages: f.affected_packages }))} onRow=${(r) => ({ onClick: () => setOpen(r.vuln_id) })} columns=${vulnColumns(setOpen, true)} />
        <//>`) : html`<${Card} bordered><${Result} status="success" title="Nothing matches" subTitle="No asset currently has findings in this category." /><//>`}<//>
      <${VulnDrawer} id=${open} onClose=${() => setOpen(null)} onChanged=${q.reload} />
    </div>`;
  }

  function Vulns({ params }) {
    const [text, setText] = useState(params.get("q") || "");
    const [sev, setSev] = useState(params.get("severity") || "");
    const [flag, setFlag] = useState(params.get("flag") || "");
    const [supp, setSupp] = useState(false);
    const [open, setOpen] = useState(params.get("open"));
    let qs = `limit=5000&include_suppressed=${supp}${params.get("q") ? `&q=${enc(params.get("q"))}` : ""}${sev ? `&severity=${enc(sev)}` : ""}`;
    if (flag === "kev") qs += "&kev=true"; if (flag === "malicious") qs += "&malicious=true"; if (flag === "ioc") qs += "&heuristic=true"; if (flag === "epss") qs += "&min_epss=0.1";
    const q = useApi(`/api/v1/vulnerabilities?${qs}`);
    useEffect(() => { setOpen(params.get("open")); }, [params.get("open")]);
    const exportCsv = () => q.data && download("openbom_vulnerabilities.csv", toCsv(q.data, [
      ["vuln_id", (v) => v.vuln_id], ["severity", (v) => v.severity], ["cvss", (v) => v.cvss_score], ["epss", (v) => v.epss_score],
      ["kev", (v) => v.is_kev], ["malicious", (v) => v.is_malicious], ["heuristic", (v) => v.is_heuristic], ["cves", (v) => v.cves.join(" ")],
      ["affected_assets", (v) => v.affected_assets], ["triage", (v) => v.triage_state],
      ["found_in", (v) => (v.occurrences || []).map((o) => `${o.hostname}:${o.name}@${o.version}${o.location ? ` (${o.location.replace(/\n/g, "; ")})` : ""}`).join(" | ")],
      ["summary", (v) => v.summary]]), "text/csv");
    return html`<div>
      <${PageHead} title="Vulnerabilities" sub="Every advisory present on at least one asset, highest risk first." icon=${html`<${I.IconBug} />`}
        extra=${html`<${Button} icon=${html`<${I.IconExport} />`} onClick=${exportCsv}>Export CSV<//>`} />
      <${Card} bordered>
        <${Space} style=${{ marginBottom: 12 }} wrap>
          <${Input.Search} allowClear placeholder="ID, CVE or keyword" value=${text} onChange=${setText} onSearch=${(v) => go(`#/vulns?q=${enc(v)}&severity=${enc(sev)}&flag=${enc(flag)}`)} style=${{ width: 260 }} />
          <${Select} style=${{ width: 150 }} value=${sev} onChange=${setSev} options=${[{ label: "All severities", value: "" }, ...SEVS.map((s) => ({ label: s, value: s }))]} />
          <${Select} style=${{ width: 160 }} value=${flag} onChange=${setFlag} options=${[{ label: "Any intel", value: "" }, { label: "Malicious only", value: "malicious" }, { label: "KEV only", value: "kev" }, { label: "IOC only", value: "ioc" }, { label: "EPSS ≥ 10%", value: "epss" }]} />
          <${Switch} checked=${supp} onChange=${setSupp} /><span class="ob-muted">include suppressed</span>
        <//>
        <${Loader} q=${q}>${(rows) => html`<${Table} className="ob-click-row" size="small" rowKey="id" data=${rows} scroll=${{ x: 1400 }} pagination=${{ pageSize: 25, showTotal: true, sizeCanChange: true }}
          onRow=${(r) => ({ onClick: () => setOpen(r.vuln_id) })} columns=${vulnListColumns(setOpen)} />`}<//>
      <//>
      <${VulnDrawer} id=${open} onClose=${() => { setOpen(null); if (params.get("open")) history.replaceState(null, "", "#/vulns"); }} onChanged=${q.reload} />
    </div>`;
  }

  function Packages({ params }) {
    const [form] = Form.useForm();
    const name = params.get("name") || "";
    const query = name ? `/api/v1/packages/search?name=${enc(name)}${params.get("version") ? `&version=${enc(params.get("version"))}` : ""}${params.get("eco") ? `&ecosystem=${enc(params.get("eco"))}` : ""}${params.get("exact") === "1" ? "&exact=true" : ""}` : null;
    const q = useApi(query);
    useEffect(() => { form.setFieldsValue({ name, version: params.get("version") || "", eco: params.get("eco") || "", exact: params.get("exact") === "1" }); }, [query]);
    const submit = (v) => go(`#/packages?name=${enc(v.name || "")}&version=${enc(v.version || "")}&eco=${enc(v.eco || "")}&exact=${v.exact ? 1 : 0}`);
    return html`<div>
      <${PageHead} title="Package search" sub="Which assets have a given package installed right now? e.g. xz, log4j-core, event-stream, polyfill" icon=${html`<${I.IconSearch} />`} />
      <${Card} bordered style=${{ marginBottom: 14 }}>
        <${Form} form=${form} layout="inline" onSubmit=${submit}>
          <${Form.Item} field="name" rules=${[{ required: true, message: "name required" }]}><${Input} placeholder="Package name" style=${{ width: 240 }} allowClear /><//>
          <${Form.Item} field="version"><${Input} placeholder="Exact version (optional)" style=${{ width: 200 }} allowClear /><//>
          <${Form.Item} field="eco"><${Select} placeholder="Any ecosystem" style=${{ width: 170 }} allowClear options=${["RPM", "Debian", "Alpine", "PyPI", "NPM", "Go", "Maven", "Cargo", "RubyGems", "Packagist", "NuGet"]} /><//>
          <${Form.Item} field="exact" triggerPropName="checked"><${Switch} checkedText="exact" uncheckedText="contains" /><//>
          <${Form.Item}><${Button} type="primary" htmlType="submit" icon=${html`<${I.IconSearch} />`}>Search<//><//>
        <//>
      <//>
      <${Card} bordered>${!name ? html`<${Empty} description="Enter a package name to hunt across the fleet" />` : html`<${Loader} q=${q}>${(rows) => html`<${Table} size="small" rowKey=${(r) => r.package.id} data=${rows} pagination=${{ pageSize: 25 }} columns=${[
          { title: "Package", render: (_, r) => html`<span class="ob-mono">${r.package.name}</span>` },
          { title: "Version", render: (_, r) => html`<span class="ob-mono">${r.package.version}</span>` },
          { title: "Ecosystem", render: (_, r) => html`<${Tag} size="small">${r.package.ecosystem}<//>` },
          { title: "License", render: (_, r) => r.package.license ? html`<${LicenseTag} l=${r.package.license} />` : html`<span class="ob-muted">—</span>` },
          { title: "Vulns", render: (_, r) => r.vulnerability_count ? html`<${Space}><${SevTag} s=${r.max_severity} />${r.vulnerability_count}<//>` : html`<span class="ob-muted">0</span>` },
          { title: "Assets · path", render: (_, r) => html`<div class="ob-occ">${(r.locations && r.locations.length ? r.locations : r.hosts.map((h) => ({ hostname: h })))
              .map((h) => html`<div key=${h.hostname} class="ob-occ-item"><${Tag} size="small" color="arcoblue" style=${{ cursor: "pointer" }} onClick=${() => go(`#/asset/${enc(h.hostname)}`)}>${h.hostname}<//><${FoundIn} loc=${h.location} eco=${r.package.ecosystem} placeholder /></div>`)}</div>` }]}
          noDataElement=${html`<${Empty} description="No asset has a matching package" />`} />`}<//>`}<//>
    </div>`;
  }

  const licenseRisk = (l) => {
    const u = String(l).toUpperCase();
    if (/(^|[^L])AGPL|SSPL|^GPL|[ (]GPL|EUPL|OSL-|CC-BY-NC/.test(u) && !/LGPL/.test(u) || /^GPL/.test(u)) return ["red", "strong copyleft"];
    if (/LGPL|MPL|EPL|CDDL|CPL/.test(u)) return ["orange", "weak copyleft"];
    if (u === "UNKNOWN") return ["gray", "unknown"];
    if (/MIT|BSD|APACHE|ISC|ZLIB|PSF|UNLICENSE|0BSD|CC0|PUBLIC|PYTHON|HPND/.test(u)) return ["green", "permissive"];
    return ["arcoblue", "other"];
  };
  const LicenseTag = ({ l }) => html`<${Tag} size="small" color=${licenseRisk(l)[0]}>${l}<//>`;

  function Licenses() {
    const q = useApi("/api/v1/licenses");
    const [sel, setSel] = useState(null);
    const [filter, setFilter] = useState("");
    const pk = useApi(sel ? `/api/v1/licenses/packages?license=${enc(sel)}` : null);
    return html`<div>
      <${PageHead} title="License compliance" sub="Licenses of every installed component. Enforce policy in CI with the agent's --license-deny." icon=${html`<${I.IconFile} />`} />
      <${Loader} q=${q}>${(rows) => {
        const cats = {}; rows.forEach((r) => { const c = licenseRisk(r.license)[1]; cats[c] = (cats[c] || 0) + r.packages; });
        const shown = filter ? rows.filter((r) => licenseRisk(r.license)[1] === filter) : rows;
        return html`<div>
          <div class="ob-kpi-grid c5" style=${{ marginBottom: 14 }}>
            ${[["permissive", "green"], ["weak copyleft", "orange"], ["strong copyleft", "red"], ["unknown", "gray"], ["other", "blue"]].map(([c, tone]) => html`<${Kpi} key=${c} title=${c} value=${cats[c] || 0} tone=${tone} onClick=${() => setFilter(filter === c ? "" : c)} />`)}
          </div>
          <${Card} bordered title=${filter ? `Licenses — ${filter}` : "All licenses"} extra=${filter ? html`<${Link} onClick=${() => setFilter("")}>Clear filter<//>` : null}>
            <${Table} className="ob-click-row" size="small" rowKey="license" data=${shown} pagination=${{ pageSize: 25, showTotal: true }} onRow=${(r) => ({ onClick: () => setSel(r.license) })} columns=${[
              { title: "License", dataIndex: "license", render: (l) => html`<${LicenseTag} l=${l} />` },
              { title: "Category", render: (_, r) => licenseRisk(r.license)[1] },
              { title: "Packages", dataIndex: "packages", sorter: (a, b) => a.packages - b.packages },
              { title: "Assets", dataIndex: "assets", sorter: (a, b) => a.assets - b.assets }]} />
          <//>
        </div>`; }}<//>
      <${Drawer} width=${640} visible=${!!sel} title=${html`<span>Packages under <${LicenseTag} l=${sel || ""} /></span>`} onCancel=${() => setSel(null)} footer=${null} unmountOnExit>
        <${Loader} q=${pk}>${(rows) => html`<${Table} size="small" rowKey=${(r) => r.package.id} data=${rows} pagination=${{ pageSize: 20 }} columns=${[
          { title: "Package", render: (_, r) => html`<span class="ob-mono">${r.package.name}</span>` }, { title: "Version", render: (_, r) => r.package.version },
          { title: "Ecosystem", render: (_, r) => r.package.ecosystem }, { title: "Assets", render: (_, r) => r.hosts.join(", ") }]} />`}<//>
      <//>
    </div>`;
  }

  function Eol() {
    const q = useApi("/api/v1/eol");
    return html`<div>
      <${PageHead} title="End-of-life software" sub="Operating systems and runtimes past (or near) vendor end-of-life — they stop receiving security fixes. Data: endoflife.date." icon=${html`<${I.IconCalendarClock} />`} />
      <${Card} bordered><${Loader} q=${q}>${(rows) => html`<${Table} rowKey="hostname" data=${rows} pagination=${{ pageSize: 25 }} columns=${[
        { title: "Asset", dataIndex: "hostname", render: (h, r) => html`<${Space}><${TargetTag} t=${r.target_type} /><${HostLink} h=${h} /><//>` },
        { title: "Products", render: (_, r) => html`<div>${r.eol.map((e) => html`<div key=${e.label} style=${{ marginBottom: 4 }}>${e.is_eol ? html`<${Tag} color="red" size="small">EOL<//>` : e.days_left != null && e.days_left <= 180 ? html`<${Tag} color="orange" size="small">${e.days_left}d<//>` : html`<${Tag} color="green" size="small">OK<//>`} ${e.label} <span class="ob-muted">— ${e.eol}</span></div>`)}</div>` }]}
        noDataElement=${html`<${Empty} description="No EOL data yet — agents report it during --check-osv scans" />`} />`}<//><//>
    </div>`;
  }

  function TriagePage() {
    const q = useApi("/api/v1/triage");
    const [busy, setBusy] = useState(false);
    const exportVex = async () => { try { download(`openbom_openvex_${new Date().toISOString().slice(0, 10)}.json`, await api("/api/v1/vex")); } catch (e) { Message.error(e.message); } };
    const importVex = (file) => { const r = new FileReader(); r.onload = async () => {
      setBusy(true);
      try { const res = await api("/api/v1/vex", { method: "POST", json: JSON.parse(r.result) }); Message.success(`VEX imported: ${res.applied} applied, ${res.skipped} skipped`); q.reload(); }
      catch (e) { Message.error(e instanceof SyntaxError ? "Not a JSON file" : e.message); } finally { setBusy(false); } }; r.readAsText(file); return false; };
    return html`<div>
      <${PageHead} title="Triage & VEX" sub="Analyst decisions. not_affected / false_positive suppress findings fleet-wide or per asset, and round-trip as OpenVEX." icon=${html`<${I.IconCheckCircle} />`}
        extra=${html`<${Upload} accept=".json,application/json" showUploadList=${false} beforeUpload=${importVex}><${Button} loading=${busy} icon=${html`<${I.IconImport} />`}>Import OpenVEX<//><//>
          <${Button} type="primary" icon=${html`<${I.IconExport} />`} onClick=${exportVex}>Export OpenVEX<//>`} />
      <${Card} bordered><${Loader} q=${q}>${(rows) => html`<${Table} size="small" rowKey="id" data=${rows} pagination=${{ pageSize: 25 }} scroll=${{ x: 900 }} columns=${[
        { title: "Vulnerability", dataIndex: "vuln_id", render: (id) => html`<${VulnLink} id=${id} />` },
        { title: "Scope", dataIndex: "hostname", render: (h) => h ? html`<${HostLink} h=${h} />` : html`<${Tag} size="small" color="arcoblue">fleet-wide<//>` },
        { title: "State", dataIndex: "state", render: (s) => html`<${Tag} color=${TRIAGE_COLOR[s]}>${s}<//>` },
        { title: "Justification", dataIndex: "justification", render: (j) => j ? html`<span class="ob-mono">${j}</span>` : "—" },
        { title: "Notes", dataIndex: "detail", render: (d) => html`<span class="ob-trunc">${d || ""}</span>` },
        { title: "Author", dataIndex: "author" }, { title: "Updated", dataIndex: "updated_at", render: ago },
        { title: "", width: 90, render: (_, r) => html`<${Popconfirm} title="Remove this decision?" onOk=${async () => { try { await api(`/api/v1/triage/${r.id}`, { method: "DELETE" }); Message.success("Removed"); q.reload(); } catch (e) { Message.error(e.message); } }}><${Button} size="mini" status="danger">Remove<//><//>` }]}
        noDataElement=${html`<${Empty} description="No decisions yet — triage findings from any vulnerability view" />`} />`}<//><//>
    </div>`;
  }

  function SbomImport() {
    const [doc, setDoc] = useState(null); const [fileName, setFileName] = useState("");
    const [hostname, setHostname] = useState(""); const [analyze, setAnalyze] = useState(true);
    const [busy, setBusy] = useState(false); const [result, setResult] = useState(null); const [fleetBusy, setFleetBusy] = useState(false);
    const pick = (file) => { const r = new FileReader(); r.onload = () => {
      try { const d = JSON.parse(r.result); if (!d.bomFormat && !d.spdxVersion) throw new Error("Not a CycloneDX or SPDX JSON document"); setDoc(d); setFileName(file.name); setResult(null);
        setHostname(d.metadata?.component?.name || d.name || file.name.replace(/\.json$/, "")); }
      catch (e) { Message.error(e.message); } }; r.readAsText(file); return false; };
    const upload = async () => { setBusy(true);
      try { const r = await api(`/api/v1/sbom?analyze=${analyze}${hostname ? `&hostname=${enc(hostname)}` : ""}`, { method: "POST", json: doc }); setResult(r); Message.success("SBOM imported"); }
      catch (e) { Message.error(e.message); } finally { setBusy(false); } };
    const fleet = () => Modal.confirm({ title: "Re-analyse the whole fleet?", content: "Every stored inventory is re-matched against OSV, EPSS and CISA KEV. This can take a while for large fleets.",
      onOk: async () => { setFleetBusy(true); try { const r = await api("/api/v1/reanalyze", { method: "POST" }); Message.success(`${r.assets} assets, ${r.packages_checked} packages re-analysed`); } catch (e) { Message.error(e.message); } finally { setFleetBusy(false); } } });
    return html`<div>
      <${PageHead} title="SBOM import & continuous monitoring" sub="Bring SBOMs from any generator (Syft, Trivy, cdxgen, Microsoft sbom-tool, GitHub dependency graph) and keep them monitored." icon=${html`<${I.IconUpload} />`} />
      <${Row} gutter=${14}>
        <${Col} xs=${24} lg=${14}><${Card} bordered title="Upload SBOM">
          <${Upload} className="ob-upload" drag accept=".json,application/json" showUploadList=${false} beforeUpload=${pick} tip="CycloneDX 1.4–1.6 or SPDX 2.x JSON. Components need purls." />
          ${doc ? html`<div style=${{ marginTop: 16 }}>
            <${Descriptions} column=${1} size="small" border data=${[
              { label: "File", value: fileName }, { label: "Format", value: doc.bomFormat ? `CycloneDX ${doc.specVersion || ""}` : doc.spdxVersion },
              { label: "Components", value: (doc.components || doc.packages || []).length }]} />
            <${Space} direction="vertical" style=${{ width: "100%", marginTop: 14 }}>
              <${Input} addBefore="Asset name" value=${hostname} onChange=${setHostname} />
              <${Space}><${Switch} checked=${analyze} onChange=${setAnalyze} /><span>Run OSV / EPSS / KEV analysis on the server</span><//>
              <${Button} type="primary" long loading=${busy} icon=${html`<${I.IconUpload} />`} onClick=${upload}>Import<//>
            <//>
          </div>` : null}
          ${result ? html`<${Result} status="success" title=${`Imported as ${result.hostname}`} subTitle=${`${result.packages_processed} packages · ${result.vulnerabilities_linked} vulnerability links`}
            extra=${html`<${Button} type="primary" onClick=${() => go(`#/asset/${enc(result.hostname)}`)}>Open asset<//>`} />` : null}
        <//><//>
        <${Col} xs=${24} lg=${10}><${Card} bordered title="Continuous monitoring">
          <${Typography.Paragraph}>New advisories are published every day. Re-analysis re-matches every stored inventory against fresh OSV, EPSS and KEV data — no agent rerun needed.<//>
          <${Typography.Paragraph}>Automate it with <span class="ob-mono">OPENBOM_REANALYZE_HOURS=24</span> on the server.<//>
          <${Button} long icon=${html`<${I.IconRefresh} />`} loading=${fleetBusy} onClick=${fleet}>Re-analyse entire fleet now<//>
          <${Divider} />
          <div class="ob-muted" style=${{ marginBottom: 6 }}>Generate an SBOM with other tools:</div>
          <${Typography.Paragraph} copyable className="ob-code ob-mono">syft registry.example/app:1.0 -o cyclonedx-json=app.cdx.json<//>
          <${Typography.Paragraph} copyable className="ob-code ob-mono">trivy image --format spdx-json -o app.spdx.json app:1.0<//>
        <//><//>
      <//>
    </div>`;
  }

  function Reports() {
    const assets = useApi("/api/v1/assets?limit=1000&sort=hostname");
    const [host, setHost] = useState("");
    const grab = async (fn, name) => { try { download(name, await fn()); } catch (e) { Message.error(e.message); } };
    const assetsCsv = () => assets.data && download("openbom_assets.csv", toCsv(assets.data, [
      ["asset", (a) => a.hostname], ["type", (a) => a.target_type || "host"], ["os", (a) => a.os_name], ["risk", (a) => a.risk_score],
      ["packages", (a) => a.package_count], ["vulnerabilities", (a) => a.vulnerability_count], ["critical", (a) => a.severity_counts.CRITICAL],
      ["high", (a) => a.severity_counts.HIGH], ["kev", (a) => a.kev_count], ["malicious", (a) => a.malicious_count],
      ["license_violations", (a) => a.license_violation_count], ["eol", (a) => (a.eol || []).some((e) => e.is_eol)], ["last_seen", (a) => a.last_seen]]), "text/csv");
    const items = [
      { t: "Asset SBOM (CycloneDX 1.5)", d: "Components + vulnerabilities for one asset.", icon: html`<${I.IconStorage} />`,
        body: html`<${Space} wrap><${Select} showSearch placeholder="Select asset" style=${{ width: 260 }} value=${host || undefined} onChange=${setHost} options=${(assets.data || []).map((a) => a.hostname)} />
          <${Button} type="primary" disabled=${!host} icon=${html`<${I.IconDownload} />`} onClick=${() => grab(() => api(`/api/v1/assets/${enc(host)}/sbom`), `cyclonedx_${fileSafe(host)}.json`)}>Download<//><//>` },
      { t: "OpenVEX statements", d: "All triage decisions as an OpenVEX 0.2.0 document.", icon: html`<${I.IconCheckCircle} />`,
        body: html`<${Button} icon=${html`<${I.IconDownload} />`} onClick=${() => grab(() => api("/api/v1/vex"), "openbom_openvex.json")}>Download<//>` },
      { t: "Fleet inventory (CSV)", d: "Risk, counts, EOL and license status for every asset.", icon: html`<${I.IconDesktop} />`,
        body: html`<${Button} icon=${html`<${I.IconDownload} />`} onClick=${assetsCsv} disabled=${!assets.data}>Download<//>` },
      { t: "Vulnerabilities (CSV)", d: "Use the Export button on the Vulnerabilities page (respects filters).", icon: html`<${I.IconBug} />`,
        body: html`<${Button} onClick=${() => go("#/vulns")}>Open Vulnerabilities<//>` },
      { t: "Threat summary (JSON)", d: "Raw fleet statistics for SIEM / ticketing pipelines.", icon: html`<${I.IconCode} />`,
        body: html`<${Button} icon=${html`<${I.IconDownload} />`} onClick=${() => grab(() => api("/api/v1/threats/summary"), "openbom_summary.json")}>Download<//>` },
    ];
    return html`<div>
      <${PageHead} title="Reports & export" sub="Machine-readable exports for auditors, customers and downstream tools. Agents additionally write SPDX 2.3, SARIF and HTML/PDF reports locally." icon=${html`<${I.IconCloudDownload} />`} />
      <${Row} gutter=${[14, 14]}>${items.map((it) => html`<${Col} key=${it.t} xs=${24} md=${12} xl=${8}><${Card} bordered style=${{ height: "100%" }} title=${html`<${Space}>${it.icon}${it.t}<//>`}>
        <div class="ob-muted" style=${{ marginBottom: 12, minHeight: 40 }}>${it.d}</div>${it.body}<//><//>`)}<//>
    </div>`;
  }

  function AgentSetup() {
    const server = location.origin;
    const cmds = [
      ["Install", "pip install -r requirements.txt"],
      ["Interactive menu", "python3 agent/openbom_agent.py"],
      ["Hunt this host & push here", `python3 agent/openbom_agent.py --check-osv --diff --server-url ${server} --api-key $OPENBOM_API_KEY`],
      ["Scan a container image", `python3 agent/openbom_agent.py --image nginx:1.25 --server-url ${server}`],
      ["Scan a repository (CI)", "python3 agent/openbom_agent.py --path . --sarif openbom.sarif --license-deny GPL-3.0,AGPL --fail-on high"],
      ["Analyse a Syft/Trivy SBOM", "python3 agent/openbom_agent.py --sbom app.cdx.json --spdx app.spdx.json"],
      ["Suppress with VEX / ignore", "python3 agent/openbom_agent.py --path . --vex openvex.json --ignore .openbomignore"],
      ["Schedule (cron, daily)", `0 3 * * * cd /opt/openbom && python3 agent/openbom_agent.py --check-osv --diff --server-url ${server} >> /var/log/openbom.log 2>&1`],
    ];
    return html`<div>
      <${PageHead} title="Agent setup" sub="Deploy the single-file agent on endpoints, in CI, or against images and SBOMs." icon=${html`<${I.IconCode} />`} />
      <${Row} gutter=${14}>
        <${Col} xs=${24} xl=${15}><${Card} bordered title="Commands">${cmds.map(([t, c]) => html`<div key=${t} style=${{ marginBottom: 14 }}><div style=${{ fontWeight: 600, marginBottom: 4 }}>${t}</div><${Typography.Paragraph} copyable className="ob-code ob-mono" style=${{ marginBottom: 0 }}>${c}<//></div>`)}<//><//>
        <${Col} xs=${24} xl=${9}><${Card} bordered title="Coverage">
          <${Descriptions} column=${1} size="small" data=${[
            { label: "OS packages", value: "RPM, dpkg, apk (host, containers, images, rootfs)" },
            { label: "OSV distros", value: "Debian, Ubuntu, AlmaLinux, Rocky, Alpine" },
            { label: "Languages", value: "PyPI, npm/yarn/pnpm, Go, Cargo, RubyGems, Composer, NuGet, Maven/Gradle, JAR/WAR" },
            { label: "Intel", value: "OSV, OpenSSF malicious packages, CISA KEV, EPSS, PoC links, endoflife.date, deps.dev" },
            { label: "Detection", value: "Heuristic IOC (install hooks, obfuscation, reverse shells), typosquatting" },
            { label: "Formats out", value: "JSON, CycloneDX 1.5, SPDX 2.3, SARIF 2.1, OpenVEX, HTML/PDF, CSV" },
            { label: "Formats in", value: "CycloneDX, SPDX, OpenVEX, CycloneDX VEX" },
          ]} />
        <//><//>
      <//>
    </div>`;
  }

  function Settings({ onAuth }) {
    const [key, setKey] = useState(store.get("openbom_api_key"));
    const health = useApi("/health");
    const [msg, setMsg] = useState(null);
    const save = async () => { store.set("openbom_api_key", key.trim()); try { await api("/api/v1/assets?limit=1"); setMsg({ type: "success", text: "Key accepted." }); onAuth(); } catch (e) { setMsg({ type: "error", text: e.message }); } };
    const prune = () => Modal.confirm({ title: "Prune orphaned records?", content: "Deletes packages no asset has installed and vulnerabilities no package references.",
      onOk: async () => { const r = await api("/api/v1/maintenance/prune", { method: "POST" }); Message.success(`Deleted ${r.packages_deleted} packages, ${r.vulnerabilities_deleted} vulnerabilities`); } });
    return html`<div>
      <${PageHead} title="Settings" sub="Stored only in this browser." icon=${html`<${I.IconSettings} />`} />
      <${Row} gutter=${[14, 14]}>
        <${Col} xs=${24} lg=${12}><${Card} bordered title="API key">
          <div class="ob-muted" style=${{ marginBottom: 10 }}>Server authentication: <b>${health.data ? (health.data.auth_required ? "required" : "disabled (OPENBOM_API_KEY not set)") : "…"}</b></div>
          <${Space} direction="vertical" style=${{ width: "100%" }}>
            <${Input.Password} value=${key} onChange=${setKey} placeholder="X-API-Key" onPressEnter=${save} />
            <${Space}><${Button} type="primary" onClick=${save}>Save & test<//><${Button} onClick=${() => { setKey(""); store.set("openbom_api_key", ""); setMsg({ type: "info", text: "Cleared." }); }}>Clear<//><//>
            ${msg ? html`<${Alert} type=${msg.type} content=${msg.text} />` : null}
          <//>
        <//><//>
        <${Col} xs=${24} lg=${12}><${Card} bordered title="Server">
          <${Descriptions} column=${1} size="small" data=${[
            { label: "Status", value: health.data ? html`<${Badge} status="success" text=${health.data.status} />` : html`<${Badge} status="error" text="unreachable" />` },
            { label: "Version", value: health.data?.version || "—" },
            { label: "API documentation", value: html`<${Link} href="/docs" target="_blank">/docs<//>` }]} />
          <${Divider} />
          <${Button} status="warning" icon=${html`<${I.IconDelete} />`} onClick=${prune}>Prune orphaned records<//>
        <//><//>
      <//>
    </div>`;
  }

  // ------------------------------------------------------------------ shell
  const MENU = [
    { group: "Monitor", items: [["overview", "Overview", I.IconDashboard], ["assets", "Assets", I.IconDesktop]] },
    { group: "Hunt", items: [["threats", "Threat Hunt", I.IconSafe, [["malicious", "Malicious packages"], ["kev", "CISA KEV"], ["heuristics", "IOC & typosquat"], ["critical", "Critical"], ["high-epss", "High EPSS"]]],
                             ["vulns", "Vulnerabilities", I.IconBug], ["packages", "Package Search", I.IconSearch]] },
    { group: "Govern", items: [["licenses", "Licenses", I.IconFile], ["eol", "End-of-Life", I.IconCalendarClock], ["triage", "Triage & VEX", I.IconCheckCircle]] },
    { group: "Data", items: [["sbom", "SBOM Import", I.IconUpload], ["reports", "Reports & Export", I.IconCloudDownload], ["agent", "Agent Setup", I.IconCode], ["settings", "Settings", I.IconSettings]] },
  ];
  const TITLES = { overview: "Overview", assets: "Assets", asset: "Asset", threats: "Threat Hunt", vulns: "Vulnerabilities", packages: "Package Search", licenses: "Licenses", eol: "End-of-Life", triage: "Triage & VEX", sbom: "SBOM Import", reports: "Reports & Export", agent: "Agent Setup", settings: "Settings" };

  function App() {
    const route = useRoute();
    const [collapsed, setCollapsed] = useState(window.innerWidth < 1000);
    const [dark, setDark] = useState(store.get("openbom_theme", "dark") === "dark");
    const [authTick, setAuthTick] = useState(0);
    const health = useApi("/health", [authTick]);
    useEffect(() => { dark ? document.body.setAttribute("arco-theme", "dark") : document.body.removeAttribute("arco-theme"); store.set("openbom_theme", dark ? "dark" : "light"); }, [dark]);
    const [page, ...rest] = route.parts.length ? route.parts : ["overview"];
    const selected = page === "asset" ? "assets" : page === "threats" ? `threats/${rest[0] || "kev"}` : page;
    const onSearch = (v) => { v = (v || "").trim(); if (!v) return; if (/^(CVE|GHSA|PYSEC|MAL|RUSTSEC|GO|DEBIAN|UBUNTU|ALSA|RLSA|ALPINE)-/i.test(v)) go(`#/vulns?q=${enc(v)}`); else go(`#/packages?name=${enc(v)}`); };
    let body;
    switch (page) {
      case "assets": body = html`<${Assets} key=${location.hash} params=${route.params} />`; break;
      case "asset": body = html`<${AssetDetail} key=${rest.join("/")} hostname=${rest.join("/")} params=${route.params} />`; break;
      case "threats": body = html`<${Threats} key=${rest[0]} kind=${rest[0] || "kev"} params=${route.params} />`; break;
      case "vulns": body = html`<${Vulns} params=${route.params} />`; break;
      case "packages": body = html`<${Packages} params=${route.params} />`; break;
      case "licenses": body = html`<${Licenses} />`; break;
      case "eol": body = html`<${Eol} />`; break;
      case "triage": body = html`<${TriagePage} />`; break;
      case "sbom": body = html`<${SbomImport} />`; break;
      case "reports": body = html`<${Reports} />`; break;
      case "agent": body = html`<${AgentSetup} />`; break;
      case "settings": body = html`<${Settings} onAuth=${() => setAuthTick((t) => t + 1)} />`; break;
      default: body = html`<${Overview} />`;
    }
    return html`<${Layout} className="ob-layout" hasSider>
      <${Sider} className="ob-sider" collapsible collapsed=${collapsed} onCollapse=${setCollapsed} width=${236} collapsedWidth=${64} breakpoint="lg" trigger=${null}>
        <div class="ob-logo" onClick=${() => go("#/overview")} title="OpenBOM">
          <img class="ob-mark" src="/static/logo.svg" alt="OpenBOM" />
          ${collapsed ? null : html`<div class="ob-wordmark"><div class="ob-name"><span>Open</span><b>BOM</b></div><div class="ob-tag">Supply chain threat hunter</div></div>`}
        </div>
        <${Menu} theme="dark" selectedKeys=${[selected]} defaultOpenKeys=${["threats"]} autoOpen onClickMenuItem=${(k) => go(`#/${k}`)} style=${{ width: "100%" }}>
          ${MENU.map((g) => html`<${Menu.ItemGroup} key=${g.group} title=${collapsed ? "" : g.group}>
            ${g.items.map(([k, label, Icon, sub]) => sub
              ? html`<${Menu.SubMenu} key=${k} title=${html`<span><${Icon} />${label}</span>`}>${sub.map(([sk, sl]) => html`<${Menu.Item} key=${`${k}/${sk}`}>${sl}<//>`)}<//>`
              : html`<${Menu.Item} key=${k}><${Icon} />${label}<//>`)}
          <//>`)}
        <//>
        ${!collapsed ? html`<div class="ob-sider-foot">backend ${health.data?.version || "…"}${health.data?.auth_required ? " · auth on" : ""}</div>` : null}
      <//>
      <${Layout}>
        <${Header} className="ob-header">
          <${Button} shape="circle" type="text" icon=${collapsed ? html`<${I.IconMenuUnfold} />` : html`<${I.IconMenuFold} />`} onClick=${() => setCollapsed(!collapsed)} />
          <${Breadcrumb} className="ob-hide-sm"><${Breadcrumb.Item}>OpenBOM<//><${Breadcrumb.Item}>${TITLES[page] || "Overview"}<//><//>
          <div class="ob-grow" />
          <${Input.Search} allowClear placeholder="Search package or CVE / GHSA / MAL id…" style=${{ maxWidth: 340 }} onSearch=${onSearch} />
          <${Tooltip} content=${health.error ? "Backend unreachable" : health.data?.auth_required ? "Authentication enabled" : "API is unauthenticated"}>
            <${Badge} status=${health.error ? "error" : health.data?.auth_required ? "success" : "warning"} />
          <//>
          <${Tooltip} content=${dark ? "Light theme" : "Dark theme"}><${Button} shape="circle" type="text" icon=${dark ? html`<${I.IconSunFill} />` : html`<${I.IconMoonFill} />`} onClick=${() => setDark(!dark)} /><//>
          <${Tooltip} content="API docs"><${Button} shape="circle" type="text" icon=${html`<${I.IconQuestionCircle} />`} href="/docs" target="_blank" /><//>
        <//>
        <${Content} className="ob-content"><div class="ob-page" key=${route.parts.join("/") || "overview"}>${body}</div><//>
      <//>
    <//>`;
  }

  ReactDOM.createRoot(document.getElementById("root")).render(
    html`<${arco.ConfigProvider} locale=${window.arcoLocaleEnUS} componentConfig=${{ Table: { border: false } }}><${App} /><//>`);
})();
