#!/usr/bin/env python3
"""Generate an offline dashboard for the latest Multi-IdP audit or a selected JSON file."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def validate_audit(data):
    """Reject incompatible reports before displaying them as an audit."""
    if not isinstance(data, dict):
        raise ValueError("Audit must be a JSON object")
    for key in ("runId", "utc"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise ValueError(f"Audit {key} must be a nonempty string")
    for key in ("tests", "milestones", "installations"):
        if not isinstance(data.get(key), dict):
            raise ValueError(f"Audit {key} must be an object")
        for name, record in data[key].items():
            if not isinstance(record, dict):
                raise ValueError(f"Audit {key}.{name} must be an object")
    for name, record in data["tests"].items():
        if "status" in record and not isinstance(record["status"], str):
            raise ValueError(f"Test {name} status must be a string")
    for name, record in data["milestones"].items():
        required = record.get("requiredTests", [])
        if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
            raise ValueError(f"Milestone {name} requiredTests must be a list of test IDs")
        if "status" in record and not isinstance(record["status"], str):
            raise ValueError(f"Milestone {name} status must be a string")
    if "complete" in data and not isinstance(data["complete"], bool):
        raise ValueError("Audit complete must be a boolean")
    if not isinstance(data.get("environmentChecks", {}), dict):
        raise ValueError("Audit environmentChecks must be an object")
    return data


def latest_audit(directory):
    """Select the newest available audit by filesystem modification time."""
    candidates = [path for path in directory.glob("audit-*.json") if path.is_file()]
    if not candidates:
        raise ValueError(f"No audit-*.json files in {directory}. Run full acceptance or supply an audit file.")
    return max(candidates, key=lambda path: (path.stat().st_mtime_ns, path.name))


def render_dashboard(data, source):
    """Embed report data as inert JSON; all dynamic UI text uses textContent."""
    validate_audit(data)
    payload = json.dumps({"audit": data, "source": str(source)}, ensure_ascii=False,
                         separators=(",", ":"), allow_nan=False).replace("<", "\\u003c")
    return HTML_START + payload + HTML_END


HTML_START = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Multi-IdP PoC — Evidence Explorer</title>
<style>
:root{--bg:#0b1220;--panel:#121d31;--panel2:#182640;--line:#2b3c56;--text:#e9eff8;--sub:#9eacc1;--green:#51d2ac;--blue:#75acff;--yellow:#ffd084;--red:#ef8191;--purple:#c4a3ff;--radius:15px}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% -20%,#1b3052 0,transparent 38%),var(--bg);font-family:Inter,system-ui,-apple-system,Segoe UI,Arial,sans-serif;color:var(--text)}.shell{max-width:1430px;margin:auto;padding:26px 30px 65px}.header{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.eyebrow{font-size:11px;letter-spacing:2.3px;text-transform:uppercase;font-weight:700;color:var(--blue)}h1{font-size:30px;line-height:1.15;margin:12px 0 6px;letter-spacing:-.8px}h2{font-size:20px;margin:0 0 8px;letter-spacing:-.4px}h3{font-size:14px;margin:0 0 8px}.muted{color:var(--sub)}.small{font-size:12px}.mono{font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:26px 0}.stat,.panel{background:linear-gradient(150deg,rgba(27,42,67,.94),rgba(17,29,49,.96));border:1px solid var(--line);border-radius:var(--radius)}.stat{padding:18px 20px;min-height:112px}.stat .num{font-size:31px;font-weight:700;line-height:1.4;letter-spacing:-1px}.stat .label{font-size:12px;color:var(--sub)}.ok{color:var(--green)}.warn{color:var(--yellow)}.bad{color:var(--red)}.nav{display:flex;gap:7px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin-bottom:22px}.nav button{border:0;border-bottom:2px solid transparent;background:transparent;color:var(--sub);font-size:14px;padding:13px 17px;margin-bottom:-1px;cursor:pointer}.nav button.active{color:var(--text);border-bottom-color:var(--blue);font-weight:650}.view{display:none}.view.active{display:block}.panel{padding:22px;margin-bottom:16px}.layout2{display:grid;grid-template-columns:1fr;gap:15px}.section-title{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:18px}.pill{border:1px solid var(--line);border-radius:99px;padding:5px 9px;font-size:11px;color:var(--sub)}.pill.success{color:var(--green);background:rgba(81,210,172,.08);border-color:rgba(81,210,172,.3)}.pill.warning{color:var(--yellow);background:rgba(255,208,132,.08);border-color:rgba(255,208,132,.24)}.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--sub);margin-top:13px}.legend b{display:inline-block;width:9px;height:9px;border-radius:100%;margin-right:5px}.stack{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.milestone{padding:16px;border:1px solid var(--line);border-radius:11px;background:rgba(0,0,0,.07)}.milestone .top{display:flex;gap:10px;justify-content:space-between;align-items:center}.progress{height:6px;background:#29384b;border-radius:10px;margin:13px 0 8px;overflow:hidden}.progress>div{height:100%;background:var(--green)}.rowbetween{display:flex;justify-content:space-between;gap:10px}.tablewrap{overflow:auto}.tbl{width:100%;border-collapse:collapse;font-size:13px}.tbl th{text-align:left;color:var(--sub);font-size:11px;letter-spacing:.5px;font-weight:650;padding:12px 9px;border-bottom:1px solid var(--line)}.tbl td{padding:12px 9px;border-bottom:1px solid rgba(80,107,138,.23);vertical-align:top}.tbl tr:last-child td{border-bottom:0}.tbl .testlink{color:var(--blue);cursor:pointer;border:none;background:none;padding:0;text-align:left;font:inherit;font-weight:650}.tbl .testlink:hover{text-decoration:underline}.search{background:#0d192b;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:12px 14px;width:100%;outline:0}.search:focus{border-color:var(--blue)}.filters{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:13px}.filter{background:#1b2b43;border:1px solid var(--line);color:var(--sub);cursor:pointer;padding:8px 12px;border-radius:9px;font-size:12px}.filter.active{color:var(--text);border-color:var(--blue)}.test-layout{display:grid;grid-template-columns:minmax(340px,.9fr) minmax(0,1.1fr);gap:15px}.listbox{max-height:640px;overflow:auto;padding-right:3px}.test-item{width:100%;display:flex;align-items:flex-start;gap:10px;text-align:left;background:rgba(14,25,43,.65);color:var(--text);padding:12px;margin:0 0 7px;border:1px solid #304258;border-radius:9px;cursor:pointer}.test-item.selected{border-color:var(--blue);background:#1c3052}.test-item .id{color:var(--blue);min-width:36px;font-weight:700}.test-item .name{font-size:12.5px;line-height:1.45;flex:1}.test-item .status{color:var(--green);font-size:11px}.detail{min-height:550px}.meta-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:13px 0}.meta-card{padding:12px;border:1px solid var(--line);border-radius:8px;background:#0d1b2e}.meta-card .k{color:var(--sub);font-size:11px;margin-bottom:4px}.meta-card .v{font-size:12px;overflow-wrap:anywhere}.json{background:#07101e;padding:15px;border-radius:10px;border:1px solid var(--line);color:#b4d2ed;overflow:auto;max-height:560px;font:11px/1.55 ui-monospace,Consolas,monospace;white-space:pre;tab-size:2}.alert{border:1px solid rgba(255,208,132,.33);background:rgba(255,208,132,.07);border-radius:11px;padding:14px 16px;font-size:13px;line-height:1.6;color:#e9dac1}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green)}.token-list{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.token-card{padding:16px;border-radius:11px;background:#0d192b;border:1px solid var(--line);cursor:pointer;text-align:left;color:var(--text)}.token-card:hover,.token-card.selected{border-color:var(--blue)}.token-card h3{margin-top:7px;font-size:16px}.token-card .tag{font-size:11px;color:var(--sub);line-height:1.4}.token-card .aud{font:12px/1.5 ui-monospace,Consolas,monospace;color:var(--green);margin:10px 0;overflow-wrap:anywhere}.footer{margin-top:28px;font-size:11px;color:#8394a8}.inline-code{font:11px ui-monospace,Consolas,monospace;color:#a8d0ff}.envrow{display:grid;grid-template-columns:145px 1fr;gap:8px;padding:10px 0;border-bottom:1px solid rgba(80,107,138,.23);font-size:12px}.envrow span:first-child{color:var(--sub)}.envrow span:last-child{overflow-wrap:anywhere}@media(max-width:950px){.layout2,.test-layout,.stack{grid-template-columns:1fr}.summary{grid-template-columns:repeat(2,1fr)}.token-list{grid-template-columns:1fr}.shell{padding:17px 15px 35px}.header{display:block}.panel{padding:15px}.meta-grid{grid-template-columns:1fr}.envrow{grid-template-columns:110px 1fr}h1{font-size:25px}}

.pill.failure{color:var(--red);border-color:var(--red)}
.test-item .status.ok{color:var(--green)}.test-item .status.bad{color:var(--red)}.test-item .status.warn{color:var(--yellow)}
.toolbar{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-top:20px}
.toolbar input{max-width:100%}.source{overflow-wrap:anywhere}.toolbar label{font-size:13px;color:var(--sub)}
#runmeta{white-space:pre-line}
.summary{grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}
.token-list{grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}
button:focus-visible,input:focus-visible{outline:2px solid var(--blue);outline-offset:3px}

/* Diagram styles are scoped so the rest of the evidence dashboard stays unchanged. */
.identity-map{--map-internal:#75acff;--map-external:#c4a3ff;--map-agent:#51d2ac;padding:24px;border:1px solid var(--line);border-radius:14px;background:#0e182a}
.map-entry{display:grid;grid-template-columns:minmax(0,1fr) 132px minmax(0,1fr);gap:18px;margin-bottom:18px}
.map-source{display:flex;align-items:center;gap:13px;min-width:0}
.map-icon{display:grid;place-items:center;flex:0 0 36px;width:36px;height:36px;border-radius:10px;border:1px solid currentColor;background:rgba(117,172,255,.07);color:var(--map-internal)}
.map-icon svg{width:19px;height:19px;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.map-source strong{font-size:14px}.map-source small{display:block;font-size:11px;color:var(--sub);margin-top:3px}
.map-entry-caption{grid-column:2/4;align-self:center;font-size:12px;line-height:1.6;color:var(--sub)}
.map-entry-caption span{color:var(--text)}
.map-lanes{display:grid;grid-template-columns:minmax(0,1fr) 132px minmax(0,1fr);gap:18px;align-items:stretch}
.map-domain{min-width:0;padding:18px;border:1px dashed rgba(117,172,255,.35);border-radius:12px;background:rgba(117,172,255,.025);display:grid;grid-template-rows:auto 106px minmax(260px,1fr) auto;gap:18px}
.map-domain.external-domain{border-color:rgba(196,163,255,.38);background:rgba(196,163,255,.025);--map-internal:var(--map-external)}
.map-domain-heading{display:flex;gap:10px;align-items:center;justify-content:space-between;min-width:0}
.map-domain-heading h3{font-size:11px;letter-spacing:1.1px;text-transform:uppercase;margin:0;color:var(--map-internal)}
.map-boundary{font:10px ui-monospace,monospace;color:var(--sub);white-space:nowrap}
.map-node{border:1px solid #344966;border-radius:10px;background:#142238;padding:15px;min-width:0}
.map-node-title{display:flex;gap:11px;align-items:center}
.map-node-title strong{display:block;font-size:15px;font-weight:650;letter-spacing:-.2px}
.map-node-title small{display:block;color:var(--sub);font-size:11px;line-height:1.5;margin-top:3px}
.map-agent{border-color:rgba(81,210,172,.32);background:linear-gradient(110deg,rgba(18,61,68,.75),#142638)}
.map-agent .map-icon{color:var(--map-agent);background:rgba(81,210,172,.05)}
.map-agent-a{position:relative}
.map-agent-a:before{content:"";position:absolute;left:32px;top:-19px;height:18px;border-left:1px solid var(--map-internal)}
.map-agent-a:after{content:"";position:absolute;left:29px;top:-5px;border:3.5px solid transparent;border-top-color:var(--map-internal)}
.map-node-note{font-size:11px;color:var(--sub);line-height:1.6;margin:9px 0 0}
.map-issuer{position:relative;padding:0;display:flex;flex-direction:column}
.map-issuer:before{content:"";height:18px;border-left:1px solid #486285;position:absolute;left:32px;top:-19px}
.map-issuer>.map-node-title{padding:15px;border-bottom:1px solid var(--line)}
.external-domain .map-issuer{border-color:rgba(196,163,255,.32);background:#1c2339}
.map-transforms{padding:6px 14px;flex:1}
.map-transform{padding:12px 0;border-bottom:1px solid rgba(80,107,138,.23)}
.map-transform:last-child{border:0}
.map-transform-label{display:flex;gap:8px;align-items:center;font-size:11px;color:var(--sub);margin-bottom:10px}
.map-step{font:10px ui-monospace,monospace;display:inline-grid;place-items:center;width:19px;height:19px;border:1px solid #3a4e6c;border-radius:6px;color:var(--text);flex:0 0 19px}
.map-transform-row{display:flex;align-items:center;gap:9px;flex-wrap:wrap;min-height:27px}
.map-assertion{font:11px ui-monospace,monospace;color:#bfd0e6}
.map-arrow{font-size:15px;color:#6f88aa}
.map-token{appearance:none;border:1px solid rgba(117,172,255,.34);background:rgba(117,172,255,.08);color:var(--blue);border-radius:6px;padding:4px 9px;font:600 11px ui-monospace,monospace;cursor:pointer;transition:border-color .15s,background .15s}
.map-token.external-token{border-color:rgba(196,163,255,.38);background:rgba(196,163,255,.08);color:var(--purple)}
.map-token:hover,.map-token.is-selected{border-color:currentColor;background:rgba(117,172,255,.17)}
.map-token.external-token:hover,.map-token.external-token.is-selected{background:rgba(196,163,255,.16)}
.map-token:focus-visible{outline:2px solid currentColor;outline-offset:3px}
.map-token-caption{font-size:11px;color:var(--sub);line-height:1.6}
.map-call{position:relative}
.map-call:before{content:"";height:18px;border-left:1px solid rgba(81,210,172,.5);position:absolute;left:32px;top:-19px}
.map-call-heading{display:flex;gap:8px;align-items:center;font-size:11px;color:var(--sub);margin-bottom:11px}
.map-call .map-node-title{margin-bottom:12px}
.map-client{border-left:2px solid rgba(196,163,255,.45);padding:8px 12px;align-self:center}
.map-client .map-transform-label{color:var(--purple)}
.map-client p{margin:0;font-size:12px;line-height:1.7;color:var(--sub)}
.map-client code{font:10px ui-monospace,monospace;color:#d5c6f4;overflow-wrap:anywhere}
.map-handoff{display:flex;flex-direction:column;justify-content:center;align-items:center;align-self:center;gap:12px;position:relative;min-width:0}
.map-handoff:before{content:"";position:absolute;left:-18px;right:-18px;top:50%;border-top:1px solid rgba(196,163,255,.55)}
.map-handoff:after{content:"";position:absolute;right:-18px;top:calc(50% - 3px);border:3.5px solid transparent;border-left-color:var(--purple)}
.map-handoff-label{font-size:10px;line-height:1.5;color:var(--sub);text-align:center}
.map-handoff .map-token{position:relative;z-index:1;background:#1c2339;padding:12px 16px;font-size:15px;border-radius:9px}
.map-handoff .map-token:hover,.map-handoff .map-token.is-selected{background:#29334c}
.map-handoff-foot{font-size:10px;text-align:center;line-height:1.5;color:var(--purple)}
.map-return{margin:15px 0 4px;border-top:1px solid var(--line);padding-top:13px;font-size:11px;line-height:1.7;color:var(--sub)}
.map-return strong{color:var(--text);font-weight:500}
.map-caption{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-top:18px;font-size:10px;color:var(--sub);line-height:1.6}
.map-caption span:first-child{color:var(--map-agent)}
@media(max-width:1100px){
.identity-map{padding:16px}
.map-entry,.map-lanes{grid-template-columns:minmax(0,1fr)}
.map-entry{gap:10px}.map-entry-caption{grid-column:auto}
.map-domain{padding:16px;grid-template-rows:auto auto auto auto;gap:18px}
.map-agent-a{min-height:99px}
.map-domain-heading{flex-wrap:wrap}
.map-handoff{min-height:115px;gap:8px;align-self:stretch;padding:12px}
.map-handoff:before{left:50%;right:auto;top:-18px;bottom:-18px;border-top:0;border-left:1px solid rgba(196,163,255,.55)}
.map-handoff:after{left:calc(50% - 3px);right:auto;top:auto;bottom:-18px;border-left-color:transparent;border-top-color:var(--purple)}
.map-handoff-label,.map-handoff-foot{position:relative;background:#0e182a;padding:0 9px}
.map-client{min-height:76px}
.map-source strong{font-size:14px}.map-caption{gap:6px}
}
@media(prefers-reduced-motion:reduce){.map-token{transition:none}}

</style></head><body><main class="shell"><header class="header"><div><div class="eyebrow">Security validation / Technical evidence</div><h1>Multi-IdP Evidence Dashboard</h1><div class="muted small">Red Hat build of Keycloak · JWT Authorization Grant · Token Exchange · Agent-to-Agent calls</div></div><div class="mono muted" style="text-align:right;margin-top:8px" id="runmeta"></div></header>
<div class="toolbar"><label for="audit-file">Open another audit file:</label><input id="audit-file" type="file" accept=".json,application/json"><span id="source" class="small muted source"></span></div><p id="load-error" class="bad small" role="alert" hidden></p>
<div class="panel" style="margin-top:18px"><strong>Acceptance status: </strong><span id="complete"></span><span id="environment" class="small muted" style="margin-left:15px"></span></div><section class="summary"><div class="stat"><div class="label">TESTS PASSED</div><div class="num ok" id="testscore">—</div><div class="label" id="testtypes">Positive & negative scenarios</div></div><div class="stat"><div class="label">MILESTONES</div><div class="num ok" id="milestonescore">—</div><div class="label">Required tests satisfied</div></div><div class="stat"><div class="label">RHBK INSTALLATIONS</div><div class="num" id="installs">—</div><div class="label">Internal & external realms</div></div><div class="stat"><div class="label">RESET VALIDATION</div><div class="num warn" id="reset" style="font-size:23px;margin-top:9px">—</div><div class="label">Separate verification status</div></div></section>
<nav class="nav" aria-label="Report tabs"><button class="active" data-view="overview">Overview</button><button data-view="flow">Token & identity flow</button><button data-view="tests">Test matrix</button><button data-view="evidence">Evidence explorer</button></nav>
<section id="overview" class="view active"><div class="layout2"><article class="panel"><div class="section-title"><h2>Agent execution flow</h2><span class="pill">from P1, P2, P3, P6</span></div><div id="flow-overview"></div><div class="legend"><span><b style="background:#709cd4"></b>Internal issuer</span><span><b style="background:#c29af8"></b>External issuer</span><span><b style="background:#62cfc2"></b>A2A application call</span></div></article><article class="panel"><div class="section-title"><h2>Milestone coverage</h2><span class="pill" id="milestone-status"></span></div><div id="milestone-cards" class="stack"></div></article></div><div class="panel"><div class="section-title"><h2>Interpretation & caveats</h2></div><div class="alert"><strong>Pass ≠ unrestricted access.</strong> A passing negative test means the targeted invalid request was denied as expected. Milestone success reflects the required tests, not necessarily every operational recovery scenario.</div><div id="notices" style="margin-top:15px"></div></div></section>
<section id="flow" class="view"><div class="panel"><div class="section-title"><h2>Cross-domain token chain</h2><span class="pill">Evidence P1 / P2 / P3 / P6</span></div><div id="flow-large"></div><p class="small muted" style="margin-top:14px">Agent A receives the RH SSO ID token, obtains T1, exchanges it for TC and calls Agent C. It then exchanges T1 for T2, presents T2 to External Keycloak, and calls Agent B with T3.</p></div><div class="panel"><div class="section-title"><h2>Inspect issued token summaries</h2><span class="pill">Click a token</span></div><div class="token-list" id="tokens"></div><div id="token-detail" style="margin-top:14px"></div></div></section>
<section id="tests" class="view"><div class="panel"><div class="section-title"><h2>Test matrix</h2><span class="pill">click test ID for evidence</span></div><div class="filters"><button class="filter active" data-filter="all">All</button><button class="filter" data-filter="P">Positive</button><button class="filter" data-filter="N">Negative / security</button></div><div class="tablewrap"><table class="tbl"><thead><tr><th>ID</th><th>Scenario</th><th>Expected category</th><th>Reported status</th><th>Milestones</th></tr></thead><tbody id="test-rows"></tbody></table></div></div></section>
<section id="evidence" class="view"><div class="test-layout"><article class="panel"><div class="section-title"><h2>Tests</h2><span class="pill" id="result-count">0</span></div><input type="search" id="search" class="search" placeholder="Search ID, test name, description…" aria-label="Filter tests"><div class="filters" style="margin-top:12px"><button class="filter active" data-evidence-filter="all">All</button><button class="filter" data-evidence-filter="P">Positive</button><button class="filter" data-evidence-filter="N">Negative</button></div><div id="test-list" class="listbox"></div></article><article class="panel detail"><div class="section-title"><h2>Evidence details</h2><span class="pill" id="selected-id">P1</span></div><div id="detail"></div></article></div></section>
<section class="panel"><h2>Downstream Identity Evidence</h2><p class="small muted">Original RH SSO identity, realm user, and Agent A client are distinct. These values come from agent replies recorded in the audit.</p><div id="identities" class="meta-grid"></div></section><div class="footer">Local report generated from the selected audit file. No network requests or third-party libraries. Test status and evidence are reported observations, not independently rerun verification.</div></main><script id="payload" type="application/json">'''

HTML_END = r'''</script><script>
const text = value => String(value ?? 'Not recorded');
const el = (tag, klass, value) => {
  const node = document.createElement(tag);
  if (klass) node.className = klass;
  if (value !== undefined) node.textContent = text(value);
  return node;
};
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const statusClass = status => status === 'pass' ? 'ok' : status === 'fail' ? 'bad' : 'warn';
const pillClass = status => 'pill ' + (status === 'pass' ? 'success' : status === 'fail' ? 'failure' : 'warning');
let D, tests = [], milestones = [], tokens = [];
let selected = null, matFilter = 'all', evFilter = 'all', evQuery = '';

function validateAudit(data) {
  if (!object(data)) throw Error('Audit must be a JSON object.');
  for (const key of ['runId', 'utc'])
    if (typeof data[key] !== 'string' || !data[key]) throw Error('Audit ' + key + ' must be a nonempty string.');
  for (const key of ['tests', 'milestones', 'installations'])
    if (!object(data[key]) || Object.values(data[key]).some(v => !object(v)))
      throw Error('Audit ' + key + ' must contain objects.');
  for (const [id, test] of Object.entries(data.tests))
    if ('status' in test && typeof test.status !== 'string') throw Error('Test ' + id + ' status must be a string.');
  for (const [id, milestone] of Object.entries(data.milestones)) {
    const required = 'requiredTests' in milestone ? milestone.requiredTests : [];
    if (!Array.isArray(required) || required.some(id => typeof id !== 'string'))
      throw Error('Milestone ' + id + ' requiredTests must be a list of test IDs.');
    if ('status' in milestone && typeof milestone.status !== 'string')
      throw Error('Milestone ' + id + ' status must be a string.');
  }
  if ('complete' in data && typeof data.complete !== 'boolean') throw Error('Audit complete must be a boolean.');
  if ('environmentChecks' in data && !object(data.environmentChecks)) throw Error('Audit environmentChecks must be an object.');
}
function changeView(name) {
  document.querySelectorAll('.nav button').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === name));
}
function metaCards(target, values) {
  for (const [key, value] of Object.entries(values)) {
    const card = el('div', 'meta-card');
    card.append(el('div', 'k', key), el('div', 'v mono', value));
    target.append(card);
  }
}
function setScore(id, value, status) {
  const node = document.getElementById(id);
  node.textContent = value;
  node.classList.remove('ok', 'bad', 'warn');
  node.classList.add(statusClass(status));
}
function renderReport(data, source) {
  validateAudit(data);
  D = data;
  tests = Object.entries(D.tests).map(([id, t]) => ({...t, id, status: t.status ?? 'not-recorded'}));
  milestones = Object.entries(D.milestones).map(([id, m]) => ({...m, id, requiredTests: m.requiredTests ?? [], status: m.status ?? 'not-recorded'}));
  selected = tests[0]?.id ?? null;
  matFilter = evFilter = 'all'; evQuery = '';
  document.getElementById('search').value = '';
  document.querySelectorAll('[data-filter]').forEach(b => b.classList.toggle('active', b.dataset.filter === 'all'));
  document.querySelectorAll('[data-evidence-filter]').forEach(b => b.classList.toggle('active', b.dataset.evidenceFilter === 'all'));
  document.getElementById('source').textContent = 'Source: ' + source;
  document.getElementById('runmeta').textContent = 'Run ' + D.runId + '\nRecorded: ' + D.utc;
  const passed = tests.filter(t => t.status === 'pass').length;
  const milestonePasses = milestones.filter(m => m.status === 'pass').length;
  setScore('testscore', passed + ' / ' + tests.length, !tests.length ? 'not-recorded' : passed === tests.length ? 'pass' : 'fail');
  document.getElementById('testtypes').textContent =
    tests.filter(t => t.id.startsWith('P')).length + ' positive · ' + tests.filter(t => t.id.startsWith('N')).length + ' negative';
  setScore('milestonescore', milestonePasses + ' / ' + milestones.length, !milestones.length ? 'not-recorded' : milestonePasses === milestones.length ? 'pass' : 'fail');
  document.getElementById('installs').textContent = Object.keys(D.installations).length;
  setScore('reset', D.resetValidation ?? 'not-recorded', D.resetValidation);
  const recorded = typeof D.complete === 'boolean' ? (D.complete ? 'pass' : 'fail') : 'not-recorded';
  const conflicts = tests.some(t => t.status !== 'pass') || !tests.length ||
    !milestones.length || milestones.some(m => m.status !== 'pass' || m.requiredTests.some(id => D.tests[id]?.status !== 'pass')) ||
    Object.values(D.environmentChecks ?? {}).some(value => value !== true);
  setScore('complete', recorded === 'pass' && conflicts ? 'Inconsistent audit: recorded complete, checks incomplete' :
    recorded === 'pass' ? 'Complete' : recorded === 'fail' ? 'Incomplete' : 'Not recorded',
    recorded === 'pass' && conflicts ? 'not-recorded' : recorded);
  document.getElementById('environment').textContent = 'Environment: ' +
    (Object.entries(D.environmentChecks ?? {}).map(([name, value]) => name + '=' + value).join(', ') || 'Not recorded');
  document.querySelector('[data-filter="all"]').textContent = 'All ' + tests.length;
  const badge = document.getElementById('milestone-status');
  badge.textContent = milestonePasses + ' of ' + milestones.length + ' passed';
  badge.className = pillClass(!milestones.length ? 'not-recorded' : milestonePasses === milestones.length ? 'pass' : 'fail');
  const box = document.getElementById('milestone-cards');
  box.replaceChildren();
  if (!milestones.length) box.append(el('p', 'muted', 'No milestones recorded.'));
  for (const m of milestones) {
    const card = el('div', 'milestone'), top = el('div', 'top');
    top.append(el('strong', '', m.id + ' · ' + text(m.name)), el('span', pillClass(m.status), m.status));
    const n = m.requiredTests.filter(id => D.tests[id]?.status === 'pass').length;
    const progress = el('div', 'progress'), bar = el('div');
    bar.style.width = (m.requiredTests.length ? 100 * n / m.requiredTests.length : 0) + '%';
    bar.style.background = m.status === 'pass' ? 'var(--green)' : 'var(--red)';
    progress.append(bar);
    card.append(top, el('p', 'small muted', m.description), progress,
      el('div', 'small muted', n + '/' + m.requiredTests.length + ' required tests passed'));
    box.append(card);
  }
  const notices = document.getElementById('notices');
  notices.replaceChildren();
  for (const [id, inst] of Object.entries(D.installations)) {
    const card = el('div');
    card.append(el('h3', '', id + ' installation'));
    metaCards(card, {'Issuer': inst.issuer, 'Realm': inst.realm, 'Namespace': inst.namespace,
      'Runtime version': inst.runtimeVersion, 'TLS verified': inst.tlsVerified,
      'Requested image': inst.requestedImage, 'Running image': inst.runningImage});
    notices.append(card);
  }
  notices.append(el('p', 'small muted', 'Reset validation is separate from milestone coverage. The diagram describes the configured flow; the test records determine which steps passed.'));
  if (conflicts && D.complete === true) notices.append(el('p', 'warn', 'The recorded complete field conflicts with the test, milestone, or environment results.'));
  tokens = [
    ['RH', 'Original RH SSO identity', null],
    ['T1', 'Internal user context', D.tests.P1?.t1],
    ['TC', 'Internal token for Agent C', null],
    ['T2', 'Assertion for External Keycloak', D.tests.P2?.t2],
    ['T3', 'External token for Agent B', D.tests.P2?.t3],
  ];
  const tokenBox = document.getElementById('tokens');
  tokenBox.replaceChildren();
  tokens.forEach(([id, name, token], index) => {
    const button = el('button', 'token-card');
    button.append(el('div', 'eyebrow', id), el('h3', '', name),
      el('div', 'tag', token?.subjectLabel ?? 'Summary not recorded'),
      el('div', 'aud', 'Audience: ' + text(Array.isArray(token?.audience) ? token.audience.join(', ') : token?.audience)));
    button.addEventListener('click', () => tokenDetail(index));
    tokenBox.append(button);
  });
  tokenDetail(tokens.findIndex(([, , token]) => token) < 0 ? 0 : tokens.findIndex(([, , token]) => token));
  renderIdentities(); renderMatrix(); renderExplorer();
  changeView('overview');
}
function tokenDetail(index) {
  const [id, name, token] = tokens[index];
  const target = document.getElementById('token-detail');
  target.replaceChildren(el('h3', '', id + ' · ' + name));
  if (!object(token)) {
    target.append(el('p', 'muted', 'This audit does not record this token summary. Downstream identities are shown separately.'));
  } else {
    const grid = el('div', 'meta-grid');
    metaCards(grid, {
      'User identity role': token.subjectLabel,
      'Issuer': token.issuer,
      'Issuer-local user fingerprint': token.subjectSha256,
      'Agent A OAuth client (azp)': token.azp,
      'Audience': Array.isArray(token.audience) ? token.audience.join(', ') : token.audience,
      'Scopes': token.scope, 'Permissions': Array.isArray(token.permissions) ? token.permissions.join(', ') : undefined,
      'Lifetime (seconds)': Number.isFinite(token.expires) && Number.isFinite(token.issuedAt) ? token.expires - token.issuedAt : undefined,
      'Token fingerprint': token.sha256, 'Signature verified in source report': token.signatureVerified,
    });
    target.append(grid);
  }
  document.querySelectorAll('.token-card').forEach((b, i) => b.classList.toggle('selected', index === i));
  document.querySelectorAll('[data-map-token]').forEach(button => {
    const active = button.dataset.mapToken === id;
    button.classList.toggle('is-selected', active);
    button.setAttribute('aria-pressed', String(active));
  });
}
function renderIdentities() {
  const target = document.getElementById('identities');
  target.replaceChildren();
  for (const [id, name] of [['P6', 'Agent C · internal domain'], ['P3', 'Agent B · external domain']]) {
    const panel = el('div'), grid = el('div');
    panel.append(el('h3', '', name));
    let identity;
    try {
      const parts = D.tests[id]?.response?.result?.message?.parts ?? [];
      const record = parts.find(part => typeof part.text === 'string');
      identity = record ? JSON.parse(record.text).identity : null;
    } catch { identity = null; }
    if (object(identity)) metaCards(grid, {
      'Realm user subject': identity.user, 'Issuer': identity.issuer,
      'Agent A OAuth client': identity.authorizedClient, 'Original RH issuer': identity.originIssuer,
      'Original RH user fingerprint': identity.originSubjectSha256, 'Internal user subject': identity.internalUser,
      'Provenance guarantee': identity.provenance,
    });
    else grid.append(el('p', 'muted', 'Downstream identity not recorded.'));
    panel.append(grid); target.append(panel);
  }
}
function renderMatrix() {
  const body = document.getElementById('test-rows');
  body.replaceChildren();
  for (const t of tests.filter(t => matFilter === 'all' || t.id.startsWith(matFilter))) {
    const row = el('tr'), cell = el('td'), button = el('button', 'testlink', t.id);
    button.addEventListener('click', () => {
      evFilter = 'all'; evQuery = ''; document.getElementById('search').value = '';
      document.querySelectorAll('[data-evidence-filter]').forEach(b => b.classList.toggle('active', b.dataset.evidenceFilter === 'all'));
      selected = t.id; renderExplorer(); changeView('evidence');
    });
    cell.append(button);
    row.append(cell, el('td', '', t.name ?? 'Name not recorded'), el('td', 'muted',
      t.id.startsWith('P') ? 'Positive behavior' : t.id.startsWith('N') ? 'Security regression' : 'Other'),
      el('td', statusClass(t.status), t.status),
      el('td', 'muted', milestones.filter(m => m.requiredTests.includes(t.id)).map(m => m.id).join(', ') || '—'));
    body.append(row);
  }
}
function renderExplorer() {
  const filtered = tests.filter(t => (evFilter === 'all' || t.id.startsWith(evFilter)) &&
    [t.id, t.name, t.description].join(' ').toLowerCase().includes(evQuery));
  if (!filtered.some(t => t.id === selected)) selected = filtered[0]?.id ?? null;
  const list = document.getElementById('test-list');
  list.replaceChildren();
  document.getElementById('result-count').textContent = filtered.length + ' results';
  for (const t of filtered) {
    const button = el('button', 'test-item' + (selected === t.id ? ' selected' : ''));
    button.append(el('span', 'id mono', t.id), el('span', 'name', t.name ?? 'Name not recorded'),
      el('span', 'status ' + statusClass(t.status), t.status));
    button.addEventListener('click', () => { selected = t.id; renderExplorer(); });
    list.append(button);
  }
  const target = document.getElementById('detail');
  target.replaceChildren();
  document.getElementById('selected-id').textContent = selected ?? '—';
  const t = tests.find(t => t.id === selected);
  if (!t) { target.append(el('p', 'muted', 'No matching tests.')); return; }
  target.append(el('h2', '', t.name ?? t.id), el('p', 'small muted', t.description ?? 'Description not recorded'));
  const grid = el('div', 'meta-grid');
  metaCards(grid, {'Status': t.status, 'Required by': milestones.filter(m => m.requiredTests.includes(t.id)).map(m => m.id).join(', ') || '—'});
  target.append(grid, el('h3', '', 'Source evidence'), el('pre', 'json', JSON.stringify(D.tests[selected], null, 2)));
}

const mapIcon = kind => {
  const paths = {
    user: '<circle cx="12" cy="8" r="3"/><path d="M5 21v-2a7 7 0 0 1 14 0v2"/>',
    issuer: '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m8 12 3 3 5-6"/>',
    agent: '<rect x="3" y="5" width="18" height="14" rx="3"/><path d="m7 10 3 2-3 2m6 0h4"/>',
  };
  return '<span class="map-icon" aria-hidden="true"><svg viewBox="0 0 24 24">' + paths[kind] + '</svg></span>';
};
const mapToken = (id, external = false) =>
  '<button type="button" class="map-token' + (external ? ' external-token' : '') +
  '" data-map-token="' + id + '" aria-pressed="false" aria-label="Inspect ' + id + ' token evidence" title="Inspect ' + id + ' token evidence">' + id + '</button>';
const architecture = '<div class="identity-map" role="group" aria-label="RH SSO identity enters Agent A, which executes grants and exchanges across two independent Keycloak domains and calls Agents C and B.">' +
  '<div class="map-entry"><div class="map-source">' + mapIcon('user') +
    '<div><strong>RH SSO</strong><small>Upstream identity provider · approved user</small></div></div>' +
    '<div class="map-entry-caption"><span>ID token → Agent A</span><br>Agent A executes every grant, exchange, and downstream call.</div></div>' +
  '<div class="map-lanes">' +
    '<section class="map-domain" aria-label="Internal authorization domain">' +
      '<div class="map-domain-heading"><h3>Internal Domain</h3><span class="map-boundary">realm / internal</span></div>' +
      '<div class="map-node map-agent map-agent-a"><div class="map-node-title">' + mapIcon('agent') +
        '<div><strong>Agent A</strong><small>Internal agent · OAuth client <span class="inline-code">agent-a-internal</span></small></div></div>' +
        '<p class="map-node-note">Receives the approved RH SSO ID token.</p></div>' +
      '<div class="map-node map-issuer"><div class="map-node-title">' + mapIcon('issuer') +
        '<div><strong>Internal Keycloak</strong><small>Token issuer · grants and exchanges</small></div></div>' +
        '<div class="map-transforms">' +
          '<div class="map-transform"><div class="map-transform-label"><span class="map-step">1</span>JWT Authorization Grant</div>' +
            '<div class="map-transform-row"><span class="map-assertion">RH ID token</span><span class="map-arrow" aria-hidden="true">→</span>' + mapToken('T1') +
              '<span class="map-token-caption">Internal user context</span></div></div>' +
          '<div class="map-transform"><div class="map-transform-label"><span class="map-step">2</span>Token Exchange V2 · internal target</div>' +
            '<div class="map-transform-row">' + mapToken('T1') + '<span class="map-arrow" aria-hidden="true">→</span>' + mapToken('TC') +
              '<span class="map-token-caption">Audience: agent-c</span></div></div>' +
          '<div class="map-transform"><div class="map-transform-label"><span class="map-step">4</span>Token Exchange V2 · external target</div>' +
            '<div class="map-transform-row">' + mapToken('T1') + '<span class="map-arrow" aria-hidden="true">→</span>' + mapToken('T2') +
              '<span class="map-token-caption">Audience: external realm issuer</span></div></div>' +
        '</div></div>' +
      '<div class="map-node map-agent map-call"><div class="map-call-heading"><span class="map-step">3</span>Agent A invokes Agent C · A2A</div>' +
        '<div class="map-node-title">' + mapIcon('agent') + '<div><strong>Agent C</strong><small>Internal resource agent</small></div></div>' +
        '<div class="map-transform-row">' + mapToken('TC') + '<span class="map-token-caption">Internal issuer · audience: agent-c</span></div></div>' +
    '</section>' +
    '<div class="map-handoff" aria-label="Agent A presents the internal T2 assertion to External Keycloak">' +
      '<div class="map-handoff-label">Agent A presents</div>' + mapToken('T2') +
      '<div class="map-handoff-foot">Internal assertion<br>Trust boundary</div></div>' +
    '<section class="map-domain external-domain" aria-label="External authorization domain">' +
      '<div class="map-domain-heading"><h3>External Domain</h3><span class="map-boundary">realm / partner</span></div>' +
      '<div class="map-client"><div class="map-transform-label"><span class="map-step">5</span>Same Agent A · external client</div>' +
        '<p>Agent A authenticates as<br><code>agent-a-external</code></p></div>' +
      '<div class="map-node map-issuer"><div class="map-node-title">' + mapIcon('issuer') +
        '<div><strong>External Keycloak</strong><small>Independent token issuer</small></div></div>' +
        '<div class="map-transforms">' +
          '<div class="map-transform"><div class="map-transform-label"><span class="map-step">5</span>JWT Authorization Grant</div>' +
            '<div class="map-transform-row">' + mapToken('T2') + '<span class="map-arrow" aria-hidden="true">→</span>' + mapToken('T3', true) + '</div>' +
            '<p class="map-node-note">The approved mapping selects the external pilot user.</p></div>' +
          '<div class="map-transform"><div class="map-transform-label">External access token</div>' +
            '<div class="map-transform-row">' + mapToken('T3', true) + '<span class="map-token-caption">Audience: agent-b</span></div>' +
            '<div class="map-return"><strong>T3 is returned to Agent A.</strong><br>Agent A uses this token for its call to Agent B.</div></div>' +
        '</div></div>' +
      '<div class="map-node map-agent map-call"><div class="map-call-heading"><span class="map-step">6</span>Agent A invokes Agent B · A2A</div>' +
        '<div class="map-node-title">' + mapIcon('agent') + '<div><strong>Agent B</strong><small>External resource agent</small></div></div>' +
        '<div class="map-transform-row">' + mapToken('T3', true) + '<span class="map-token-caption">External issuer · audience: agent-b</span></div></div>' +
    '</section>' +
  '</div><div class="map-caption"><span>Agent A executes steps 1–6 in order. Select a token to inspect its evidence.</span>' +
    '<span>Independent realms and signing keys · trusted transitive identity provenance</span></div></div>';
document.getElementById('flow-overview').innerHTML = architecture;
document.getElementById('flow-large').innerHTML = architecture;
document.querySelectorAll('[data-map-token]').forEach(button => button.addEventListener('click', () => {
  const index = tokens.findIndex(([id]) => id === button.dataset.mapToken);
  if (index < 0) return;
  changeView('flow');
  tokenDetail(index);
  document.getElementById('token-detail').scrollIntoView({block: 'nearest'});
}));
document.querySelectorAll('.nav button').forEach(b => b.addEventListener('click', () => changeView(b.dataset.view)));
document.querySelectorAll('[data-filter]').forEach(b => b.addEventListener('click', () => {
  matFilter = b.dataset.filter;
  document.querySelectorAll('[data-filter]').forEach(x => x.classList.toggle('active', x === b));
  renderMatrix();
}));
document.querySelectorAll('[data-evidence-filter]').forEach(b => b.addEventListener('click', () => {
  evFilter = b.dataset.evidenceFilter;
  document.querySelectorAll('[data-evidence-filter]').forEach(x => x.classList.toggle('active', x === b));
  renderExplorer();
}));
document.getElementById('search').addEventListener('input', event => {
  evQuery = event.target.value.trim().toLowerCase(); renderExplorer();
});
document.getElementById('audit-file').addEventListener('change', async event => {
  const file = event.target.files[0];
  if (!file) return;
  const error = document.getElementById('load-error');
  try {
    const data = JSON.parse(await file.text());
    renderReport(data, file.name);
    error.hidden = true;
  } catch (failure) {
    error.textContent = 'Could not load ' + file.name + ': ' + failure.message;
    error.hidden = false;
  }
  event.target.value = '';
});
const initial = JSON.parse(document.getElementById('payload').textContent);
renderReport(initial.audit, initial.source);
</script></body></html>'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, nargs="?", help="audit JSON (default: newest audit in evidence)")
    parser.add_argument("--evidence-dir", type=Path, default=ROOT / "evidence",
                        help="audit search and default dashboard directory")
    parser.add_argument("-o", "--output", type=Path, help="output HTML path")
    args = parser.parse_args(argv)
    try:
        source = (args.input if args.input is not None else latest_audit(args.evidence_dir)).resolve()
        data = validate_audit(json.loads(source.read_text(encoding="utf-8")))
        output = args.output or args.evidence_dir / "dashboards" / (source.stem + ".html")
        if output.resolve() == source:
            raise ValueError("Output cannot overwrite the source audit")
        if output.suffix.lower() != ".html":
            raise ValueError("Output must use the .html extension")
        html = render_dashboard(data, source)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding="utf-8")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Audit: {source}")
    print(f"Dashboard: {output.resolve()}")
    print("Open this HTML file in your browser. Use Open another audit file to switch reports.")


if __name__ == "__main__":
    main()
