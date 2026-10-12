"""Dependency-free presentation of saved summaries; never recomputes statistics."""

from __future__ import annotations

import html
import json


_LABELS = {
    "keygen_ns": "Key generation",
    "sign_release_ns": "Signing and release",
    "signature_verify_ns": "Signature verification",
    "process_cpu_ns": "Process CPU time",
    "process_user_cpu_ns": "User CPU time",
    "process_system_cpu_ns": "System CPU time",
    "process_cpu_core_equivalents": "Process CPU / wall time",
    "process_cpu_normalized_percent": "CPU share of declared entitlement",
    "effective_cpu_cores": "Effective CPU entitlement",
    "rss_before_bytes": "RSS at operation start",
    "rss_after_bytes": "RSS at operation end",
    "rss_current_bytes": "Current RSS",
    "process_peak_rss_bytes": "Process lifetime peak RSS",
    "public_key_bytes": "Public key size",
    "signature_bytes": "Signature size",
    "message_bytes": "Message size",
    "transaction_bytes": "On-chain transaction size",
    "authorization_bytes": "Authorization size",
    "descriptor_bytes": "Descriptor size",
}
_PRIMARY_METRICS = ("keygen_ns", "sign_release_ns", "signature_verify_ns")
_STYLE = """
:root{color-scheme:light;--ink:#172536;--muted:#516173;--line:#dbe2e9;--bg:#f4f7fa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
main{max-width:1320px;margin:auto;padding:24px 24px 64px}h1{font-size:30px;margin:0 0 8px}
h2{font-size:23px;margin:24px 0 12px}h3{font-size:17px;margin:0;overflow-wrap:anywhere}p{margin:8px 0}
a{color:#075ea7}code,pre{font:12px/1.5 ui-monospace,monospace}code{overflow-wrap:anywhere}
.muted,.scope{color:var(--muted)}.downloads{display:flex;gap:18px;margin:14px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;margin:12px 0}
.card,.panel,.population{background:white;border:1px solid var(--line);border-radius:10px}
.card{padding:10px 18px}.card strong{display:block;font-size:23px}.card span{color:var(--muted)}
.panel{padding:14px 18px;margin:12px 0}.notice{border-left:4px solid #ba7400;background:#fff9e9}
.good{border-left:4px solid #18815a}.status{font-size:18px;font-weight:650}.status code{margin-left:8px;font-weight:400}
.population{margin:14px 0;overflow:hidden}.population header{padding:14px 18px;border-bottom:1px solid var(--line)}
.scope{display:flex;flex-wrap:wrap;gap:4px 18px;font-size:13px;margin-top:6px}.scope b{color:var(--ink)}
.outcome{display:inline-block;font-size:13px;font-weight:600;border:1px solid var(--line);border-radius:20px;padding:2px 9px;margin-left:8px}
.outcome-issue{color:#8b3d0c;background:#fff3e7}.outcome-good{color:#126444;background:#eef9f3}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:11px 13px;border-bottom:1px solid var(--line);vertical-align:top}
th{position:sticky;top:0;background:#eef3f7;color:#41556a;font-size:12px;white-space:nowrap;z-index:1}
td.number{white-space:nowrap;font-variant-numeric:tabular-nums}td.metric{min-width:210px;width:24%}
td.notes{min-width:250px;width:31%;font-size:12px}.metric strong{display:block}.metric code{display:block;color:var(--muted);font-size:11px}
.scope-note{color:var(--muted);font-size:12px;margin-top:4px}.caution{color:#875000;margin-bottom:4px}
.empty{padding:15px 18px}.jump{display:flex;flex-wrap:wrap;gap:8px 18px;padding:0;list-style:none}
details{margin:6px 0}summary{cursor:pointer;color:#075ea7}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6f8;padding:12px;border-radius:6px;max-height:420px;overflow:auto}
.audit{margin-top:24px}.audit>summary{font-size:18px;font-weight:600}.outcomes{display:flex;flex-wrap:wrap;gap:8px 18px}
footer{color:var(--muted);font-size:13px;margin-top:24px}
@media(max-width:640px){main{padding:20px 12px}h1{font-size:25px}.cards{grid-template-columns:repeat(2,1fr)}th,td{padding:9px}.scope{display:block}.scope span{display:block}}
@media print{body{background:white}main{max-width:none;padding:0}.table-wrap{overflow:visible}th{position:static}.population{break-inside:avoid}details[open] pre{max-height:none}.downloads{display:none}}
"""


def _escape(value):
    return html.escape(str(value), quote=True)


def _json(value):
    return _escape(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))


def _number(value):
    if type(value) is int:
        return f"{value:,}"
    if value and abs(value) < 0.001:
        return f"{value:.3g}"
    return f"{value:,.3f}".rstrip("0").rstrip(".")


def _value(value, unit):
    if value is None:
        return '<span class="muted">Unavailable</span>'
    display, display_unit = value, unit
    if unit == "ns":
        for divisor, label in ((1_000_000_000, "s"), (1_000_000, "ms"), (1_000, "µs")):
            if abs(value) >= divisor:
                display, display_unit = value / divisor, label
                break
    elif unit in ("bytes", "bytes/s"):
        display_unit = "B" if unit == "bytes" else "B/s"
        # Small encoded sizes stay exact and easy to compare with the protocol.
        if abs(value) >= 65_536:
            for divisor, label in ((1024**3, "GiB"), (1024**2, "MiB"), (1024, "KiB")):
                if abs(value) >= divisor:
                    display, display_unit = value / divisor, label + ("/s" if unit == "bytes/s" else "")
                    break
    elif unit == "percent":
        display_unit = "%"
    raw = _escape(f"Exact: {value} {unit}")
    return f'<span title="{raw}">{_escape(_number(display))} {_escape(display_unit)}</span>'


def _metric_sort(item):
    name = item[0]
    return (_PRIMARY_METRICS.index(name) if name in _PRIMARY_METRICS else len(_PRIMARY_METRICS), name)


def _metric_row(name, metric, catalog):
    unit = metric["unit"]
    samples = metric["samples"]
    description = catalog.get(name, {}).get("description", "")
    label = _LABELS.get(name, name.replace("_", " "))
    cautions = []
    if samples == 0:
        cautions.append("No exact samples; no quantiles.")
    elif samples == 1:
        cautions.append("One sample; all three percentiles repeat this value.")
    elif samples < 20:
        cautions.append("Small sample: p95 and p99 are the observed maximum; tail stability is unproven.")
    elif samples < 100:
        cautions.append("Small sample: p99 is the observed maximum; tail stability is unproven.")
    if metric["missing_count"]:
        cautions.append(f'{metric["missing_count"]} missing from recorded attempts.')
    if metric["unavailable_count"]:
        cautions.append(f'{metric["unavailable_count"]} unavailable: ' + "; ".join(
            f"{reason} ({count})" for reason, count in metric["unavailable_reasons"].items()))
    if metric["censored_count"]:
        bounds = f'{metric["lower_bound_min"]}–{metric["lower_bound_max"]} {unit}'
        cautions.append(f'{metric["censored_count"]} censored lower bounds ({bounds}); excluded from quantiles.')
    if metric["tail_incomplete"]:
        cautions.append("Incomplete tail: exact quantiles omit missing, unavailable or censored observations.")
    if name == "process_peak_rss_bytes":
        cautions.append("Lifetime high-water mark includes setup; not an operation peak.")
    note_html = "".join(f'<div class="caution">{_escape(note)}</div>' for note in cautions)
    exact = {"metric": name, "scope": description, **metric}
    note_html += f'<details><summary>Exact values and scope</summary><pre>{_json(exact)}</pre></details>'
    values = "".join(f'<td class="number">{_value(metric[key], unit)}</td>' for key in ("p50", "p95", "p99"))
    return (
        f'<tr><td class="metric"><strong>{_escape(label)}</strong><code>{_escape(name)}</code>'
        f'<div class="scope-note">{_escape(description)}</div></td>{values}'
        f'<td class="number">{_escape(samples)}</td><td class="notes">{note_html}</td></tr>'
    )


def _population(group, catalog):
    outcome = group["outcome"]
    label = outcome.replace("_", " ")
    if outcome == "expected_rejection":
        label += " · expected result"
    style = "outcome-good" if outcome in ("success", "expected_rejection") else "outcome-issue"
    if outcome == "all_outcomes":
        style = ""
    scope = "".join(f'<span><b>{label}:</b> {_escape(group[key])}</span>' for label, key in (
        ("Run", "run_id"), ("Configuration", "configuration_id"), ("Phase", "phase"), ("Cache", "cache_mode")))
    header = (
        f'<header><h3>{_escape(group["process_id"])} <span class="outcome {style}">{_escape(label)}</span></h3>'
        f'<div class="scope">{scope}</div><p class="scope">'
        f'{_escape(group["observation_count"])} non-warmup records · {_escape(group["warmup_count"])} warmup records excluded from quantiles</p></header>'
    )
    if not group["metrics"]:
        content = '<p class="empty caution">No metric values were recorded for this population.</p>'
    else:
        rows = "".join(_metric_row(name, metric, catalog) for name, metric in sorted(group["metrics"].items(), key=_metric_sort))
        content = (
            '<div class="table-wrap"><table><thead><tr><th scope="col">Metric</th>'
            '<th scope="col">p50 · median</th><th scope="col">p95</th><th scope="col">p99</th>'
            '<th scope="col">Exact n</th><th scope="col">Coverage and interpretation</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )
    return f'<section class="population">{header}{content}</section>'


def render_report(summary, catalog):
    """Render all populations, preserving outcome and process boundaries."""
    groups = summary["groups"]
    cases = sorted({group["case_id"] for group in groups})
    processes = {(group["run_id"], group["process_id"]) for group in groups}
    status = summary["status"].replace("_", " ").capitalize()
    style = "good" if summary["successful"] else "notice"
    issues = "".join(f'<li>{_escape(issue)}</li>' for issue in summary["issues"])
    status_detail = '<ul>' + issues + '</ul>' if issues else '<p>No recorded failures, missing values or censored observations.</p>'
    cards = "".join(f'<div class="card"><strong>{value:,}</strong><span>{label}</span></div>' for value, label in (
        (len(cases), "cases"), (len(processes), "process populations"),
        (summary["observation_count"], "non-warmup records"), (summary["warmup_count"], "warmup records")))
    outcomes = "".join(
        f'<span><b>{_escape(outcome.replace("_", " "))}:</b> {_escape(count)}</span>'
        for outcome, count in summary["measurement_outcome_counts"].items() if count
    ) or '<span>No non-warmup outcomes.</span>'
    warmup_outcomes = "".join(
        f'<span><b>{_escape(outcome.replace("_", " "))}:</b> {_escape(count)}</span>'
        for outcome, count in summary["warmup_outcome_counts"].items() if count
    ) or '<span>No warmup outcomes.</span>'
    jump = "".join(f'<li><a href="#case-{index}">{_escape(case)}</a></li>' for index, case in enumerate(cases))
    main = []
    for index, case in enumerate(cases):
        populations = "".join(_population(group, catalog) for group in groups
                              if group["case_id"] == case and group["outcome"] != "all_outcomes")
        main.append(f'<section id="case-{index}"><h2>{_escape(case)}</h2>{populations}</section>')
    combined = "".join(
        f'<h3>{_escape(group["case_id"])}</h3>{_population(group, catalog)}'
        for group in groups if group["outcome"] == "all_outcomes")
    overview = {key: value for key, value in summary.items() if key != "groups"}
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>SLH benchmark report</title><style>{_STYLE}</style></head><body><main>'
        '<h1>SLH benchmark report</h1><p class="muted">Per-process measurements · empirical nearest-rank percentiles</p>'
        '<nav class="downloads" aria-label="Download data"><a href="summary.json">Summary JSON</a>'
        '<a href="summary.csv">Metric CSV</a></nav>'
        f'<div class="panel {style}"><div class="status">{_escape(status)} <code>{_escape(summary["status"])}</code></div>'
        f'<p>Producer finalized: {"yes" if summary["complete"] else "no"} · Evidence successful: {"yes" if summary["successful"] else "no"}</p>'
        f'{status_detail}</div><div class="cards">{cards}</div>'
        f'<div class="panel"><b>Non-warmup outcomes</b><div class="outcomes">{outcomes}</div>'
        f'<details><summary>Warmup outcomes</summary><div class="outcomes">{warmup_outcomes}</div></details></div>'
        '<div class="panel notice"><b>Read exact n before interpreting tail percentiles.</b>'
        '<p>For n &lt; 20, p95 and p99 are the observed maximum. For n = 1, all three percentiles repeat one value.</p>'
        '<details><summary>How to read these measurements</summary>'
        '<p>Each row is one case, configuration, run, process, phase, cache mode and outcome. '
        'Runs and processes are never pooled. Exact n counts measured values, not warmups, unavailable values or censored bounds. '
        'Record totals can include a separate final process-peak record; they are not operation sample counts.</p>'
        '<p>For fewer than 100 exact samples, p99 is the observed maximum. More samples alone do not establish tail stability. '
        'Expected rejection means the negative test returned its expected result. '
        'Displayed values are rounded; expand “Exact values and scope” for precise recorded units.</p></details></div>'
        f'<nav aria-label="Cases"><ul class="jump">{jump}</ul></nav>'
        + ("".join(main) if main else '<p class="panel">No measured populations are available.</p>')
        + '<details class="audit"><summary>Combined outcome distributions (audit view)</summary>'
        '<p>These repeat the same attempts across outcomes within each process. They are not additional measurements '
        'and do not pool processes. Success and failure values can coexist here; use the separate outcomes above.</p>'
        f'{combined}</details><details class="audit"><summary>Provenance and full report metadata</summary>'
        f'<p>The downloadable JSON also includes every group and attempt identifier.</p><pre>{_json(overview)}</pre></details>'
        '<footer>Measurements describe this experiment and are not production capacity or budget recommendations.</footer>'
        '</main></body></html>\n'
    )
