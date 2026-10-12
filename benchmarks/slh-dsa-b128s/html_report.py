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
    "rss_before_bytes": "RSS at interval start",
    "rss_after_bytes": "RSS at interval end",
    "rss_current_bytes": "Current RSS",
    "process_peak_rss_bytes": "Process lifetime peak RSS",
    "cgroup_cpu_core_equivalents": "Cgroup CPU / wall time",
    "cgroup_memory_current_bytes": "Current cgroup memory",
    "cgroup_memory_peak_bytes": "Cgroup lifetime peak memory",
    "mempool_transactions": "Mempool transaction count · gauge",
    "mempool_bytes": "Mempool encoded bytes · gauge",
    "mempool_cost": "Mempool cost · gauge",
    "mempool_growth_transactions_per_second": "Net transaction count growth",
    "mempool_growth_bytes_per_second": "Net encoded byte growth",
    "public_key_bytes": "Public key size",
    "signature_bytes": "Signature size",
    "message_bytes": "Message size",
    "transaction_bytes": "Serialized transaction size",
    "authorization_bytes": "Authorization size",
    "descriptor_bytes": "Descriptor size",
    "payment_inventory_ns": "Generated inventory and enrollment",
    "payment_wallet_setup_ns": "Fresh wallet setup and sync",
    "payment_prepare_persist_ns": "Payment preparation and durable writes",
    "payment_sign_persist_ns": "Signing and durable writes",
    "payment_assemble_persist_ns": "Assembly and durable writes",
    "payment_assembly_ns": "Classical transaction assembly",
    "payment_sign_ns": "Classical transaction signing",
    "payment_verify_ns": "Complete authorization verification",
    "payment_total_ns": "Foreground payment total",
    "input_count": "Transparent input count",
    "signature_count": "Authorization signature count",
}
_PRIMARY_METRICS = ("keygen_ns", "sign_release_ns", "signature_verify_ns")
_PAYMENT_METRICS = ("payment_total_ns", "payment_inventory_ns", "payment_wallet_setup_ns",
                    "payment_prepare_persist_ns", "payment_sign_persist_ns", "payment_assemble_persist_ns",
                    "payment_assembly_ns", "payment_sign_ns", "payment_verify_ns")
_NODE_METRICS = ("process_cpu_core_equivalents", "rss_current_bytes",
                 "cgroup_cpu_core_equivalents", "cgroup_memory_current_bytes",
                 "mempool_transactions", "mempool_bytes", "mempool_cost",
                 "mempool_growth_transactions_per_second", "mempool_growth_bytes_per_second")
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
.good{border-left:4px solid #18815a}.status{font-size:18px;font-weight:650}
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
.timing-overview td{padding:7px 13px}.timing-overview .outcome{margin:0}.timing-overview td:first-child{min-width:190px}
.timing-overview code{display:block;font-size:11px}.timing-overview .notes{min-width:210px;width:25%}
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
    ordered = _PRIMARY_METRICS + _PAYMENT_METRICS
    return (ordered.index(name) if name in ordered else len(ordered), name)


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
    if name == "process_peak_rss_bytes" and samples:
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


def _outcome(outcome):
    label = outcome.replace("_", " ")
    if outcome == "expected_rejection":
        label += " · expected result"
    style = "outcome-good" if outcome in ("success", "expected_rejection") else "outcome-issue"
    if outcome == "all_outcomes":
        style = ""
    return f'<span class="outcome {style}">{_escape(label)}</span>'


def _population(group, catalog, index):
    scope = "".join(f'<span><b>{label}:</b> {_escape(group[key])}</span>' for label, key in (
        ("Run", "run_id"), ("Configuration", "configuration_id"), ("Phase", "phase"), ("Cache", "cache_mode")))
    header = (
        f'<header><h3>{_escape(group["process_id"])} {_outcome(group["outcome"])}</h3>'
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
    return f'<section class="population" id="population-{index}">{header}{content}</section>'


def _timing_overview(groups, metrics=_PRIMARY_METRICS, *, title="Primitive timing overview",
                     anchor="timing-overview", label_each_metric=False):
    timing_groups = [group for group in groups if group["outcome"] != "all_outcomes"
                     and any(name in group["metrics"] for name in metrics)]
    dimensions = (("Run", "run_id"), ("Configuration", "configuration_id"),
                  ("Phase", "phase"), ("Cache", "cache_mode"))
    varying = [(label, key) for label, key in dimensions
               if len({group[key] for group in timing_groups}) > 1]
    rows = []
    for index, group in enumerate(groups):
        if group["outcome"] == "all_outcomes":
            continue
        for name in metrics:
            if name not in group["metrics"]:
                continue
            metric = group["metrics"][name]
            samples = metric["samples"]
            notes = []
            if samples == 0:
                notes.append("No exact samples")
            elif samples == 1:
                notes.append("One sample; all percentiles repeat it")
            elif samples < 20:
                notes.append("Small n: p95 = p99 = observed max")
            elif samples < 100:
                notes.append("Small n: p99 = observed max")
            for field, label in (("missing_count", "missing"), ("unavailable_count", "unavailable"),
                                 ("censored_count", "censored")):
                if metric[field]:
                    notes.append(f'{metric[field]} {label}')
            if metric["tail_incomplete"]:
                notes.append("Incomplete tail")
            coverage = "".join(f'<div class="caution">{_escape(note)}</div>' for note in notes)
            scope = "".join(f'<code>{label}: {_escape(group[key])}</code>' for label, key in varying)
            if label_each_metric or sum(candidate in group["metrics"] for candidate in metrics) > 1:
                scope += f'<code>{_escape(_LABELS.get(name, name))}</code>'
            values = "".join(f'<td class="number">{_value(metric[key], metric["unit"])}</td>'
                             for key in ("p50", "p95", "p99"))
            rows.append(
                f'<tr><td><strong>{_escape(group["case_id"])}</strong>'
                f'<code>{_escape(group["process_id"])}</code>{scope}</td>'
                f'<td>{_outcome(group["outcome"])}</td>{values}'
                f'<td class="number">{_escape(samples)}</td><td class="notes">{coverage}'
                f'<a href="#population-{index}">Full metrics and scope</a></td></tr>'
            )
    if not rows:
        return ""
    shared = "".join(f'<p><b>{label}:</b> <code>{_escape(timing_groups[0][key])}</code></p>'
                     for label, key in dimensions if (label, key) not in varying)
    return (
        f'<section id="{_escape(anchor)}"><h2>{_escape(title)}</h2>'
        '<p class="muted">One row per recorded case, process and outcome. No pooling. '
        'Small samples do not establish stable tail percentiles.</p>'
        + (f'<details><summary>Shared measurement scope</summary>{shared}</details>' if shared else "") +
        '<div class="panel table-wrap timing-overview" style="padding:0"><table><thead><tr>'
        '<th scope="col">Case / process</th><th scope="col">Outcome</th>'
        '<th scope="col">p50 · median</th><th scope="col">p95</th><th scope="col">p99</th>'
        '<th scope="col">Exact n</th><th scope="col">Coverage / details</th></tr></thead><tbody>'
        + "".join(rows) + '</tbody></table></div></section>'
    )


def _node_scope(summary):
    provenance = summary.get("provenance", {})
    scope = provenance.get("node_scope")
    if not scope:
        return ""
    profile = provenance.get("node_profile", {})
    identity = provenance.get("node_identity", {})
    workload = profile.get("workload", {})
    elapsed = provenance.get("node_execution", {}).get("elapsed_ns")
    schedule = (
        f'{_escape(scope.get("samples", "Unavailable"))} intervals × '
        f'{_escape(scope.get("interval_ms", "Unavailable"))} ms requested delay between observations; '
        f'{_escape(scope.get("planned_interval_total_ms", "Unavailable"))} ms total requested delay.'
    )
    comparison_notice = (
        '<p class="caution">Matched comparison unavailable: this node build receipt does not record '
        'build-time Cargo configuration and compiler settings. Existing measurements remain readable.</p>'
    ) if summary.get("compatibility", {}).get("toolchain") is None else ""
    budget = scope.get("time_budget", {})
    budget_notice = (
        f'<p><b>Full request allowances:</b> {_escape(budget.get("maximum_request_total_ms"))} ms; '
        f'{_escape(budget.get("remaining_after_delays_and_requests_ms"))} ms remains after delays and requests. '
        'Startup, the binary hash and local I/O also consume time; completion is not guaranteed.</p>'
        + (f'<p class="caution">{_escape(budget["warning"])}</p>' if budget.get("warning") else "")
    ) if budget else ""
    evidence = {"identity": identity, "profile": profile, "scope": scope,
                "build": provenance.get("node_build"),
                "toolchain": provenance.get("toolchain"),
                "execution": provenance.get("node_execution")}
    return (
        '<section id="node-scope" class="panel notice"><h2>Attached node collection</h2>'
        f'<p><b>Schedule:</b> {schedule}</p>'
        f'{budget_notice}'
        f'<p><b>Sampler elapsed:</b> {_value(elapsed, "ns")} (includes collection overhead; '
        'actual rate intervals use the recorded monotonic collection windows).</p>'
        f'<p><b>Node:</b> {_escape(profile.get("network", "Unavailable"))} · '
        f'PID {_escape(profile.get("pid", "Unavailable"))} · '
        f'<code>{_escape(profile.get("binary_path", "Unavailable"))}</code></p>'
        f'<p><b>Build variant:</b> {_escape(provenance.get("node_build", {}).get("kind", "Unavailable"))}</p>'
        f'<p><b>Declared workload:</b> <code>{_escape(workload.get("id", "Unavailable"))}</code> · '
        f'{_escape(workload.get("description", "Unavailable"))}</p>'
        f'<p><b>Declared state / activity:</b> {_escape(workload.get("state", "Unavailable"))} / '
        f'{_escape(workload.get("activity", "Unavailable"))}</p>'
        '<p>Percentiles describe repeated resource intervals and mempool snapshots, '
        'not transaction or block latency. Each interval produces separate process, mempool '
        'and optional cgroup records. No isolated validation, admission, propagation or bandwidth measurement is made.</p>'
        '<p>CPU / wall time is CPU use over each actual interval. RSS and cgroup memory are point samples. '
        'Mempool count, encoded bytes and cost are gauges; growth is a signed net change per second, '
        'not arrival or removal throughput. Attached process and cgroup lifetime peaks are unavailable. '
        'An observed sample maximum does not establish peak memory.</p>'
        f'{comparison_notice}'
        '<details><summary>Node identity, source and collection evidence</summary>'
        '<p>The operator declares the workload and associates the metrics endpoint with this process. '
        'Collection does not launch a node, send transactions or mine blocks. '
        'Hashes identify the retained binary, configuration, source receipt and declared fixture evidence; '
        'they do not establish that the declared workload ran.</p>'
        f'<pre>{_json(evidence)}</pre></details></section>'
    )


def render_report(summary, catalog):
    """Render all populations, preserving outcome and process boundaries."""
    groups = summary["groups"]
    cases = sorted({group["case_id"] for group in groups})
    processes = {(group["run_id"], group["process_id"]) for group in groups}
    status = summary["status"].replace("_", " ").capitalize()
    style = "good" if summary["successful"] else "notice"
    issues = "".join(f'<li>{_escape(issue)}</li>' for issue in summary["issues"])
    status_detail = '<ul>' + issues + '</ul>' if issues else ""
    cards = "".join(f'<div class="card"><strong>{value:,}</strong><span>{label}</span></div>' for value, label in (
        (len(cases), "cases"), (len(processes), "process populations"),
        (summary["observation_count"], "non-warmup records"), (summary["warmup_count"], "warmup records")))
    timing_count = sum(group["observation_count"] for group in groups
                       if group["outcome"] != "all_outcomes"
                       and any(name in group["metrics"] for name in _PRIMARY_METRICS))
    payment_count = sum(group["observation_count"] for group in groups
                        if group["outcome"] != "all_outcomes"
                        and any(name in group["metrics"] for name in _PAYMENT_METRICS))
    peak_count = sum(group["observation_count"] for group in groups
                     if group["outcome"] != "all_outcomes"
                     and set(group["metrics"]) == {"process_peak_rss_bytes"})
    record_note = ""
    if timing_count or peak_count or payment_count:
        other_count = summary["observation_count"] - timing_count - peak_count - payment_count
        other = f" · {other_count} other records" if other_count else ""
        payments = f" · {payment_count} wallet/payment records" if payment_count else ""
        record_note = (f'<p class="muted">{timing_count} primitive timing records · '
                       f'{peak_count} separate process-peak records{payments}{other}. Exact n varies per metric.</p>')
    storage = summary.get("provenance", {}).get("wallet_storage")
    storage_notice = (
        '<details><summary>Registered wallet storage</summary>'
        f'<p><b>Root:</b> <code>{_escape(storage["root"])}</code></p>'
        f'<p><b>Device / directory:</b> {_escape(storage["st_dev"])} / {_escape(storage["st_ino"])}</p>'
        '<p>Storage descriptions below are operator declarations; they do not establish power-loss durability.</p>'
        f'<pre>{_json(storage["profile"])}</pre></details>'
    ) if storage else (
        '<p class="caution">Wallet storage identity is unavailable. '
        'These records cannot establish matched persistence comparisons.</p>'
    )
    payment_notice = (
        '<div class="panel notice"><b>Wallet stages and classical controls have different boundaries.</b>'
        '<p>SLH preparation, signing and assembly include the actual durable wallet writes within each stage. '
        'The classical cases measure matched transparent transactions, with no equivalent durable wallet workflow. '
        'Compare exact transaction bytes and explicitly matched operations; do not compare their total times as equivalent wallet payments.</p>'
        '<p>Cached inventory is prepared outside foreground timing, so no inventory duration is shown for cached cases. '
        'Generated inventory is inside the foreground interval. Both SLH modes derive secret signing keys through the actual wallet. '
        'Classical cached controls reuse prepared secp256k1 key pairs. '
        'Every SLH attempt sets up fresh watch stores with empty journals. '
        'These modes do not establish cold or warm processor caches.</p>'
        '<p>Foreground total is measured directly. Never add stage p50, p95 or p99 values to obtain a total. '
        'Registered payment runs verify artifacts after the measured process exits, outside its timing. '
        'Their funding is an offline synthetic fixture. Imported timing records remain operator-supplied evidence; '
        'their presence here does not establish independent checks or live chain acceptance.</p>'
        + storage_notice + '</div>'
    ) if payment_count else ""
    node_notice = _node_scope(summary)
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
        populations = "".join(_population(group, catalog, group_index) for group_index, group in enumerate(groups)
                              if group["case_id"] == case and group["outcome"] != "all_outcomes")
        main.append(f'<section id="case-{index}"><h2>{_escape(case)}</h2>{populations}</section>')
    combined = "".join(
        f'<h3>{_escape(group["case_id"])}</h3>{_population(group, catalog, group_index)}'
        for group_index, group in enumerate(groups) if group["outcome"] == "all_outcomes")
    overview = {key: value for key, value in summary.items() if key != "groups"}
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>SLH benchmark report</title><style>{_STYLE}</style></head><body><main>'
        '<h1>SLH benchmark report</h1><p class="muted">Per-process measurements · empirical nearest-rank percentiles</p>'
        '<nav class="downloads" aria-label="Download data"><a href="summary.json">Summary JSON</a>'
        '<a href="summary.csv">Metric CSV</a></nav>'
        f'<div class="panel {style}"><div class="status">{_escape(status)}</div>'
        f'<p>Producer finalized: {"yes" if summary["complete"] else "no"} · Evidence successful: {"yes" if summary["successful"] else "no"}</p>'
        f'{status_detail}<div class="outcomes"><b>Non-warmup outcomes:</b>{outcomes}</div></div>'
        f'<div class="cards">{cards}</div>{record_note}{payment_notice}{node_notice}{_timing_overview(groups)}'
        f'{_timing_overview(groups, _PAYMENT_METRICS, title="Wallet/payment stage overview", anchor="payment-overview")}'
        + (_timing_overview(groups, _NODE_METRICS, title="Node resource and mempool overview",
                            anchor="node-overview", label_each_metric=True)
           if node_notice else "") +
        '<div class="panel notice"><b>Read exact n before interpreting tail percentiles.</b>'
        '<p>With 1–19 exact samples, p95 and p99 are the observed maximum. With one sample, all three percentiles repeat one value.</p>'
        '<details><summary>How to read these measurements</summary>'
        '<p>Each row is one case, configuration, run, process, phase, cache mode and outcome. '
        'Runs and processes are never pooled. Exact n counts measured values, not warmups, unavailable values or censored bounds. '
        'Record totals can include a separate final process-peak record; they are not operation sample counts.</p>'
        '<p>With 1–99 exact samples, p99 is the observed maximum. More samples alone do not establish tail stability. '
        'Expected rejection means the negative test returned its expected result. '
        'Displayed values are rounded; expand “Exact values and scope” for precise recorded units. '
        'The timing overview repeats the linked distributions and adds no measurements.</p></details>'
        f'<details><summary>Warmup outcomes</summary><div class="outcomes">{warmup_outcomes}</div></details></div>'
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
