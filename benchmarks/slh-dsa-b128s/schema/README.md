# Result contract, version 1

The [metric catalog](metrics.json) fixes each metric's unit and measurement
boundary. A record cannot supply a different unit. Nanoseconds, bytes and
counts must be JSON integers. CPU ratios and rates can be fractional.
Mempool growth rates can be negative. Other metrics must be nonnegative;
effective CPU entitlement must be positive. Boolean and nonfinite numbers are
not measurements. Numeric magnitudes cannot exceed `2**64 - 1`.

Each JSONL line is one attempt with these required fields:

| Field | Contract |
| --- | --- |
| `schema_version` | Integer `1`. |
| `run_id`, `case_id`, `configuration_id`, `process_id`, `attempt_id`, `phase`, `cache_mode` | Tokens of 1 to 128 ASCII letters, digits, `_`, `.`, `:`, or `-`. The first character must be a letter or digit. |
| `warmup` | Boolean. Warmups remain in counts but never enter quantiles. |
| `outcome` | `success`, `expected_rejection`, `unexpected_rejection`, `timeout`, `cancelled`, or `error`. |
| `metrics` | Object from registered metric name to numeric value or `null`. |
| `unavailable` | Exactly one nonempty reason for each null metric. No extra entries. |
| `censored` | Distinct metric names whose numeric values are lower bounds. A success cannot contain censored values. |
| `details` | Optional bounded JSON object, for collector scope and event references. |

Unknown fields are errors. An attempt's identity is
`(run_id, process_id, attempt_id)`, even if its case changes. Duplicate identities
are errors. A retry needs a new identity. An attempt emits all its metrics in
one record. Null means unavailable, never zero.

Input uses UTF-8 JSONL with a final newline for every record. Duplicate JSON
keys, blank lines, partial final lines and invalid records are errors. The
reader does not silently discard them. Limits are 64 KiB per input line,
100,000 records, 64 MiB total input and 10,000 summary groups. Details also have
a 16 KiB encoded bound. JSON depth, item counts and individual strings are
bounded in the validator. These are import limits, not benchmark workload
recommendations.

## Distribution and completion rules

Each distribution keeps run, case, configuration, process, phase, cache mode
and outcome separate. A second group named `all_outcomes` contains all outcomes
for those same dimensions. All groups refer to their raw attempt IDs. Warmup
attempt IDs and outcome counts stay visible.

For sorted exact observations `x` of length `n`, percentile `p` is
`x[ceil(n * p / 100) - 1]`. Thus p50 uses the lower middle observation when `n`
is even. Every numeric metric gets p50, p95 and p99. Empty distributions get
null quantiles and an explicit reason. A one-sample peak-RSS distribution
contains one process lifetime peak. It does not describe operation-level peaks.

Censored lower bounds never enter exact quantiles. Their count and minimum and
maximum bounds remain visible. Missing and unavailable values have separate
counts. A missing or censored tail sets `tail_incomplete`; remaining exact
quantiles do not establish the full population's tail. Small samples cannot
establish tail stability.

`complete` means the producer finalized and reconciled the input. The result
layer cannot infer that fact from a plausible last record. Its default is
incomplete. `successful` also requires non-warmup observations, no unexpected
outcomes, no censored or unavailable values, and no missing measurements within
a group. Attempts with no metrics cannot make a successful result. Expected
rejections can be successful evidence. Warmup errors prevent success.

The runner must verify expected attempt counts, required case metrics, process
exit and collector closure before it passes `complete=True`. This prevents a
wholly absent case or metric from escaping the result layer's union-of-observed
metrics check.

## Reports and comparisons

`write_reports` creates `summary.json`, `summary.csv` and `report.html` and
refuses to replace existing report files. All external HTML text is escaped.
Caller-supplied metadata, including source hashes and compatibility information,
stays in JSON and the HTML overview. Reports contain counts and completion
status beside the quantiles.

Comparisons require finalized, measured summaries with the current schema and
catalog hash. The runner supplies a nonempty `compatibility` object with
source-independent hardware, workload, cache, compiler and instrumentation
identity. The objects must match exactly. Source revisions can differ and stay
in separate source metadata.

Comparisons match case, configuration, phase, cache and outcome. They preserve
both run and process identities. Multiple processes for one matched population
are ambiguous: select explicit process runs before comparison. The tool never
averages quantiles or silently pools repeated processes. Differences are
descriptive; they do not establish statistical significance. Relative change
is null for a zero baseline or an unrepresentable floating-point ratio.
