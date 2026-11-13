# Workflow automation

Projects → *Automation* chains built-in steps into workflows. A workflow belongs to one project. It runs by hand or, if it only has passive steps, on a schedule while ExploitX is open. The definitions are in `src-tauri/src/workspace/workflows.rs`, the executor in `src-tauri/src/commands/workflows.rs`, and the tables in schema 11.

## No arbitrary code

A workflow is a list of steps of predefined types with validated settings. There is no script, expression, command or URL step, so a workflow cannot do anything that the matching manual action in ExploitX cannot do:
* Definitions with unknown step types, unknown settings or unknown fields are refused (`deny_unknown_fields`, per-type setting schemas).
* Target lists are trimmed and deduplicated. Entries that contain spaces or control characters, or that start with `-` (option injection), are refused.

| Step | Contacts targets | Settings | Retries | Default / max time |
|---|---|---|---|---|
| Passive discovery | no | none | up to 3 | 15 min / 1 h |
| Check web services | yes | hosts (optional, ≤ 100; in-scope defaults otherwise) | up to 3 | 15 min / 1 h |
| Service scan | yes | targets (1–64), ports profile (100 or 1,000 most common) | no | 1 h / 4 h |
| Update vulnerability scores | no (NVD and EPSS lookups) | none | up to 3 | 5 min / 30 min |
| Save project report | no | evidence title (optional) | no | 1 min / 5 min |
| Wait | no | seconds (1–3600) | no | ~1 h |
| Correlate records | no (local) | none | up to 3 | 5 min / 30 min |
| Verify evidence | no (local) | none | up to 3 | 5 min / 1 h |
| Wait for a recorded result | no | result: file triage, log or event log triage, packet capture triage, imported scan results, SBOM or lockfile, API definition, ATT&CK layer | no | 1 h / 4 h |

A workflow has 1 to 20 steps.

## Safety rules

* **Confirmation.** A manual run of a workflow with steps that contact targets starts only after a native confirmation. The dialog lists those steps and their targets: hosts are resolved and scope-checked first, and the run does not start if a target is out of scope or the project is not active.
* **Scope at run time.** Each step goes through the same code as the manual action, so the scope gate checks it again when it runs. A scope change in the meantime is respected, and refusals are recorded in the scope history.
* **Service scans** also show the execution engine's own confirmation of the exact Nmap command, like any tool run.
* **Schedules** (every 1 to 720 hours) are accepted only for workflows without steps that contact targets. The definition is checked again before every scheduled run; a run that is not allowed is skipped. Scheduled runs need no confirmation because nothing they do contacts a target: passive steps ask public sources only, and private or internal names are never sent.
* **One run at a time** per workflow, and one discovery at a time per project (a step waits for nothing: it fails with a clear message if another discovery runs).

## Execution

* Steps run in order.
* **Time limits.** Each attempt has a time limit. A step that exceeds it is stopped: its discovery snapshot is closed as failed, and a scan's process tree is terminated.
* **Retries.** Failures of retryable steps are retried after 5 s × attempt. A cancellation is never retried.
* **Failures.** A failed step stops the run unless it is set to *continue on error*. The remaining steps are recorded as skipped.
* **Cancellation.** It stops the running step (and its discovery) and marks the remaining steps as cancelled.
* **Result.** The run is *succeeded* (all steps), *partial* (some failed but the run continued), *failed* or *cancelled*.
* **Records.** Every run stores a copy of the definition it ran, and each step its state, attempts, summary and a log (the last 64 KB). Runs appear on the project timeline. Runs interrupted by closing ExploitX are marked failed at the next start, along with their running and pending steps.

**Investigation steps** (Mission 3). *Correlate records* runs the correlation rules ([DATA_MODEL.md](DATA_MODEL.md#correlation)); matches are only suggestions. *Verify evidence* checks every stored file and text against its SHA-256 and records the result on each record; it fails when a record does not match, naming the first three. *Wait for a recorded result* waits until the analyst records a result of the chosen kind in the project: a utility result recorded with its evidence (file, log or event log, packet capture triage), an imported scan, an SBOM or lockfile, an API definition or an ATT&CK layer. Results recorded since the run started count, including before the step began. ExploitX never runs the capability itself: the analyst chooses the file in its native dialog and confirms anything that contacts a service, so a playbook cannot do anything the analyst did not do. The step ends with the time limit when nothing is recorded, and a cancellation stops it.

## Templates

| Template | Steps |
|---|---|
| Passive attack surface refresh | passive discovery (1 retry, continue on error), update vulnerability scores (continue on error), save report; can be scheduled |
| External exposure check | passive discovery, check web services |
| Service baseline | service scan (targets to fill in), save report |
| Playbook: suspicious file | wait for a file triage (2 h), correlate, verify evidence (continue on error), save report |
| Playbook: incident logs | wait for a log or event log triage (2 h), correlate, verify evidence (continue on error), save report |
| Playbook: vulnerable dependency | wait for an SBOM or lockfile (2 h; the OSV.dev check stays in the Components tab, which asks first), update vulnerability scores (continue on error), correlate, save report |
| Playbook: web application | passive discovery (1 retry, continue on error), check web services (confirmed when the run starts), wait for imported scanner results (4 h), correlate, save report |
| Playbook: cloud account | wait for an imported cloud audit such as Prowler OCSF (2 h), correlate, verify evidence (continue on error), save report |

Playbooks are workflows like any other: they keep their runs, step states, summaries and logs, appear on the timeline, can be cancelled, and are run again to retry (every step is safe to repeat: correlation keeps decisions, recorded results are not duplicated, each report is a new evidence record).

## Tests

The driver is tested with simulated steps. The tests cover:
* ordering and stopping after a failure;
* retries and continue on error (a partial run);
* time limits;
* cancellation, which is not retried and cancels the rest.

Validation tests cover unknown step types, settings and fields, option-like targets, ranges, retries on steps that cannot retry, and schedules with active steps. Persistence tests cover runs, steps and logs, one run at a time, and due schedules. A database test checks that interrupted runs are recovered.
