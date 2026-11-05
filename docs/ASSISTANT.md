# Project assistant

Projects → *Assistant* answers questions about one project with Claude (`claude-opus-5-5`), through the Anthropic Messages API. The code is `src-tauri/src/commands/assistant.rs`.

## Setup

The application owner provisions an Anthropic API key with `cyberhub-keys set anthropic` ([PROVISIONING.md](PROVISIONING.md)). As with every other credential, there is no way to enter, read or change it in the app; the web view only learns whether the assistant is configured. `cyberhub-keys test anthropic` checks the key by listing models, which uses no tokens.

## What is sent, and when

* **Nothing before the first question.** The first question of a conversation sends the question and the project data the user selected: scope and rules of engagement, assets, vulnerabilities, findings, recent activity. Every record is one line, and the data is limited to 150,000 characters.
* **Credentials are redacted** (`redact_text`) before anything is sent.
* **The data can be inspected first.** *Preview exactly what is sent* shows the text.
* **Native confirmation.** Before sending, a system dialog names the destination (api.anthropic.com), the model, the sections and their size. Cancelling sends nothing.
* **Follow-up questions** in the same conversation reuse the data already sent, and send only the new question.
* **Conversations are kept in memory only**, never written to disk. Closing Cyber Hub or starting a new conversation forgets them. The activity log records that a question was asked and the token counts, not the content. Anthropic's own data retention applies to what was sent.

## Prompt-injection design

Project data comes from targets and public sources (page titles, DNS names, OSINT text, tool output) and can contain text written to steer a model. The design limits what such text could do:

* **No tools.** The model cannot run scans, contact targets, read files or change anything, so injected instructions have nothing to act on. At most they could distort an answer, which the analyst reads.
* **Data is marked as data.** It is sent inside `<project_data>` tags, separate from the question. The system prompt (operator instructions, stable across requests) says to treat everything inside as data and never to follow instructions found in it.
* **Answers are shown as plain text**, not as rendered HTML, so an answer cannot inject markup into the app.

## API usage

| Setting | Value |
|---|---|
| Endpoint | `POST https://api.anthropic.com/v1/messages` (no redirects followed, 300 s time limit, at most 4 MB read) |
| Headers | `x-api-key`, `anthropic-version: 2026-10-21`, `anthropic-beta: server-side-fallback-2026-07-01` |
| Model | `claude-opus-5-5`; thinking at the model's default (adaptive), `output_config.effort: medium`, `max_tokens: 16000` |
| Fallback | `fallbacks: "default"`: if a safety classifier declines, the API retries on a fallback model in the same call; the answer says when a fallback model answered |
| Caching | automatic prompt caching (`cache_control: ephemeral`), so follow-up questions reuse the system prompt and project data |
| History | earlier assistant turns are sent back exactly as returned (required for preserved thinking) |

* **Errors.** A refusal of the whole chain (`stop_reason: refusal`) is shown with its category. An answer cut off at the length limit says so. Errors are mapped to readable messages: rejected key (401/403), rate limit with `retry-after` (429), service unavailable (5xx/529), invalid request with the API's message. None of them contain the key.
* **Limits.** A question is limited to 8,000 characters and a conversation to 30 turns.
