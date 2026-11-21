# Learning guide: course concepts to code

Use this guide to study the codebase one concept at a time. Each stop maps a concept from the 5-day AI agents
course to the files that implement it, with a short exercise. Plan 15-30 minutes per stop.

## Before you start

```bash
source .venv/bin/activate
make test        # everything should pass offline
make web         # optional: chat with the agent (needs gcloud auth application-default login)
```

## Day 1: Agents and the "model + harness" idea

| Concept | Where to look | What to notice |
| --- | --- | --- |
| Agent = model + tools + orchestration | `firewall_ops_agent/agent.py` | The coordinator is an `LlmAgent` with sub-agents; the `App` adds plugins (the harness). |
| System instructions (the "constitution") | `firewall_ops_agent/prompts.py` | Persona, procedure, constraints and output format per agent; shared safety rules. |
| Grounding vs. hallucination | `core/risk_engine.py`, `core/grounding.py` | Code decides the risks; a verifier checks the LLM's report against the data. |
| Levels of agents | `sub_agents/` | Level 3: specialists collaborating through a coordinator and a pipeline. |

Exercise: run `make test`, then open `tests/test_end_to_end_offline.py:test_audit_pipeline_end_to_end` and follow
the order of tool calls it asserts.

## Day 2: Tools, schemas and MCP

| Concept | Where to look | What to notice |
| --- | --- | --- |
| Python functions as tools | `tools/inventory_tools.py` | ADK reads the type hints and docstring to build the tool schema. |
| Parameter schemas | `tools/inventory_tools.py` (`ScopeIdArg`, `RuleNameArg`) | `Annotated[..., Field(...)]` adds enums, patterns, bounds and descriptions the model sees. |
| Async tools | `tools/_common.py:load_rules` | Slow Google Cloud calls run in a worker thread so other users are not blocked. |
| Docstrings and naming | every function in `tools/` | `Args:` and `Returns:` tell the model when and how to call the tool. |
| JSON schemas (Pydantic) | `schemas.py` | `ScopeRequest` validates IDs before anything touches Google Cloud. |
| Guided errors | `tools/_common.py:tool_error`, `map_exception_to_error` | Errors include a `recovery_hint` the model can act on. |
| Self-correction | `guardrails/policy_plugin.py:GuidedToolErrorReflectionPlugin` | Errors become reflection guidance with limited retries. |
| MCP (concept) | `tools/` | These tools are local functions; the same tools could be published through an MCP server so other agents can use them. |

Exercise: in a Python shell started in the repo folder, run
`import asyncio; from tests.conftest import FakeToolContext; from firewall_ops_agent.tools.inventory_tools import list_firewall_rules_for_scope`
then `asyncio.run(list_firewall_rules_for_scope("organization", "abc", FakeToolContext()))` and read the guided
error. (The tool is `async`, so it must be run with `asyncio.run`.)

## Day 3: Context engineering, sessions and memory

| Concept | Where to look | What to notice |
| --- | --- | --- |
| Session state | `tools/_common.py` (state keys) | Big data is stored in state, one key per audited scope; tools return compact views. |
| Passing context between agents | `sub_agents/audit_pipeline.py` (`output_key`), `prompts.py` (`{risk_analysis?}`) | Each step writes its result to state; the next step reads it from its instructions. |
| History compaction and caching | `agent.py:build_app` | `EventsCompactionConfig` (sliding window + token threshold) and `ContextCacheConfig`. |
| Persistent sessions | `memory/services.py:build_session_service` | SQLite/Cloud SQL locally, Agent Platform Sessions when deployed. |
| Long-term memory | `memory/services.py`, coach's `load_memory` tool | Memories are scrubbed for PII and written in the background. |

Exercise: run `make chat`, audit a project, exit, then resume with `--session <id>` and ask about the last audit.

## Day 4: Quality, safety and multi-agent design

| Concept | Where to look | What to notice |
| --- | --- | --- |
| Coordinator and sequential patterns | `agent.py`, `sub_agents/audit_pipeline.py` | LLM-driven delegation plus a fixed four-step pipeline. |
| Model routing | `config.py`, `routing.py` | Fast model by default; the coach escalates for hard questions, the writer for big inventories; fallback on errors. |
| Guardrails | `guardrails/input_guardrails.py`, `guardrails/policy_plugin.py` | Attacks are blocked before any model call, but normal firewall questions pass. |
| Human in the loop | `tools/remediation_tools.py:apply_firewall_remediation` | `request_confirmation` pauses the agent until a person approves. |
| Logging, tracing, PII | `observability/` | Intent and outcome logs, OpenTelemetry spans, and redaction of user messages, logs, memories and spans. |
| Evaluation | `eval/`, `tests/test_agent_evaluation.py` | Golden dataset for the engine, ADK eval set for agent behaviour. |

Exercise: run `python -m eval.run_golden_eval`, then change one severity in `core/risk_engine.py` and watch the
evaluation fail. Revert your change afterwards.

## Day 5: From prototype to production

| Concept | Where to look | What to notice |
| --- | --- | --- |
| Infrastructure as code | `infra/terraform/` | Least-privilege service account, IAM, APIs, Secret Manager, log metric. |
| Deployment | `Makefile:deploy`, README | `adk deploy agent_engine` to Agent Runtime with OpenTelemetry. |
| Agents CLI | `agents-cli-manifest.yaml`, README "Use the Agents CLI" | `agents-cli info`, `playground`, `run`, `lint`, `eval run`, `deploy`. |
| CI/CD | `.github/workflows/ci.yml` | Lint, tests, evals and Terraform checks on every push; keyless live eval. |
| Secrets | `config.py:configure_model_credentials`, `.env.example` | No keys in code; Secret Manager for the optional developer key. |

Exercise: read `docs/RUBRIC_EVIDENCE.md` and, for each criterion, open the file and find the evidence yourself.

## Glossary of project terms

- **Scope**: an organization, folder or project to audit.
- **Inherited policies**: organization and folder firewall policy rules that also apply to a project's VMs.
- **Shadowed rule**: a rule that never takes effect because an earlier rule with the opposite action matches first.
- **Mitigated**: an exposure that exists in a project rule but is blocked by a higher-level deny today.
- **Posture score**: 0-100 (higher is better), capped at 59 if any CRITICAL finding exists.
