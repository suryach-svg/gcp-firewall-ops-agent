# Developer shortcuts for the GCP Firewall Ops Agent.
PY ?= python3
PROJECT ?= $(GOOGLE_CLOUD_PROJECT)
REGION ?= us-central1
PORT ?= 8080
SA ?= firewall-ops-agent@$(PROJECT).iam.gserviceaccount.com
PROMPT ?= Audit project prod-payments-app including inherited org and folder policies
AGENTS_CLI = AGENTS_CLI_TELEMETRY=0 agents-cli

.PHONY: install test lint eval-golden eval-live web run chat infra-init infra-plan infra-apply deploy \
	agents-setup agents-info playground agents-run agents-lint

install:            ## Install runtime + dev dependencies
	$(PY) -m pip install -r requirements-dev.txt

test:               ## Offline tests (unit, end-to-end with scripted model, ADK evaluator, golden)
	$(PY) -m pytest -q

lint:               ## Static checks
	ruff check .

eval-golden:        ## Deterministic risk-engine regression evaluation
	$(PY) -m eval.run_golden_eval

eval-live:          ## Real Gemini evaluation (needs credentials)
	RUN_LIVE_EVAL=1 $(PY) -m pytest tests/test_agent_evaluation.py -m live -q

web:                ## ADK dev UI with persistent local sessions (Cloud Shell: Web Preview on $(PORT))
	mkdir -p .adk_data
	adk web --port $(PORT) --session_service_uri=sqlite:///./.adk_data/adk_web_sessions.db .

run:                ## ADK terminal runner
	adk run firewall_ops_agent

chat:               ## Project CLI: persistent sessions + memory + interactive approvals
	$(PY) -m scripts.chat_cli

# ---- Agents CLI (agents-cli-manifest.yaml describes this project to the CLI) ----
agents-setup:       ## Install the Agents CLI skills into your coding agent (optional)
	uvx google-agents-cli setup

agents-info:        ## Show how the Agents CLI sees this project
	$(AGENTS_CLI) info

playground:         ## Agents CLI local playground (alternative to `make web`)
	$(AGENTS_CLI) playground --port $(PORT)

agents-run:         ## One-shot prompt through the Agents CLI: make agents-run PROMPT="..."
	$(AGENTS_CLI) run "$(PROMPT)"

agents-lint:        ## Agents CLI code-quality checks
	$(AGENTS_CLI) lint

# ---- Infrastructure as code ----
infra-init:         ## Terraform init
	terraform -chdir=infra/terraform init

infra-plan:         ## Terraform plan (uses infra/terraform/terraform.tfvars)
	terraform -chdir=infra/terraform plan

infra-apply:        ## Terraform apply
	terraform -chdir=infra/terraform apply

deploy:             ## Deploy to Agent Runtime with ADK, using the least-privilege service account
	adk deploy agent_engine --project=$(PROJECT) --region=$(REGION) \
		--display_name="GCP Firewall Ops Agent" --service_account=$(SA) --otel_to_cloud firewall_ops_agent
