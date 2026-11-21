# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Infrastructure for the GCP Firewall Ops Agent:
#   * required APIs
#   * a dedicated least-privilege runtime service account (no keys are created)
#   * read-only firewall access on audited projects / org / folders
#   * optional write access for approved live remediation
#   * optional Secret Manager secret (value added out-of-band, never in TF state)
#   * a log-based metric that counts guardrail and policy blocks

locals {
  services = [
    "aiplatform.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "cloudtrace.googleapis.com",
    "compute.googleapis.com",
    "dlp.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "secretmanager.googleapis.com",
    "storage.googleapis.com",
    "telemetry.googleapis.com",
  ]
  agent_member     = "serviceAccount:${google_service_account.agent.email}"
  audited_projects = toset(length(var.audited_project_ids) > 0 ? var.audited_project_ids : [var.project_id])
  runtime_roles = [
    "roles/aiplatform.user",         # call Gemini models, sessions and Memory Bank
    "roles/logging.logWriter",       # structured JSON logs
    "roles/monitoring.metricWriter", # ADK metrics
    "roles/cloudtrace.agent",        # Cloud Trace
    "roles/telemetry.tracesWriter",  # OpenTelemetry (OTLP) traces via telemetry.googleapis.com
    "roles/dlp.user",                # optional Sensitive Data Protection redaction of memories
  ]
}

resource "google_project_service" "required" {
  for_each           = toset(local.services)
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "agent" {
  project      = var.project_id
  account_id   = var.agent_name
  display_name = "GCP Firewall Ops Agent runtime"
  description  = "Least-privilege identity for the Firewall Ops Agent on Agent Runtime or Cloud Run. No keys are issued."
  depends_on   = [google_project_service.required]
}

resource "google_project_iam_member" "runtime" {
  for_each = toset(local.runtime_roles)
  project  = var.project_id
  role     = each.value
  member   = local.agent_member
}

# Read-only access to VPC firewall rules (includes compute.firewalls.list and
# compute.networks.getEffectiveFirewalls for inherited-policy analysis).
resource "google_project_iam_member" "firewall_reader" {
  for_each = local.audited_projects
  project  = each.value
  role     = "roles/compute.networkViewer"
  member   = local.agent_member
}

# Write access only when explicitly enabled, through a narrow custom role: patch
# existing VPC firewall rules and wait for the operation. It cannot create or
# delete rules (unlike the broad roles/compute.securityAdmin). Every change still
# requires human approval inside the agent (apply_firewall_remediation), a change
# ticket, and ENABLE_LIVE_REMEDIATION=true.
resource "google_project_iam_custom_role" "firewall_remediator" {
  for_each    = var.enable_live_remediation ? local.audited_projects : toset([])
  project     = each.value
  role_id     = "${replace(var.agent_name, "-", "_")}_remediator"
  title       = "Firewall Ops Agent remediator"
  description = "Patch existing VPC firewall rules after human approval. Cannot create or delete rules."
  permissions = [
    "compute.firewalls.get",
    "compute.firewalls.update",
    "compute.networks.updatePolicy",
    "compute.globalOperations.get",
  ]
}

resource "google_project_iam_member" "firewall_remediator" {
  for_each = google_project_iam_custom_role.firewall_remediator
  project  = each.value.project
  role     = each.value.name
  member   = local.agent_member
}

# Read hierarchical firewall policies (compute.firewallPolicies.get/list).
resource "google_organization_iam_member" "org_policy_reader" {
  count  = var.organization_id == "" ? 0 : 1
  org_id = var.organization_id
  role   = "roles/compute.orgFirewallPolicyUser"
  member = local.agent_member
}

resource "google_folder_iam_member" "folder_policy_reader" {
  for_each = toset(var.folder_ids)
  folder   = "folders/${each.value}"
  role     = "roles/compute.orgFirewallPolicyUser"
  member   = local.agent_member
}

# Optional secret for developer API-key mode. Add the value out-of-band:
#   printf '%s' "$KEY" | gcloud secrets versions add <secret_id> --data-file=-
resource "google_secret_manager_secret" "gemini_api_key" {
  count     = var.create_api_key_secret ? 1 : 0
  project   = var.project_id
  secret_id = "${var.agent_name}-gemini-api-key"

  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_iam_member" "agent_reads_api_key" {
  count     = var.create_api_key_secret ? 1 : 0
  project   = var.project_id
  secret_id = google_secret_manager_secret.gemini_api_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = local.agent_member
}

# Observability: count guardrail and policy blocks emitted by the agent's JSON logs.
resource "google_logging_metric" "guardrail_blocks" {
  project     = var.project_id
  name        = "${var.agent_name}-guardrail-blocks"
  description = "Requests or tool calls blocked by the agent's security guardrails."
  filter      = "jsonPayload.event=\"guardrail_blocked\" OR jsonPayload.event=\"policy_blocked\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
  depends_on = [google_project_service.required]
}
