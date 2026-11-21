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

variable "project_id" {
  description = "Project that hosts the agent (Agent Runtime, logs, traces, secrets)."
  type        = string
}

variable "region" {
  description = "Region for Agent Runtime (Agent Engine) deployment. Models are called on the 'global' endpoint."
  type        = string
  default     = "us-central1"
}

variable "agent_name" {
  description = "Short name used for the service account and related resources (6-30 chars, lowercase)."
  type        = string
  default     = "firewall-ops-agent"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.agent_name))
    error_message = "agent_name must be 6-30 lowercase letters, digits or hyphens and start with a letter."
  }
}

variable "audited_project_ids" {
  description = "Projects whose VPC firewall rules the agent may read. Defaults to project_id when empty."
  type        = list(string)
  default     = []
}

variable "organization_id" {
  description = "Optional numeric organization ID; grants read access to organization firewall policies."
  type        = string
  default     = ""
}

variable "folder_ids" {
  description = "Optional numeric folder IDs; grants read access to folder firewall policies."
  type        = list(string)
  default     = []
}

variable "enable_live_remediation" {
  description = "Grant a narrow custom role that can patch existing VPC firewall rules on audited projects. Keep false unless approved changes should be applied by the agent."
  type        = bool
  default     = false
}

variable "create_api_key_secret" {
  description = "Create a Secret Manager secret for a Gemini API key (developer API mode only; Agent Platform mode uses the service account and needs no key)."
  type        = bool
  default     = false
}
