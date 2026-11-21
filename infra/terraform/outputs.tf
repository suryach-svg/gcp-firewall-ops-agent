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

output "agent_service_account_email" {
  description = "Runtime identity to pass to `adk deploy agent_engine --service_account`."
  value       = google_service_account.agent.email
}

output "gemini_api_key_secret" {
  description = "Secret resource for GOOGLE_API_KEY_SECRET (only when create_api_key_secret = true)."
  value       = var.create_api_key_secret ? "${google_secret_manager_secret.gemini_api_key[0].id}/versions/latest" : null
}

output "deploy_command" {
  description = "Command to deploy the agent to Agent Runtime with this identity."
  value       = "adk deploy agent_engine --project=${var.project_id} --region=${var.region} --display_name='GCP Firewall Ops Agent' --service_account=${google_service_account.agent.email} --otel_to_cloud firewall_ops_agent"
}
