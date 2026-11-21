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
"""Knowledge tool: retrieval-augmented grounding for coaching and remediation advice."""

from typing import Annotated, Any

from pydantic import Field

from ..core.knowledge_base import get_knowledge_base
from ..observability.tracing import traced_operation
from ._common import tool_error

_MAX_QUERY_CHARS = 500


def search_firewall_best_practices(
    query: Annotated[
        str,
        Field(min_length=1, max_length=_MAX_QUERY_CHARS,
              description="Short keyword query, e.g. 'internet exposed ssh iap' or 'shadowed deny rule priority'."),
    ],
    max_results: Annotated[int, Field(ge=1, le=5, description="Number of articles to return (1-5).")] = 3,
) -> dict[str, Any]:
    """Searches the curated Google Cloud firewall best-practice knowledge base.

    Use this to ground explanations and remediation advice in vetted guidance
    instead of model memory. Cite the returned kb_id values in your answer.

    Args:
        query: Short natural-language query, e.g. "internet exposed ssh iap" or
            "hierarchical policy evaluation order".
        max_results: Number of articles to return (1-5).

    Returns:
        status "success" with articles (kb_id, title, relevance_score, guidance,
        related_checks, references) ranked by vector similarity; or status
        "error" with a recovery_hint.
    """
    query = (query or "").strip()
    if not query or len(query) > _MAX_QUERY_CHARS:
        return tool_error("invalid_arguments", f"query must be 1-{_MAX_QUERY_CHARS} characters.",
                          "Retry with a short keyword query such as 'redis exposed to internet'.")
    max_results = max(1, min(5, int(max_results)))
    with traced_operation("knowledge_base.search", query=query, max_results=max_results) as span:
        results = get_knowledge_base().search(query, max_results=max_results)
        span.set_attribute("firewall_ops.results", len(results))
    if not results:
        return {"status": "success", "results_returned": 0, "articles": [],
                "note": "No matching guidance. Try different keywords (e.g. a service name or check ID)."}
    return {
        "status": "success",
        "results_returned": len(results),
        "articles": [
            {"kb_id": article.id, "title": article.title, "relevance_score": score, "guidance": article.content,
             "related_checks": article.check_ids, "references": article.references}
            for article, score in results
        ],
    }
