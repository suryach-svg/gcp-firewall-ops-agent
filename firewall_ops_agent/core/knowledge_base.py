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
"""Lightweight vector retrieval over the firewall best-practice knowledge base.

Articles are embedded as TF-IDF vectors and ranked by cosine similarity. This
keeps retrieval deterministic and offline for tests and grading. The
``KnowledgeBaseIndex.search`` interface is the seam for swapping in a managed
vector store (for example Vertex AI Search or Vector Search) in production.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

KNOWLEDGE_BASE_PATH = Path(__file__).resolve().parent.parent / "data" / "firewall_knowledge_base.json"

_TOKEN = re.compile(r"[a-z0-9][a-z0-9._/-]*")
_STOPWORDS = frozenset(
    "a an and are as at be by can do does for from how i if in into is it its me my of on or our should so "
    "that the their them then there these this to use what when where which who why will with you your".split()
)


def tokenize(text: str) -> list[str]:
    """Lowercases and splits text into search tokens, dropping stopwords."""
    tokens = []
    for token in _TOKEN.findall(text.lower()):
        token = token.strip("._/-")
        if token and token not in _STOPWORDS:
            tokens.append(token)
    return tokens


@dataclass
class Article:
    """One knowledge base article."""

    id: str
    title: str
    content: str
    check_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


class KnowledgeBaseIndex:
    """In-memory TF-IDF index with cosine-similarity search."""

    def __init__(self, articles: list[Article]) -> None:
        self.articles = articles
        docs = [self._document_tokens(a) for a in articles]
        doc_freq: Counter[str] = Counter()
        for tokens in docs:
            doc_freq.update(set(tokens))
        n_docs = len(docs)
        self._idf = {term: math.log((1 + n_docs) / (1 + df)) + 1.0 for term, df in doc_freq.items()}
        self._vectors = [self._vectorize(tokens) for tokens in docs]

    @staticmethod
    def _document_tokens(article: Article) -> list[str]:
        # Titles and tags are weighted more heavily than body text.
        return (
            tokenize(article.title) * 3
            + tokenize(" ".join(article.tags)) * 2
            + tokenize(" ".join(article.check_ids)) * 3
            + tokenize(article.content)
        )

    def _vectorize(self, tokens: list[str]) -> dict[str, float]:
        counts = Counter(tokens)
        vector = {t: (1 + math.log(c)) * self._idf.get(t, 0.0) for t, c in counts.items() if t in self._idf}
        norm = math.sqrt(sum(v * v for v in vector.values())) or 1.0
        return {t: v / norm for t, v in vector.items()}

    def search(self, query: str, max_results: int = 3) -> list[tuple[Article, float]]:
        """Returns up to ``max_results`` (article, score) pairs, best first."""
        query_vector = self._vectorize(tokenize(query))
        scored = []
        for article, vector in zip(self.articles, self._vectors, strict=True):
            score = sum(weight * vector.get(term, 0.0) for term, weight in query_vector.items())
            if score > 0:
                scored.append((article, round(score, 4)))
        scored.sort(key=lambda pair: (-pair[1], pair[0].id))
        return scored[:max_results]

    def by_check_id(self, check_id: str) -> list[Article]:
        """Articles explicitly linked to a risk check such as 'FW-001'."""
        return [a for a in self.articles if check_id.upper() in a.check_ids]


@lru_cache(maxsize=1)
def get_knowledge_base(path: Path = KNOWLEDGE_BASE_PATH) -> KnowledgeBaseIndex:
    """Loads and indexes the knowledge base once per process."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    articles = [Article(**item) for item in raw["articles"]]
    return KnowledgeBaseIndex(articles)
