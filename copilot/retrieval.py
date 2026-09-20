"""Small, dependency-free retrieval layer for security runbooks."""

from dataclasses import dataclass
from pathlib import Path
import math
import re
from collections import Counter

TOKEN_RE = re.compile(r"[a-z0-9_-]+")


@dataclass(frozen=True)
class Document:
    doc_id: str
    title: str
    text: str


@dataclass(frozen=True)
class SearchResult:
    document: Document
    score: float


def tokenize(text: str) -> list[str]:
    """Tokenize text and add security-domain signatures for high-signal patterns."""
    lowered = text.lower()
    tokens = TOKEN_RE.findall(lowered)

    signatures: list[str] = []
    if "../" in lowered or "..\\" in lowered or "%2e%2e" in lowered:
        signatures.extend(["path_traversal"] * 3)
    if "union select" in lowered or "or 1=1" in lowered or "drop table" in lowered:
        signatures.extend(["sql_injection"] * 3)
    if (
        "failed login" in lowered
        or "authentication failed" in lowered
        or "authentication failures" in lowered
        or "password spraying" in lowered
    ):
        signatures.extend(["brute_force"] * 3)

    return tokens + signatures


def load_markdown_documents(path: str | Path) -> list[Document]:
    docs: list[Document] = []
    for file_path in sorted(Path(path).glob("*.md")):
        text = file_path.read_text(encoding="utf-8")
        first_line = next(
            (line.strip("# ").strip() for line in text.splitlines() if line.startswith("#")),
            file_path.stem,
        )
        docs.append(Document(file_path.stem, first_line, text))
    return docs


class TfIdfRetriever:
    """Transparent TF-IDF cosine retriever suitable for deterministic evaluation."""

    def __init__(self, documents: list[Document]):
        if not documents:
            raise ValueError("documents cannot be empty")
        self.documents = documents
        self._doc_tokens = [Counter(tokenize(doc.text)) for doc in documents]
        self._idf = self._build_idf()

    def _build_idf(self) -> dict[str, float]:
        vocabulary = set().union(*(counts.keys() for counts in self._doc_tokens))
        total = len(self.documents)
        return {
            term: math.log(
                (1 + total) / (1 + sum(term in counts for counts in self._doc_tokens))
            )
            + 1
            for term in vocabulary
        }

    def _vector(self, counts: Counter[str]) -> dict[str, float]:
        return {term: freq * self._idf.get(term, 1.0) for term, freq in counts.items()}

    @staticmethod
    def _cosine(left: dict[str, float], right: dict[str, float]) -> float:
        common = set(left) & set(right)
        numerator = sum(left[t] * right[t] for t in common)
        left_norm = math.sqrt(sum(value * value for value in left.values()))
        right_norm = math.sqrt(sum(value * value for value in right.values()))
        if not left_norm or not right_norm:
            return 0.0
        return numerator / (left_norm * right_norm)

    def search(self, query: str, top_k: int = 3) -> list[SearchResult]:
        query_vector = self._vector(Counter(tokenize(query)))
        scored = [
            SearchResult(doc, round(self._cosine(query_vector, self._vector(counts)), 4))
            for doc, counts in zip(self.documents, self._doc_tokens)
        ]
        return sorted(scored, key=lambda item: item.score, reverse=True)[:top_k]
