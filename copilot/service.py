"""Grounded incident-response question-answering service."""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .guardrails import redact_secrets, validate_prompt
from .retrieval import TfIdfRetriever, load_markdown_documents


class Responder(Protocol):
    def answer(self, question: str, context: list[str]) -> str: ...


class BaselineResponder:
    """Deterministic baseline used for tests before an external LLM is connected."""

    def answer(self, question: str, context: list[str]) -> str:
        if not context:
            return "I do not have enough runbook evidence to answer that safely."
        joined = " ".join(context)
        sentences = [part.strip() for part in joined.replace("\n", " ").split(".") if part.strip()]
        useful = sentences[:4]
        return ". ".join(useful) + ("." if useful else "")


@dataclass(frozen=True)
class CopilotAnswer:
    answer: str
    citations: tuple[str, ...]
    retrieval_scores: tuple[float, ...]


class IncidentCopilot:
    def __init__(self, knowledge_dir: str | Path, responder: Responder | None = None):
        docs = load_markdown_documents(knowledge_dir)
        self.retriever = TfIdfRetriever(docs)
        self.responder = responder or BaselineResponder()

    def ask(self, question: str, top_k: int = 2, min_score: float = 0.05) -> CopilotAnswer:
        validate_prompt(question)
        results = [item for item in self.retriever.search(question, top_k=top_k) if item.score >= min_score]

        if not results:
            return CopilotAnswer(
                "I do not have enough runbook evidence to answer that safely.",
                (),
                (),
            )

        context = [redact_secrets(item.document.text) for item in results]
        answer = redact_secrets(self.responder.answer(question, context))
        citations = tuple(item.document.doc_id for item in results)
        scores = tuple(item.score for item in results)
        return CopilotAnswer(answer, citations, scores)
