import json
import asyncio

from ...analyzer import analyze
from ...domain.schemas import LLMReview
from ...db import now


class AnalysisService:
    """编排确定性规则与可选 LLM 复核，不让模型覆盖规则证据。"""

    def __init__(self, database, llm_client=None):
        self.database = database
        self.llm_client = llm_client

    async def analyze_submission(self, project_id: int, submission_id: int, filename: str, code: str) -> dict:
        static_findings = await asyncio.to_thread(analyze, code, filename)
        llm_review: LLMReview | None = None
        llm_error = None
        if self.llm_client:
            try:
                llm_review = await self.llm_client.review(filename, code)
            except Exception as error:
                llm_error = str(error)[:2000]
                key = getattr(getattr(self.llm_client, "settings", None), "api_key", "")
                if key:
                    llm_error = llm_error.replace(key, "[REDACTED]")
        analysis_id = await asyncio.to_thread(self._persist, project_id, submission_id, filename, static_findings, llm_review, llm_error)
        return {"id": analysis_id, "submission_id": submission_id, "static": static_findings,
                "llm": llm_review.model_dump() if llm_review else None, "llm_error": llm_error,
                "llm_status": "success" if llm_review else ("failed" if llm_error else "disabled")}

    def _persist(self, project_id, submission_id, filename, static_findings, llm_review, llm_error):
        # Commit the review, findings and analysis link together; failed writes roll back.
        with self.database.connect() as connection:
            return self._persist_on(connection, project_id, submission_id, filename, static_findings, llm_review, llm_error)

    def _persist_on(self, connection, project_id, submission_id, filename, static_findings, llm_review, llm_error):
        timestamp = now()
        connection.execute("DELETE FROM vulnerabilities WHERE project_id=? AND (vuln_code LIKE ? OR vuln_code LIKE ?)",
                           (project_id, f"S-{submission_id}-%", f"AI-{submission_id}-%"))
        llm_analysis_id = self.database.insert_on(
            connection, "llm_analyses", project_id=project_id, filename=filename,
            submission_id=submission_id,
            provider="openai_compatible" if self.llm_client else "disabled",
            model=getattr(getattr(self.llm_client, "settings", None), "model", ""),
            status="success" if llm_review else ("failed" if llm_error else "disabled"),
            summary=llm_review.summary if llm_review else (llm_error or "未启用大语言模型"),
            result_json=json.dumps(llm_review.model_dump() if llm_review else {}, ensure_ascii=False), created_at=timestamp,
        )
        for finding in static_findings:
            self.database.insert_on(
                connection, "vulnerabilities", project_id=project_id, vuln_code=f"S-{submission_id}-{finding['line_number']}-{finding['rule_id']}",
                vuln_title=finding["vuln_title"], risk_level=finding["risk_level"], file_path=finding["file_path"],
                line_number=finding["line_number"], rule_id=finding["rule_id"], impact_text=finding["impact_text"],
                condition_text=finding["condition_text"], evidence_text=finding["evidence_text"], verify_status="static_confirmed",
                reproduce_steps_text=finding["reproduce_steps_text"], verify_code_text=finding["verify_code_text"],
                remediation_text=finding["remediation_text"], created_at=timestamp,
            )
        if llm_review:
            for index, finding in enumerate(llm_review.findings, start=1):
                self.database.insert_on(
                    connection, "vulnerabilities", project_id=project_id, vuln_code=f"AI-{submission_id}-{index}",
                    vuln_title=finding.title, risk_level=finding.risk_level,
                    file_path=finding.file_path, line_number=finding.line_number, rule_id=f"LLM:{finding.rule_id}"[:80],
                    impact_text=finding.impact, condition_text=finding.condition,
                    evidence_text=finding.evidence or "大模型建议的源码位置，须与实际提交代码人工核验。",
                    verify_status="needs_review", reproduce_steps_text="人工核对大模型提供的文件、行号及触发前提；不可直接用于生产环境。",
                    verify_code_text=f"大模型置信度：{finding.confidence:.2f}。非自动验证结果。",
                    remediation_text=finding.remediation, created_at=timestamp,
                )
        return self.database.insert_on(
            connection, "submission_analyses", project_id=project_id, submission_id=submission_id,
            static_result_json=json.dumps(static_findings, ensure_ascii=False), llm_analysis_id=llm_analysis_id, created_at=timestamp,
        )
