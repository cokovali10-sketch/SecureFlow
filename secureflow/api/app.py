"""FastAPI application for SecureFlow."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from secureflow import __version__
from secureflow.scanners.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)

app = FastAPI(
    title="SecureFlow API",
    description="Security platform for analyzing software projects",
    version=__version__,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str = Field(..., description="Path to scan")
    scanners: Optional[list[str]] = Field(None, description="Specific scanners to run")
    options: Optional[dict[str, Any]] = Field(None, description="Scan options")


class FindingResponse(BaseModel):
    id: str
    scanner: str
    rule: str
    severity: str
    confidence: str
    title: str
    description: str
    file: str
    line: int
    evidence: str
    remediation: str
    status: str
    fingerprint: str


class ScanResponse(BaseModel):
    target: str
    total_findings: int
    active_findings: int
    findings_by_severity: dict[str, int]
    findings_by_scanner: dict[str, int]
    duration_seconds: float
    risk_score: float
    scanners_used: list[str]
    findings: list[FindingResponse]


class HealthResponse(BaseModel):
    status: str
    version: str
    scanners: list[str]


@app.get("/api/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        scanners=ScanOrchestrator.list_scanners().keys().__iter__().__next__() if False else [],
    )


@app.get("/api/scanners")
async def list_scanners() -> dict[str, dict[str, str]]:
    return ScanOrchestrator.list_scanners()


@app.post("/api/scan", response_model=ScanResponse)
async def run_scan(request: ScanRequest) -> ScanResponse:
    target = Path(request.target)
    if not target.exists():
        raise HTTPException(status_code=400, detail=f"Target does not exist: {request.target}")

    orchestrator = ScanOrchestrator()
    result, assessment = orchestrator.scan_with_assessment(
        target, request.scanners, request.options
    )

    return ScanResponse(
        target=result.target,
        total_findings=result.total_findings,
        active_findings=result.active_findings,
        findings_by_severity=result.findings_by_severity,
        findings_by_scanner=result.findings_by_scanner,
        duration_seconds=result.duration_seconds,
        risk_score=assessment.score,
        scanners_used=result.scanner_used,
        findings=[
            FindingResponse(
                id=f.id,
                scanner=f.scanner.value,
                rule=f.rule,
                severity=f.severity.value,
                confidence=f.confidence.value,
                title=f.title,
                description=f.description,
                file=f.location.file_path,
                line=f.location.line,
                evidence=f.evidence,
                remediation=f.remediation,
                status=f.status.value,
                fingerprint=f.fingerprint,
            )
            for f in result.findings
        ],
    )


@app.get("/api/version")
async def get_version() -> dict[str, str]:
    return {"version": __version__, "name": "SecureFlow"}
