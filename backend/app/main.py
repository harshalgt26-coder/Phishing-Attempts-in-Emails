from __future__ import annotations

import os
from pathlib import Path
from typing import List

import ujson
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse

from .config import get_settings
from .schemas import EmailInput, AttachmentMeta, DetectionResult
from .detection.engine import run_detection

app = FastAPI(title="Phishing Detection API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "phishing-detection"})


@app.post("/detect", response_model=DetectionResult)
async def detect_email(
    subject: str = Form("") ,
    body_text: str | None = Form(None),
    body_html: str | None = Form(None),
    sender_email: str = Form(...),
    sender_display_name: str | None = Form(None),
    attachments: List[UploadFile] | None = File(None),
):
    attachment_metas: List[AttachmentMeta] = []
    if attachments:
        for file in attachments:
            attachment_metas.append(
                AttachmentMeta(
                    filename=file.filename,
                    mime_type=file.content_type,
                    size_bytes=None,
                )
            )

    email = EmailInput(
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        sender_email=sender_email,
        sender_display_name=sender_display_name,
        attachments=attachment_metas,
    )

    result = run_detection(email)
    return result


@app.get("/samples")
async def list_samples():
    settings = get_settings()
    samples_dir = Path(settings.samples_dir)
    samples: List[dict] = []
    if samples_dir.exists():
        for p in sorted(samples_dir.glob("*.json")):
            try:
                data = ujson.loads(p.read_text())
                samples.append({"id": p.stem, **data})
            except Exception:
                continue
    return JSONResponse({"samples": samples})
