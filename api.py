
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from core.malware_ensemble_engine import (
    predict_malware_ensemble,
    get_engine_status as get_malware_engine_status,
)
from core.phishing_ensemble_engine import (
    predict_phishing_ensemble,
    get_engine_status as get_phishing_engine_status,
)

app = FastAPI(
    title="CyberShield AI API",
    description="API for the existing CyberShield AI detection engines",
    version="1.0.0",
)

# Local development frontend. Restrict origins when deploying.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


class PhishingRequest(BaseModel):
    url: HttpUrl


@app.get("/")
def home():
    return {
        "app": "CyberShield AI",
        "status": "running",
        "message": "Detection API is online.",
    }


@app.get("/api/health")
def health():
    result = {
        "api_status": "running",
        "malware_engine": "unknown",
        "phishing_engine": "unknown",
    }

    try:
        result["malware_engine"] = get_malware_engine_status()
    except Exception as exc:
        result["malware_engine"] = {
            "error": str(exc),
        }

    try:
        result["phishing_engine"] = get_phishing_engine_status()
    except Exception as exc:
        result["phishing_engine"] = {
            "error": str(exc),
        }

    return result


@app.post("/api/scan/malware")
async def scan_malware(file: UploadFile = File(...)):
    """
    Save an uploaded file temporarily and pass its path to
    the existing malware ensemble. The file is never executed.
    """
    temp_path = None

    try:
        original_name = Path(file.filename or "uploaded_file").name
        suffix = Path(original_name).suffix[:20]

        total_size = 0

        with tempfile.NamedTemporaryFile(
            prefix="cybershield_",
            suffix=suffix,
            delete=False,
        ) as temp_file:
            temp_path = temp_file.name

            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds the 25 MB upload limit.",
                    )

                temp_file.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="The uploaded file is empty.",
            )

        # Run the existing model; do not execute the uploaded file.
        result = predict_malware_ensemble(temp_path)

        return {
            "success": True,
            "filename": original_name,
            "file_size_bytes": total_size,
            "engine": "malware_ensemble_engine",
            "result": result,
        }

    except HTTPException:
        raise
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"File processing failed: {exc}",
        ) from exc
    except Exception as exc:
        # Log technical details in the server terminal only.
        print("Malware API error:", repr(exc))
        raise HTTPException(
            status_code=500,
            detail="Malware analysis failed. Check the backend terminal.",
        ) from exc
    finally:
        await file.close()

        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                print("Warning: could not remove temporary upload file.")


@app.post("/api/scan/phishing")
def scan_phishing(request: PhishingRequest):
    url = str(request.url)

    try:
        result = predict_phishing_ensemble(url)

        if not result.get("success", False):
            raise HTTPException(
                status_code=503,
                detail=result.get(
                    "message",
                    "The phishing model could not complete prediction.",
                ),
            )

        return {
            "success": True,
            "engine": "phishing_ensemble_engine",
            "result": result,
        }

    except HTTPException:
        raise
    except Exception as exc:
        print("Phishing API error:", repr(exc))
        raise HTTPException(
            status_code=500,
            detail="Phishing analysis failed. Check the backend terminal.",
        ) from exc
