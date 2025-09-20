import json
import subprocess
import logging
from fastapi import APIRouter, HTTPException

from ..schemas.scan import ScanImageRequest, ScanImageResponse


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan-image", response_model=ScanImageResponse)
async def scan_image(request: ScanImageRequest):
    try:
        image_name = request.image_name.strip()
        if not image_name:
            raise HTTPException(status_code=400, detail="image_name is required and cannot be empty")

        command = ["trivy", "image", "--format", "json", "--quiet", image_name]
        logger.info(f"Scanning image: {image_name}")

        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=300, check=False
            )
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy scan timed out for image: {image_name}")
            raise HTTPException(status_code=408, detail="Scan timed out. The image might be too large or the registry is slow.")
        except FileNotFoundError:
            logger.error("Trivy command not found")
            raise HTTPException(status_code=500, detail="Trivy command not found. Please ensure it is installed and in PATH.")

        if result.returncode != 0:
            error_message = result.stderr.strip() if result.stderr else "Unknown error occurred"
            logger.error(f"Trivy scan failed for {image_name}: {error_message}")
            if "image not found" in error_message.lower() or "name unknown" in error_message.lower():
                raise HTTPException(status_code=404, detail=f"Image not found: {image_name}")
            elif "unauthorized" in error_message.lower():
                raise HTTPException(status_code=401, detail=f"Unauthorized to access image: {image_name}")
            else:
                raise HTTPException(status_code=500, detail=f"Trivy scan failed: {error_message}")

        try:
            if not result.stdout.strip():
                logger.warning(f"Empty output from Trivy for image: {image_name}")
                return ScanImageResponse(message="No vulnerabilities found", data=[])

            trivy_output = json.loads(result.stdout)
            logger.info(f"Successfully scanned image: {image_name}")
            return ScanImageResponse(message="Scan completed successfully", data=trivy_output)
        except json.JSONDecodeError:
            logger.error("Failed to parse Trivy JSON output")
            logger.error(f"Raw stdout: {result.stdout}")
            raise HTTPException(status_code=500, detail="Failed to parse Trivy output")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during image scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error occurred during scan")


