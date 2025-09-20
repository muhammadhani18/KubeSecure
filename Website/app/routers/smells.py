import os
import tempfile
import yaml
from fastapi import APIRouter, UploadFile, HTTPException

from ..services.yaml_smells import load_yaml, detect_code_smells


router = APIRouter(prefix="/api", tags=["smells"])


@router.post("/detect-smells")
async def detect_smells(file: UploadFile):
    if not file.filename.endswith((".yaml", ".yml")):
        raise HTTPException(status_code=400, detail="File must be a YAML file.")

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as temp_file:
            temp_file.write(await file.read())
            temp_file_path = temp_file.name

        manifests = load_yaml(temp_file_path)
        smells = detect_code_smells(manifests)
        os.remove(temp_file_path)

        return {"smells": smells}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")


