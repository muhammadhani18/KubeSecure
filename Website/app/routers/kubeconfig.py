import logging
from typing import Dict

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends

from ..core.auth import decode_token
from ..core.mongo import get_db
from ..core.crypto import encrypt_bytes


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/kubeconfig", tags=["kubeconfig"]) 


@router.post("/upload")
async def upload_kubeconfig(file: UploadFile = File(...), user_email: str = Depends(decode_token)) -> Dict:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Empty file")

        # Encrypt kubeconfig content
        try:
            encrypted = encrypt_bytes(content)
        except Exception as exc:
            logger.error(f"Encryption failed: {exc}")
            raise HTTPException(status_code=500, detail="Encryption configuration error")

        db = get_db()
        user = db.users.find_one({"email": user_email})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        db.kubeconfigs.update_one(
            {"user_id": str(user["_id"])},
            {"$set": {"filename": file.filename, "data": encrypted}},
            upsert=True,
        )

        return {"message": "Kubeconfig stored securely"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Failed to store kubeconfig: {exc}")
        raise HTTPException(status_code=500, detail="Failed to store kubeconfig")


