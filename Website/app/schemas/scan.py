from pydantic import BaseModel
from typing import Optional, Dict, Any


class ScanImageRequest(BaseModel):
    image_name: str


class ScanImageResponse(BaseModel):
    message: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


