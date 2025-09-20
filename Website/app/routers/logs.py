from typing import List, Dict, Any, Optional

from fastapi import APIRouter, Query, Depends

from ..core.mongo import get_db
from ..core.auth import decode_token


router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("/all")
def get_all_pod_logs(
	q_namespace: Optional[str] = Query(default=None, description="Filter by namespace"),
	q_container: Optional[str] = Query(default=None, description="Filter by container"),
	user_email: str = Depends(decode_token),
) -> Dict[str, Any]:
	db = get_db()
	user = db.users.find_one({"email": user_email})
	if not user:
		return {"count": 0, "logs": [], "errors": [{"error": "User not found"}]}

	query: Dict[str, Any] = {"user_id": str(user["_id"]) }
	if q_namespace:
		query["namespace"] = q_namespace
	if q_container:
		query["container"] = q_container

	items = list(db.logs.find(query).sort("_id", -1).limit(500))
	logs: List[Dict[str, Any]] = [
		{
			"namespace": it.get("namespace"),
			"pod": it.get("pod"),
			"container": it.get("container"),
			"lines": it.get("lines", []),
		}
		for it in items
	]
	return {"count": len(logs), "logs": logs, "errors": []}


