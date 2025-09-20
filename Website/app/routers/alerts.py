from fastapi import APIRouter

from ..core.firebase import get_db_ref


router = APIRouter(prefix="/get-alerts", tags=["alerts"])


@router.get("")
async def get_alerts():
    alerts_ref = get_db_ref("alerts")
    alerts_data = alerts_ref.get()
    if not alerts_data:
        return {"message": "No alerts found"}

    alerts_list = [
        {"id": key, "message": value.get("message", ""), "timestamp": value.get("timestamp", 0)}
        for key, value in alerts_data.items()
    ]
    return {"alerts": alerts_list}


