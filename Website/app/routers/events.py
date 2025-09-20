import json
from datetime import datetime, timedelta
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from fastapi import Query


router = APIRouter(prefix="/api", tags=["events"])


def load_events():
    with open("events.json", "r") as f:
        return json.load(f)


def filter_events(events, minutes):
    time_threshold = datetime.utcnow() - timedelta(minutes=minutes)
    return [event for event in events if datetime.fromisoformat(event["timestamp"]) >= time_threshold]


@router.get("/events")
def get_events_json(minutes: int = Query(5)):
    try:
        events = load_events()
        filtered = filter_events(events, minutes)
        return JSONResponse(content=filtered)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


