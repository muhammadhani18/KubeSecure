#!/bin/bash
export XDG_RUNTIME_DIR=/run/user/$UID
systemctl --user restart telebit
~/telebit http 8000
source venv/bin/activate  # Adjust if your venv is in a different location
cd /home/hani/Desktop/new\ fyp/KubeSecure/Website/app
uvicorn main:app --host 0.0.0.0 --port 8000
