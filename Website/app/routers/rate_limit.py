import json
import subprocess
from fastapi import APIRouter, Form


router = APIRouter(tags=["rate_limit"])


REVERT_COMMAND = [
    "kubectl",
    "patch",
    "ingress",
    "calculator-ingress",
    "-n",
    "default",
    "--type=json",
    "-p",
    '[{"op": "remove", "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-rps"},'
    '{"op": "remove", "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-burst"},'
    '{"op": "remove", "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-connections"}]',
]


@router.post("/revert_rate_limit")
def revert_rate_limit():
    try:
        subprocess.run(REVERT_COMMAND, check=True)
        return {"message": "Rate limiting reverted successfully"}
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to revert rate limiting: {e}"}


@router.post("/apply_rate_limit")
def apply_rate_limit(user_value: int = Form(...)):
    patch_data = json.dumps(
        [
            {
                "op": "add",
                "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-rps",
                "value": str(user_value),
            },
            {
                "op": "add",
                "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-burst",
                "value": str(user_value + 10),
            },
            {
                "op": "add",
                "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-connections",
                "value": str(user_value + 20),
            },
        ]
    )

    patch_command = [
        "kubectl",
        "patch",
        "ingress",
        "calculator-ingress",
        "-n",
        "default",
        "--type=json",
        "-p",
        patch_data,
    ]

    try:
        subprocess.run(patch_command, check=True)
        return {"message": "Rate limiting applied successfully"}
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to apply rate limiting: {e}"}


@router.get("/check_rate_limit")
def check_rate_limit():
    try:
        result = subprocess.run(
            ["kubectl", "get", "ingress", "calculator-ingress", "-n", "default", "-o", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        ingress_data = json.loads(result.stdout)
        annotations = ingress_data.get("metadata", {}).get("annotations", {})

        rate_limits = {
            "limit-rps": annotations.get("nginx.ingress.kubernetes.io/limit-rps"),
            "limit-burst": annotations.get("nginx.ingress.kubernetes.io/limit-burst"),
            "limit-connections": annotations.get("nginx.ingress.kubernetes.io/limit-connections"),
        }

        applied = all(rate_limits.values())
        return {"rate_limiting_applied": applied, "details": rate_limits}
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to check rate limiting: {e}"}


