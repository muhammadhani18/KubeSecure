import logging
from typing import Dict

from fastapi import APIRouter, HTTPException

from ..core.k8s import get_custom_objects_client
from ..schemas.cilium import L4PolicyRequest, L7PolicyRequest


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/cilium", tags=["cilium"])


def _make_cnp_l4_manifest(payload: L4PolicyRequest) -> Dict:
    # Build a minimal CiliumNetworkPolicy with L4 ingress rules
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": payload.name, "namespace": payload.namespace},
        "spec": {
            "endpointSelector": {"matchLabels": payload.selector},
            "ingress": [
                {
                    "fromEndpoints": [{"matchLabels": {}}],  # allow from any; could be extended later
                    "toPorts": [
                        {
                            "ports": [
                                {"port": str(rule.port), "protocol": rule.protocol.upper()} for rule in payload.l4
                            ]
                        }
                    ],
                }
            ],
        },
    }


def _make_cnp_l7_http_manifest(payload: L7PolicyRequest) -> Dict:
    # Build L7 HTTP rules on top of an L4 port
    http_rules = []
    for rule in payload.http:
        entry: Dict[str, str] = {}
        if rule.method:
            entry["method"] = rule.method.upper()
        if rule.path:
            entry["path"] = rule.path
        http_rules.append(entry)

    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": payload.name, "namespace": payload.namespace},
        "spec": {
            "endpointSelector": {"matchLabels": payload.selector},
            "ingress": [
                {
                    "toPorts": [
                        {
                            "ports": [
                                {"port": str(payload.port), "protocol": payload.protocol.upper()}
                            ],
                            "rules": {"http": http_rules},
                        }
                    ]
                }
            ],
        },
    }


@router.post("/policies/l4")
def apply_cilium_l4_policy(payload: L4PolicyRequest):
    api = get_custom_objects_client()
    if api is None:
        raise HTTPException(status_code=500, detail="Kubernetes client unavailable")

    body = _make_cnp_l4_manifest(payload)

    group = "cilium.io"
    version = "v2"
    plural = "ciliumnetworkpolicies"

    try:
        # Try create; if exists, replace
        api.create_namespaced_custom_object(
            group=group, version=version, namespace=payload.namespace, plural=plural, body=body
        )
        return {"status": "created", "name": payload.name, "namespace": payload.namespace}
    except Exception as exc:
        # Attempt replace on conflict
        try:
            api.replace_namespaced_custom_object(
                group=group,
                version=version,
                namespace=payload.namespace,
                plural=plural,
                name=payload.name,
                body=body,
            )
            return {"status": "updated", "name": payload.name, "namespace": payload.namespace}
        except Exception as exc2:
            logger.error(f"Failed to apply L4 policy {payload.name} in {payload.namespace}: {exc2}")
            raise HTTPException(status_code=500, detail=f"Failed to apply L4 policy: {exc2}")


@router.post("/policies/l7")
def apply_cilium_l7_policy(payload: L7PolicyRequest):
    api = get_custom_objects_client()
    if api is None:
        raise HTTPException(status_code=500, detail="Kubernetes client unavailable")

    body = _make_cnp_l7_http_manifest(payload)

    group = "cilium.io"
    version = "v2"
    plural = "ciliumnetworkpolicies"

    try:
        api.create_namespaced_custom_object(
            group=group, version=version, namespace=payload.namespace, plural=plural, body=body
        )
        return {"status": "created", "name": payload.name, "namespace": payload.namespace}
    except Exception as exc:
        try:
            api.replace_namespaced_custom_object(
                group=group,
                version=version,
                namespace=payload.namespace,
                plural=plural,
                name=payload.name,
                body=body,
            )
            return {"status": "updated", "name": payload.name, "namespace": payload.namespace}
        except Exception as exc2:
            logger.error(f"Failed to apply L7 policy {payload.name} in {payload.namespace}: {exc2}")
            raise HTTPException(status_code=500, detail=f"Failed to apply L7 policy: {exc2}")


