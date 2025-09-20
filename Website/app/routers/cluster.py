from datetime import datetime, timezone
from typing import Dict
from fastapi import APIRouter, HTTPException

from ..core.k8s import get_k8s_clients


router = APIRouter(tags=["cluster"])


@router.get("/cluster-info")
def get_cluster_info() -> Dict:
    try:
        v1, apps_v1, _ = get_k8s_clients()

        nodes = v1.list_node().items
        pods = v1.list_pod_for_all_namespaces().items
        namespaces = v1.list_namespace().items
        deployments = apps_v1.list_deployment_for_all_namespaces().items
        events = v1.list_event_for_all_namespaces().items

        node_count = len(nodes)
        pod_count = len(pods)
        namespace_count = len(namespaces)
        deployment_count = len(deployments)

        ready_nodes = sum(
            1 for node in nodes if any(status.status == "True" and status.type == "Ready" for status in node.status.conditions)
        )

        running_pods = sum(1 for pod in pods if pod.status.phase == "Running")
        pending_pods = pod_count - running_pods

        cpu_usage = "42%"
        memory_usage = "68%"
        storage_usage = "35%"

        event_list = [
            {
                "type": event.type,
                "resource": event.involved_object.name,
                "message": event.message,
                "time": event.last_timestamp.isoformat() if event.last_timestamp else "Unknown",
            }
            for event in sorted(
                events, key=lambda x: x.last_timestamp or datetime.min.replace(tzinfo=timezone.utc), reverse=True
            )[:5]
        ]

        namespace_pods = {}
        for pod in pods:
            ns = pod.metadata.namespace
            pod_info = {
                "name": pod.metadata.name,
                "status": pod.status.phase,
                "node": pod.spec.node_name,
                "ip": pod.status.pod_ip,
                "containers": [container.name for container in pod.spec.containers],
            }
            if ns not in namespace_pods:
                namespace_pods[ns] = []
            namespace_pods[ns].append(pod_info)

        return {
            "nodes": {"total": node_count, "ready": ready_nodes},
            "pods": {"total": pod_count, "running": running_pods, "pending": pending_pods},
            "resources": {"cpu": cpu_usage, "memory": memory_usage, "storage": storage_usage},
            "deployments": deployment_count,
            "events": event_list,
            "namespaces": [{"name": ns.metadata.name, "pods": namespace_pods.get(ns.metadata.name, [])} for ns in namespaces],
        }
    except Exception as e:
        return {"error": str(e)}


