from fastapi import APIRouter, HTTPException

from ..core.k8s import get_k8s_clients
from ..services.service_map import (
    transform_services,
    transform_pods,
    transform_deployments,
    transform_ingresses,
    transform_configmaps,
    transform_secrets,
)


router = APIRouter(prefix="/api", tags=["service_map"])


@router.get("/service-map")
async def get_service_map_data():
    try:
        v1, apps_v1, networking_v1 = get_k8s_clients()

        services_raw = v1.list_service_for_all_namespaces().to_dict()
        pods_raw = v1.list_pod_for_all_namespaces().to_dict()
        deployments_raw = apps_v1.list_deployment_for_all_namespaces().to_dict()
        ingresses_raw = networking_v1.list_ingress_for_all_namespaces().to_dict()
        configmaps_raw = v1.list_config_map_for_all_namespaces().to_dict()
        secrets_raw = v1.list_secret_for_all_namespaces().to_dict()

        all_nodes = []
        all_edges = []

        service_nodes, service_edges = transform_services(services_raw)
        all_nodes.extend(service_nodes)
        all_edges.extend(service_edges)

        service_selector_map = {s['id']: s['selector'] for s in service_nodes if s['selector']}

        pod_nodes, pod_edges = transform_pods(pods_raw, service_selector_map)
        all_nodes.extend(pod_nodes)
        all_edges.extend(pod_edges)

        deployment_nodes, deployment_edges = transform_deployments(deployments_raw)
        all_nodes.extend(deployment_nodes)
        all_edges.extend(deployment_edges)
        for dep_node in deployment_nodes:
            dep_labels = dep_node.get('match_labels', {})
            if not dep_labels:
                continue
            for svc_node in service_nodes:
                svc_selector = svc_node.get('selector', {})
                if all(dep_labels.get(k) == v for k, v in svc_selector.items()):
                    if svc_node['namespace'] == dep_node['namespace']:
                        all_edges.append({"from": dep_node['id'], "to": svc_node['id'], "type": "manages"})

        ingress_nodes, ingress_edges = transform_ingresses(ingresses_raw)
        all_nodes.extend(ingress_nodes)
        all_edges.extend(ingress_edges)

        cm_nodes, cm_edges = transform_configmaps(configmaps_raw)
        all_nodes.extend(cm_nodes)
        all_edges.extend(cm_edges)

        secret_nodes, secret_edges = transform_secrets(secrets_raw)
        all_nodes.extend(secret_nodes)
        all_edges.extend(secret_edges)

        unique_edges = [dict(t) for t in {tuple(d.items()) for d in all_edges}]

        return {"nodes": all_nodes, "edges": unique_edges}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")


