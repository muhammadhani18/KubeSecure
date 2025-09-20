from typing import Dict, List, Tuple


def transform_services(services_data: Dict) -> Tuple[List[Dict], List[Dict]]:
    nodes: List[Dict] = []
    edges: List[Dict] = []
    for item in services_data.get('items', []):
        service_name = item.get('metadata', {}).get('name')
        namespace = item.get('metadata', {}).get('namespace')
        service_id = f"service_{namespace}_{service_name}"
        nodes.append({
            "id": service_id,
            "type": "service",
            "name": service_name,
            "namespace": namespace,
            "ports": item.get('spec', {}).get('ports', []),
            "selector": item.get('spec', {}).get('selector', {}),
        })
    return nodes, edges


def transform_pods(pods_data: Dict, service_selector_map: Dict[str, Dict]) -> Tuple[List[Dict], List[Dict]]:
    nodes: List[Dict] = []
    edges: List[Dict] = []
    for item in pods_data.get('items', []):
        pod_name = item.get('metadata', {}).get('name')
        namespace = item.get('metadata', {}).get('namespace')
        pod_id = f"pod_{namespace}_{pod_name}"
        pod_labels = item.get('metadata', {}).get('labels', {})
        nodes.append({
            "id": pod_id,
            "type": "pod",
            "name": pod_name,
            "namespace": namespace,
            "status": item.get('status', {}).get('phase'),
            "labels": pod_labels,
            "containers": [c.get('name') for c in item.get('spec', {}).get('containers', [])],
        })
        for service_id, selector in service_selector_map.items():
            if all(pod_labels.get(k) == v for k, v in selector.items()):
                edges.append({"from": service_id, "to": pod_id, "type": "selector"})

        for volume in item.get('spec', {}).get('volumes', []):
            if volume.get('configMap'):
                cm_name = volume.get('configMap').get('name')
                edges.append({"from": pod_id, "to": f"configmap_{namespace}_{cm_name}", "type": "mount"})
            if volume.get('secret'):
                secret_name = volume.get('secret').get('secretName')
                edges.append({"from": pod_id, "to": f"secret_{namespace}_{secret_name}", "type": "mount"})

    return nodes, edges


def transform_deployments(deployments_data: Dict) -> Tuple[List[Dict], List[Dict]]:
    nodes: List[Dict] = []
    edges: List[Dict] = []
    for item in deployments_data.get('items', []):
        deployment_name = item.get('metadata', {}).get('name')
        namespace = item.get('metadata', {}).get('namespace')
        deployment_id = f"deployment_{namespace}_{deployment_name}"
        match_labels = item.get('spec', {}).get('selector', {}).get('matchLabels', {})
        nodes.append({
            "id": deployment_id,
            "type": "deployment",
            "name": deployment_name,
            "namespace": namespace,
            "replicas": item.get('spec', {}).get('replicas'),
            "match_labels": match_labels
        })
    return nodes, edges


def transform_ingresses(ingresses_data: Dict) -> Tuple[List[Dict], List[Dict]]:
    nodes: List[Dict] = []
    edges: List[Dict] = []
    for item in ingresses_data.get('items', []):
        ingress_name = item.get('metadata', {}).get('name')
        namespace = item.get('metadata', {}).get('namespace')
        ingress_id = f"ingress_{namespace}_{ingress_name}"
        nodes.append({
            "id": ingress_id,
            "type": "ingress",
            "name": ingress_name,
            "namespace": namespace,
            "rules": item.get('spec', {}).get('rules', []),
        })
        for rule in item.get('spec', {}).get('rules', []):
            for path in rule.get('http', {}).get('paths', []):
                service_name = path.get('backend', {}).get('service', {}).get('name')
                if service_name:
                    service_id = f"service_{namespace}_{service_name}"
                    edges.append({"from": ingress_id, "to": service_id, "type": "route"})
    return nodes, edges


def transform_configmaps(configmaps_data: Dict) -> Tuple[List[Dict], List[Dict]]:
    nodes: List[Dict] = []
    for item in configmaps_data.get('items', []):
        cm_name = item.get('metadata', {}).get('name')
        namespace = item.get('metadata', {}).get('namespace')
        nodes.append({
            "id": f"configmap_{namespace}_{cm_name}",
            "type": "configmap",
            "name": cm_name,
            "namespace": namespace,
        })
    return nodes, []


def transform_secrets(secrets_data: Dict) -> Tuple[List[Dict], List[Dict]]:
    nodes: List[Dict] = []
    for item in secrets_data.get('items', []):
        secret_name = item.get('metadata', {}).get('name')
        namespace = item.get('metadata', {}).get('namespace')
        nodes.append({
            "id": f"secret_{namespace}_{secret_name}",
            "type": "secret",
            "name": secret_name,
            "namespace": namespace,
        })
    return nodes, []


