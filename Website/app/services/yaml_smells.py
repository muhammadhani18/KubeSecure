from typing import List, Dict, Any


def load_yaml(file_path: str) -> List[Dict[str, Any]]:
    import yaml
    with open(file_path, 'r') as f:
        return list(yaml.safe_load_all(f))


def detect_code_smells(manifests: List[Dict[str, Any]]) -> List[str]:
    smells: List[str] = []
    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue

        kind = manifest.get("kind", "Unknown")
        metadata = manifest.get("metadata", {})
        name = metadata.get("name", "Unknown")
        namespace = metadata.get("namespace", "default")
        spec = manifest.get("spec", {})

        if "containers" in spec:
            for container in spec["containers"]:
                image = container.get("image", "")
                if ":latest" in image or image == "latest":
                    smells.append(
                        f"[Hardcoded Value] {kind}/{name} in namespace {namespace} uses 'latest' tag for image {image}."
                    )

        if "containers" in spec:
            for container in spec["containers"]:
                resources = container.get("resources", {})
                if "requests" not in resources or "limits" not in resources:
                    smells.append(
                        f"[Resource Smell] {kind}/{name} in namespace {namespace} is missing resource requests or limits."
                    )

        if kind == "Pod" and spec.get("securityContext", {}).get("privileged", False):
            smells.append(
                f"[Overprivileged Pod] {kind}/{name} in namespace {namespace} is running as privileged."
            )

        if "containers" in spec:
            for container in spec["containers"]:
                if "livenessProbe" not in container:
                    smells.append(
                        f"[Health Check] {kind}/{name} in namespace {namespace} is missing a livenessProbe."
                    )
                if "readinessProbe" not in container:
                    smells.append(
                        f"[Health Check] {kind}/{name} in namespace {namespace} is missing a readinessProbe."
                    )

        if kind == "ConfigMap":
            data = manifest.get("data", {})
            if len(data) > 100:
                smells.append(
                    f"[Large ConfigMap] {kind}/{name} in namespace {namespace} has a large number of entries ({len(data)})."
                )

        if kind == "Secret":
            data = manifest.get("data", {})
            if any(len(value) > 100 for value in data.values()):
                smells.append(
                    f"[Secret Smell] {kind}/{name} in namespace {namespace} has potentially large plain-text entries."
                )

        if namespace == "default":
            smells.append(f"[Namespace Smell] {kind}/{name} is in the default namespace.")

        if "containers" in spec:
            for container in spec["containers"]:
                security_context = container.get("securityContext", {})
                if security_context.get("runAsUser", 0) == 0:
                    smells.append(
                        f"[Security Risk] {kind}/{name} in namespace {namespace} runs as root (runAsUser=0)."
                    )

        if "containers" in spec:
            for container in spec["containers"]:
                security_context = container.get("securityContext", {})
                if security_context.get("allowPrivilegeEscalation", True):
                    smells.append(
                        f"[Security Risk] {kind}/{name} in namespace {namespace} allows privilege escalation."
                    )

        if kind in ["RoleBinding", "ClusterRoleBinding"]:
            subjects = manifest.get("subjects", [])
            for subject in subjects:
                if subject.get("kind") == "Group" and subject.get("name") in [
                    "system:authenticated",
                    "system:unauthenticated",
                ]:
                    smells.append(
                        f"[RBAC Smell] {kind}/{name} in namespace {namespace} binds a role to a wildcard group ({subject.get('name')})."
                    )

        if "volumes" in spec:
            for volume in spec["volumes"]:
                if "hostPath" in volume:
                    smells.append(
                        f"[Security Risk] {kind}/{name} in namespace {namespace} uses a hostPath volume, which can compromise security."
                    )

        if kind == "Deployment":
            replicas = spec.get("replicas", 1)
            if replicas > 100:
                smells.append(
                    f"[Scaling Issue] {kind}/{name} in namespace {namespace} has a high replica count ({replicas}), which might be excessive."
                )

        if "containers" in spec:
            for container in spec["containers"]:
                security_context = container.get("securityContext", {})
                if not security_context:
                    smells.append(
                        f"[Security Risk] {kind}/{name} in namespace {namespace} lacks a security context."
                    )

    return smells


