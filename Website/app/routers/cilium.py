from typing import Dict

from fastapi import APIRouter

from ..core.k8s import get_k8s_clients, get_apiextensions_client


router = APIRouter(prefix="/api/cilium", tags=["cilium"]) 


@router.get("/status")
def cilium_status() -> Dict:
	core_v1, apps_v1, _ = get_k8s_clients()
	apiext = get_apiextensions_client()
	if core_v1 is None or apps_v1 is None:
		return {"installed": False, "details": {"reason": "Kubernetes client unavailable"}}

	installed = True
	details: Dict[str, object] = {}

	# Check CRDs
	crd_names = [
		"ciliumnetworkpolicies.cilium.io",
		"ciliumclusterwidenetworkpolicies.cilium.io",
		"ciliumendpoints.cilium.io",
		"ciliumidentities.cilium.io",
		"ciliumexternalworkloads.cilium.io",
	]
	crds_ok = False
	if apiext is not None:
		try:
			crds = apiext.list_custom_resource_definition().items
			present = {crd.metadata.name for crd in crds}
			crds_ok = all(name in present for name in crd_names)
			details["crds_present"] = crds_ok
		except Exception as exc:
			details["crds_error"] = str(exc)
	else:
		details["crds_present"] = False

	# Check DaemonSet in kube-system
	daemonset_ok = False
	try:
		daemonsets = apps_v1.list_namespaced_daemon_set(namespace="kube-system").items
		daemonset_ok = any(ds.metadata.name == "cilium" for ds in daemonsets)
		details["daemonset_present"] = daemonset_ok
	except Exception as exc:
		details["daemonset_error"] = str(exc)

	# Check operator deployment in kube-system
	operator_ok = False
	try:
		deployments = apps_v1.list_namespaced_deployment(namespace="kube-system").items
		operator_ok = any(dep.metadata.name.startswith("cilium-operator") for dep in deployments)
		details["operator_present"] = operator_ok
	except Exception as exc:
		details["operator_error"] = str(exc)

	installed = bool(daemonset_ok and operator_ok)
	missing = []
	if not daemonset_ok:
		missing.append("daemonset")
	if not operator_ok:
		missing.append("operator")

	response: Dict[str, object] = {"installed": installed, "details": details}
	if not installed:
		response["missing"] = missing
	return response


