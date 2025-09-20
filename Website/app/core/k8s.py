from kubernetes import client, config
import logging


logger = logging.getLogger(__name__)


def get_k8s_clients():
    try:
        # Prefer local kubeconfig; fall back to in-cluster when available
        try:
            config.load_kube_config()
        except Exception:
            config.load_incluster_config()
    except Exception:
        # Kubernetes not configured; caller should handle None
        logger.debug("Kubernetes configuration not available; skipping client initialization")
        return None, None, None

    core_v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()
    networking_v1 = client.NetworkingV1Api()
    return core_v1, apps_v1, networking_v1


def get_apiextensions_client():
    try:
        try:
            config.load_kube_config()
        except Exception:
            config.load_incluster_config()
    except Exception:
        logger.debug("Kubernetes configuration not available; skipping Apiextensions client initialization")
        return None

    return client.ApiextensionsV1Api()


def get_custom_objects_client():
    try:
        try:
            config.load_kube_config()
        except Exception:
            config.load_incluster_config()
    except Exception:
        logger.debug("Kubernetes configuration not available; skipping CustomObjects client initialization")
        return None

    return client.CustomObjectsApi()


