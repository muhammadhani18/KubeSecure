from kubernetes import client, config
from kubernetes.client.rest import ApiException

def check_rbac_enabled():
    try:
        # Load the Kubernetes configuration
        config.load_kube_config()

        # Create an API client
        api_instance = client.CoreV1Api()

        # Get the API server configuration
        api_response = api_instance.get_api_resources()
        
        # Check if RBAC API group is available
        rbac_enabled = any(resource.group == "rbac.authorization.k8s.io" for resource in api_response.resources)
        
        if rbac_enabled:
            print("RBAC is enabled.")
        else:
            print("RBAC is not enabled.")
    except ApiException as e:
        print(f"Exception when checking RBAC status: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == '__main__':
    check_rbac_enabled()
