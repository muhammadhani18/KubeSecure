import subprocess
import json
import requests
from kube_config import *


def use_docker_context(context_name):
    try:
        result = subprocess.run(['docker', 'context', 'use', context_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print(f"Successfully switched to Docker context: {context_name}")
        else:
            print(f"Failed to switch Docker context: {result.stderr.decode('utf-8')}")
    except Exception as e:
        print(f"An error occurred while switching Docker context: {e}")


def check_cluster_status():
    url = f'https://127.0.0.1:64078'
    client_certificate, client_key = get_client_credentials()
    response_data = {}
    
    try:
        response = requests.get(f'{url}/healthz', cert=(client_certificate, client_key), verify=False)  # Not verifying SSL for simplicity
        if response.status_code == 200:
            print("Minikube cluster is up and running.")
        else:
            print(f"Cluster check returned status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to connect to the Minikube cluster: {e}")
    

def get_kubernetes_response(dport):
    url = f'https://127.0.0.1:{dport}/api/v1/nodes'
    client_certificate, client_key = get_client_credentials()
    response_data = {}
    
    try:
        response = requests.get(url, cert=(client_certificate, client_key), verify=False)  # Not verifying SSL for simplicity
        if response.status_code == 200:
            response_data['response'] = response.json()
        else:
            response_data['status_code'] = response.status_code
            response_data['response_text'] = response.text
    except requests.exceptions.RequestException as e:
        response_data['error'] = f"Failed to connect to the Kubernetes API: {e}"
    
    # Write response to JSON file
    with open('results/kubernetes_response.json', 'w') as f:
        json.dump(response_data, f, indent=4)