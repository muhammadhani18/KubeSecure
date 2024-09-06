import requests
import json
from scapy.all import IP, TCP, send, sr1
from kube_config import *
import subprocess

def send_corrupt_requests(dport):
    url = f'https://127.0.0.1:{dport}/api/v1/nodes'
    client_certificate, client_key = get_client_credentials()
    corrupt_urls = [
        f'{url}/corrupt-endpoint',
        f'{url}?corrupt=query',
        f'{url}/../../../../etc/passwd'
    ]
    responses = []
    
    for corrupt_url in corrupt_urls:
        try:
            response = requests.get(corrupt_url, cert=(client_certificate, client_key), verify=False)  # Not verifying SSL for simplicity
            response_data = {}
            response_data['url'] = corrupt_url
            response_data['status_code'] = response.status_code
            try:
                response_data['response'] = response.json()
            except json.JSONDecodeError:
                response_data['response'] = response.text
            responses.append(response_data)
        except requests.exceptions.RequestException as e:
            response_data = {}
            response_data['url'] = corrupt_url
            response_data['error'] = f"Failed to connect to the Kubernetes API with corrupt request: {e}"
            responses.append(response_data)
    
    # Write responses to JSON file
    with open('results/corrupt_requests.json', 'w') as f:
        json.dump(responses, f, indent=4)

def send_corrupt_packet(dport):
    try:
        # Create a packet with wrong checksum
        ip = IP(dst="127.0.0.1")
        tcp = TCP(dport=dport, sport=12345, flags="S")
        packet = ip/tcp
        packet[TCP].chksum = 0x1234  # Set an incorrect checksum
        
        # Send the packet and wait for response
        response = sr1(packet, timeout=1, verbose=0)
        response_data = {}
        if response:
            response_data['received_response'] = True
            response_data['response_summary'] = response.summary()
        else:
            response_data['received_response'] = False
        
        # Write response to JSON file
        with open('results/corrupt_packet_response.json', 'w') as f:
            json.dump(response_data, f, indent=4)
    except Exception as e:
        print( f"Failed to send corrupt packet: {e}")
        
def send_trigger_packet(dport):
    """
    The function `send_trigger_packet` sends a TCP packet to a specified destination port and captures
    the response, saving it to a JSON file.
    
    :param dport: The `dport` parameter in the `send_trigger_packet` function represents the destination
    port to which the trigger packet will be sent. This port is where the packet will attempt to trigger
    a response
    """
    try:
        # Create a packet that attempts to trigger a response
        ip = IP(dst="127.0.0.1")
        tcp = TCP(dport=dport, sport=12345, flags="S")
        packet = ip/tcp
        
        # Send the packet and wait for response
        response = sr1(packet, timeout=1, verbose=0)
        response_data = {}
        if response:
            response_data['received_response'] = True
            response_data['response_summary'] = response.summary()
        else:
            response_data['received_response'] = False
        
        # Write response to JSON file
        with open('results/trigger_packet_response.json', 'w') as f:
            json.dump(response_data, f, indent=4)
    except Exception as e:
        print( f"Failed to send trigger packet: {e}")
        
def send_payload_packet(dport):
    """
    The function `send_payload_packet` sends a payload packet to pods in all namespaces, captures
    responses, and writes the results to a JSON file.
    
    :param dport: The `dport` parameter in the `send_payload_packet` function represents the destination
    port to which the payload packet will be sent. This port is used to specify the target port on the
    destination pod where the packet will be delivered
    """
    try:
        # Get all namespaces
        namespaces_result = subprocess.run(['kubectl', 'get', 'namespaces', '-o', 'json'], stdout=subprocess.PIPE)
        namespaces = json.loads(namespaces_result.stdout.decode('utf-8'))['items']
        
        response_data = []

        for ns in namespaces:
            namespace = ns['metadata']['name']
            # Get all pods in the namespace
            pods_result = subprocess.run(['kubectl', 'get', 'pods', '-n', namespace, '-o', 'json'], stdout=subprocess.PIPE)
            pods = json.loads(pods_result.stdout.decode('utf-8'))['items']
            
            for pod in pods:
                pod_name = pod['metadata']['name']
                pod_ip = pod['status']['podIP']
                
                # Create a packet with a payload to run a command
                ip = IP(dst=pod_ip)
                tcp = TCP(dport=dport, sport=12345, flags="PA")  # PSH+ACK to indicate data transfer
                payload = "echo hello"
                packet = ip/tcp/payload
                
                # Send the packet and wait for response
                response = sr1(packet, timeout=1, verbose=0)
                pod_response_data = {
                    'namespace': namespace,
                    'pod': pod_name,
                    'pod_ip': pod_ip,
                    'received_response': response is not None
                }
                if response:
                    pod_response_data['response_summary'] = response.summary()
                
                response_data.append(pod_response_data)

        # Write response to JSON file
        with open('results/payload_packet_response.json', 'w') as f:
            json.dump(response_data, f, indent=4)
    except Exception as e:
        response_data = {'error': f"Failed to send payload packet: {e}"}
        
        # Write error to JSON file
        with open('results/payload_packet_response.json', 'w') as f:
            json.dump(response_data, f, indent=4)
