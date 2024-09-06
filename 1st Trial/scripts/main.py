from connect_k8s import use_docker_context, check_cluster_status, get_kubernetes_response
from send_packets import *
import warnings
from urllib3.exceptions import InsecureRequestWarning


if __name__ == '__main__':
    dport = 64078
    
    use_docker_context("default")

    check_cluster_status()

    get_kubernetes_response(dport)

    send_corrupt_requests(dport)

    send_corrupt_packet(dport)

    send_trigger_packet(dport)

    send_payload_packet(dport)
