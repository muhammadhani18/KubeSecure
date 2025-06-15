# Project Overview

This project aims to create a secure and observable Kubernetes environment using Kind (Kubernetes in Docker). It integrates monitoring tools like Grafana and Prometheus for real-time visibility, and Tetragon for enhanced security. 

The core functionality involves deploying a CLSTM (Convolutional Long Short-Term Memory) model to detect anomalies in network traffic. When anomalies are identified, the system triggers alerts through Slack and Firebase, and enforces rate limiting policies to mitigate potential threats.

Key Features:
*   **Kind Cluster Setup:** Easily reproducible Kubernetes environment.
*   **Monitoring:** Integrated Grafana and Prometheus stack for comprehensive monitoring.
*   **Security:** Tetragon for eBPF-based security observability and runtime enforcement.
*   **Anomaly Detection:** CLSTM model for identifying suspicious network traffic patterns.
*   **Alerting:** Real-time notifications via Slack and Firebase.
*   **Rate Limiting:** Automated enforcement of rate limits upon anomaly detection.

# Architecture

The system's architecture is designed around a Kind Kubernetes cluster and several integrated components:

*   **Kind Cluster:** A local Kubernetes cluster with one control plane node and two worker nodes. This setup provides a lightweight and developer-friendly environment for deploying and managing containerized applications.
*   **Monitoring Stack:**
    *   **Prometheus:** Deployed within the cluster to collect metrics from various Kubernetes components and applications.
    *   **Grafana:** Used for visualizing the metrics collected by Prometheus, providing dashboards for monitoring cluster health and application performance.
*   **Security Enforcement:**
    *   **Tetragon:** Leverages eBPF for real-time security observability and runtime enforcement. It monitors system calls and network activity to detect and prevent malicious behavior.
*   **Traffic Analysis and Anomaly Detection:**
    *   **Traffic Mirroring (cicflowmeter):** Network traffic within the cluster is mirrored and processed by cicflowmeter. This tool captures network flows and extracts relevant features for analysis.
    *   **CLSTM Model:** The extracted flow data is fed into a Convolutional Long Short-Term Memory (CLSTM) model. This deep learning model is trained to identify anomalous patterns in network traffic that may indicate security threats or system misconfigurations.
*   **Alerting Mechanism:**
    *   **Slack Integration:** Upon detection of an anomaly, alerts are sent to a designated Slack channel for immediate notification of the operations team.
    *   **Firebase Integration:** Alerts and relevant event data are also sent to Firebase, potentially for persistent storage, further analysis, or integration with other services.
*   **Backend APIs:** A set of backend APIs (likely running within the Kubernetes cluster) manage the overall workflow, including:
    *   Receiving data from the CLSTM model.
    *   Triggering alerts to Slack and Firebase.
    *   Initiating rate-limiting actions based on detected anomalies.
    *   Interfacing with Tetragon for security policy enforcement.

## KubeSecure Architecture
![KubeSecure Architecture](fyp3.png)


# Prerequisites

Before you begin, ensure you have the following tools installed on your system:

*   **Docker:** Required to run Kind (Kubernetes in Docker). ([Installation Guide](https://docs.docker.com/engine/install/))
*   **Kind:** A tool for running local Kubernetes clusters using Docker container "nodes". ([Installation Guide](https://kind.sigs.k8s.io/docs/user/quick-start/#installation))
*   **kubectl:** The Kubernetes command-line tool, used to interact with your cluster. ([Installation Guide](https://kubernetes.io/docs/tasks/tools/install-kubectl/))
*   **Helm:** The package manager for Kubernetes, used to deploy and manage applications. ([Installation Guide](https://helm.sh/docs/intro/install/))

# Setup Instructions

1.  **Install Prerequisites:**
    Ensure all tools listed in the [Prerequisites](#prerequisites) section are installed and configured correctly on your system.

2.  **Set Up the Kind Cluster:**
    This project uses a Kind cluster defined in `kind-config.yaml`. To create the cluster, run the following command from the root of the repository:
    ```bash
    kind create cluster --config kind-config.yaml
    ```
    This will set up a Kubernetes cluster with one control plane and two worker nodes.

3.  **Deploy Grafana and Prometheus:**
    The monitoring stack (Grafana and Prometheus) is deployed using Helm.
    ```bash
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update
    kubectl create namespace monitoring
    helm install monitoring prometheus-community/kube-prometheus-stack -n monitoring -f monitoring/values.yaml
    ```

4.  **Install Tetragon:**
    Tetragon is used for eBPF-based security observability and runtime enforcement. Install it using Helm:
    ```bash
    helm repo add cilium https://helm.cilium.io
    helm repo update
    helm install tetragon cilium/tetragon -n kube-system -f tetragon/values.yaml
    ```

5.  **Apply Tetragon Policies:**
    Apply the necessary Tetragon TracingPolicies to monitor for security events. The specific policies are located in the `tetragon/policies` directory.
    ```bash
    kubectl apply -f tetragon/policies/
    ```
    *(Note: You may need to adjust the path if your policies are in a different subdirectory or if you want to apply them individually.)*

6.  **Set Up Traffic Mirroring and Anomaly Detection Server:**
    The traffic mirroring and anomaly detection server (`Traffic_Mirroring/server.py`) captures network traffic using `cicflowmeter`, processes it, and uses a CLSTM model to detect anomalies.

    *   **Firebase Credentials:** Place your Firebase service account key file named `service-key.json` in the `Traffic_Mirroring/` directory. This is required for sending alerts to Firebase.
    *   **Slack Webhook:** Set the `SLACK_WEBHOOK_URL` environment variable to your Slack incoming webhook URL.
        ```bash
        export SLACK_WEBHOOK_URL="YOUR_SLACK_WEBHOOK_URL_HERE"
        ```
    *   **Running the Server:** The server needs to be run with sudo privileges because `cicflowmeter` requires root access to capture network packets.
        ```bash
        cd Traffic_Mirroring/
        sudo python3 server.py
        ```

7.  **Set Up and Run Backend API Server:**
    The backend API server (`Website/app/main.py`) provides endpoints for managing detected anomalies, interacting with Firebase, and potentially other administrative tasks.

    *   **Firebase Credentials:** Ensure your Firebase service account key file named `service-key.json` is present in the `Website/app/` directory (or update the path in `Website/app/main.py` if you place it elsewhere).
    *   **Running the Server:** The server is started using the `start-server.sh` script located in the `Website/` directory. This script also handles setting up Telebit to expose the local server to the internet for testing or remote access.
        ```bash
        cd Website/
        ./start-server.sh
        ```
    *(Note: Review `start-server.sh` for any specific configurations related to Telebit or other environment settings you might need to adjust.)*

# Workflow

The end-to-end workflow of the system is as follows:

1.  **Traffic Ingress:** Network traffic enters the Kubernetes cluster, typically through an Ingress controller, and is routed to the appropriate services.
2.  **Traffic Capture:** The `Traffic_Mirroring/server.py` script, running with sudo privileges, utilizes `cicflowmeter` to capture network traffic from the cluster's network interfaces (e.g., `eth0` or a specific Kind bridge interface).
3.  **Data Processing and Anomaly Detection:**
    *   Captured traffic data is processed to extract relevant features.
    *   These features are then fed into the pre-trained CLSTM model (`Models/CLSTM/model.py`) for anomaly detection.
4.  **Anomaly Response:** If the CLSTM model identifies an anomaly:
    *   **Slack Alert:** An alert notification is sent to a pre-configured Slack channel using the `SLACK_WEBHOOK_URL`.
    *   **Firebase Alert:** Details of the anomaly are stored in the Firebase Realtime Database for persistence and potential further analysis.
    *   **Rate Limiting:** An automated process attempts to enforce rate limiting on the Nginx Ingress Controller. This is typically done by patching the Ingress resource associated with the affected service to include rate-limiting annotations.
5.  **Continuous Monitoring and Security:**
    *   **Tetragon:** Provides continuous eBPF-based security observability and runtime enforcement. It monitors kernel-level events and can block malicious activities based on the applied TracingPolicies.
    *   **Prometheus & Grafana:** Collect and visualize metrics from the cluster, applications, and network, offering insights into system health and performance.
6.  **Backend API Interaction:**
    *   The backend API server (`Website/app/main.py`), exposed via Telebit if enabled, provides RESTful endpoints.
    *   These endpoints can be used to:
        *   View detected anomalies and alerts from Firebase.
        *   Potentially manage or update Tetragon policies (depending on API capabilities).
        *   Monitor overall system status and cluster information.
        *   Manually trigger or adjust rate-limiting configurations.

# Backend APIs

The `Website/app/main.py` application serves the following key API endpoints:

*   **`/api/login` (POST):**
    *   **Purpose:** Authenticates users. Expects username and password in the request body.
    *   **Request:** JSON body with `username` and `password`.
    *   **Response:** JWT token upon successful authentication or an error message.

*   **`/get-alerts` (GET):**
    *   **Purpose:** Fetches anomaly alerts from the Firebase Realtime Database.
    *   **Response:** JSON array of alert objects.

*   **`/api/events` (GET):**
    *   **Purpose:** Retrieves Tetragon security events.
    *   **Response:** JSON array of Tetragon event objects.

*   **`/api/detect-smells` (POST):**
    *   **Purpose:** Analyzes a submitted Kubernetes YAML manifest file for potential misconfigurations or "code smells."
    *   **Request:** Expects a YAML file (`file`) in a multipart/form-data request.
    *   **Response:** JSON object detailing detected smells or a success message.

*   **`/api/enforce-policy` (POST):**
    *   **Purpose:** Applies a new Tetragon TracingPolicy to the Kubernetes cluster.
    *   **Request:** JSON body containing the Tetragon policy definition.
    *   **Response:** Success or error message.

*   **`/api/get-policies` (GET):**
    *   **Purpose:** Retrieves all currently applied Tetragon TracingPolicies from the cluster.
    *   **Response:** JSON array of policy objects.

*   **`/api/delete-policy` (DELETE):**
    *   **Purpose:** Deletes a Tetragon TracingPolicy from the cluster by its name.
    *   **Request:** JSON body with `policy_name`.
    *   **Response:** Success or error message.

*   **`/revert_rate_limit` (POST):**
    *   **Purpose:** Removes or reverts rate-limiting configurations from the Nginx Ingress Controller for a specified ingress.
    *   **Request:** JSON body likely including `ingress_name` and `namespace`.
    *   **Response:** Success or error message.

*   **`/apply_rate_limit` (POST):**
    *   **Purpose:** Applies rate-limiting configurations to the Nginx Ingress Controller for a specified ingress.
    *   **Request:** JSON body likely including `ingress_name`, `namespace`, and rate limit parameters (e.g., `rpm`, `burst`).
    *   **Response:** Success or error message.

*   **`/check_rate_limit` (GET):**
    *   **Purpose:** Checks the current rate-limiting status for a specified ingress on the Nginx Ingress Controller.
    *   **Request:** Query parameters likely including `ingress_name` and `namespace`.
    *   **Response:** JSON object detailing the current rate limit settings.

*   **`/cluster-info` (GET):**
    *   **Purpose:** Retrieves general information about the Kubernetes cluster, such as node status, version, etc.
    *   **Response:** JSON object with cluster details.

*   **`/api/service-map` (GET):**
    *   **Purpose:** Provides a map or list of services, deployments, and pods within the Kubernetes cluster, showing their relationships.
    *   **Response:** JSON object representing the cluster resource map.

*   **`/api/scan-image` (POST):**
    *   **Purpose:** Scans a specified container image for known vulnerabilities using Trivy.
    *   **Request:** JSON body with `image_name`.
    *   **Response:** JSON report of vulnerabilities found in the image.

# Contributing

Contributions are welcome! If you have suggestions for improvements or new features, please feel free to:

*   Open an issue to discuss the change.
*   Submit a pull request with your contribution.

We appreciate your help in making this project better.
