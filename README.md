# KubeSecure: Kernel Event Tracing and AI Driven Anomaly Detection in Kubernetes Cluster

## 🗂️ Table of Contents
- [Introduction](#-introduction)
- [Motivation](#-motivation)
- [Core Features](#️-core-features)
- [Project Architecture](#-project-architecture)
- [Tech Stack](#-tech-stack)
- [Setup & Installation](#-setup--installation)
- [Usage](#-usage)
---

## 📖 Introduction
Cyberattacks have grown more frequent and sophisticated, posing significant risks to modern cloud-native infrastructures. Kubernetes, a leading container orchestration platform, is especially vulnerable due to its complexity and widespread adoption across industries. Traditional static rule-based security tools are often unable to detect or mitigate the growing variety of advanced network threats — including Distributed Denial of Service (DDoS) attacks, intrusion attempts, and misconfigurations.

KubeSecure is designed to address this gap by introducing an AI-driven anomaly detection system specifically tailored for Kubernetes clusters. The system leverages deep learning models, such as Convolutional LSTM and Transformer-based architectures, to detect abnormal patterns in network traffic and dynamically adapt to evolving security threats. Combined with automated mitigation and kernel log tracing capabilities, KubeSecure aims to enhance Kubernetes security by providing intelligent, real-time protection.

---

## 💡 Motivation
The rapid expansion of cloud-native architectures has introduced new attack surfaces that traditional security measures struggle to monitor effectively. Kubernetes clusters, in particular, generate an overwhelming volume of network traffic, making manual threat detection impractical and static rule-based systems insufficient.

KubeSecure was conceived to address the following challenges:

* The growing complexity and scale of Kubernetes deployments make it difficult to manually monitor network anomalies.

* Static rule-based security policies are often bypassed by modern cyberattack techniques.

* DDoS attacks, which are increasingly executed via botnets, can evade detection and overwhelm systems before manual intervention is possible.

* YAML misconfigurations, one of the most common sources of cluster vulnerabilities, are often overlooked during manual audits.

* Kernel and System Logs mostly not parsed well when debugging issues in Kubernetes Cluster.

KubeSecure introduces an intelligent, adaptive anomaly detection approach, capable of identifying both known and unknown threat patterns, reducing false positives, and enhancing threat response speed through automation.

---

## ⚙️ Core Features
* 🔍 **In-Time Anomaly Detection:** Continuously monitors Kubernetes cluster network traffic for irregular patterns using deep learning, allowing for early detection of threats such as DDoS attacks.

* 🤖 **AI-Driven Analysis:** Utilizes trained deep learning models (LSTM & Transformer) to adaptively identify security risks based on real-time traffic trends.

* 🛡️ **Automated Threat Mitigation:** Upon detection of anomalies, the system can automatically apply mitigation actions like traffic redirection to honeypots or dynamic rate limiting using Cilium and eBPF-based scripts.

* 📄 **YAML Misconfiguration Scanner:** A web-based tool allows security teams to upload Kubernetes YAML files for automated scanning against common misconfiguration patterns and security best practices.

* 🐝 **Honeypot Integration:** Redirects suspicious traffic to honeypots for deeper analysis, helping to uncover attacker strategies and enhance future threat models.

* 🧠 **Log Aggregation and Event Tracing:** Integration with Tetragon enables detailed real-time logging, event tracing, and forensic analysis of runtime activities.

* 🖼️ **Monitoring Dashboard:**
Offers visual insights into network performance and security status through Prometheus and Grafana dashboards.

* ☎️ **Real-Time Alerts:** Notifications via Slack, email, and an Android application ensure the security team is promptly informed of threats.



---


## 🏗️ Project Architecture
The KubeSecure platform combines Kubernetes-native security tools (Cilium, Tetragon) with an AI-based anomaly detection component for real-time traffic analysis and automated threat mitigation. Below is a high-level overview of how the components interact:

1. User Traffic & Ingress Controller

    * All external requests to the application first enter the cluster through the Kubernetes Ingress Controller. This controller routes legitimate user traffic to the Application Pod running inside Kubernetes.

2. Prometheus & Metrics Collection

    * Prometheus scrapes metrics from the Kubernetes cluster, Cilium, and various application endpoints. It stores performance data, network usage metrics, and kernel-level events (in conjunction with Tetragon) for real-time analysis and alerting.

3. Tetragon: Log & Event Tracing

    * Tetragon collects deep kernel-level insights—such as process execution and network flow events—across all nodes in the cluster. These logs provide a granular view of system calls and help pinpoint suspicious activities.

4. Deep Learning Prediction Pod

    * Simultaneously, traffic is mirrored (or duplicated) to the Deep Learning (DL) Prediction Pod, which runs the trained anomaly detection model (e.g., CLSTM or Transformer). The model inspects traffic patterns in near real-time. If malicious or anomalous behavior is detected, it marks the traffic as suspicious.

5. Alerting & Mitigation

    * When a threat is identified, the DL Prediction Pod signals Prometheus, which triggers alerts via its Alertmanager (or equivalent).These alerts can be sent to Slack, email, or a custom Web Application/Android App. Depending on severity, Cilium or an eBPF-based script automatically applies mitigation actions (e.g., rate limiting, traffic redirection).

6. Automated Threat Mitigation:
    * After the model predicts that the traffic is malicious, an automated script runs which enfores nginx rate limiting. User can revert the rate limiting through the admin dashboard.

7. Visual Dashboards in Grafana

    * All metrics gathered by Prometheus are visualized in Grafana dashboards. Security teams can monitor real-time cluster metrics, alert statuses, and other operational information.

8. Web Application
    * A dedicated Web App (or Admin UI) provides a user-friendly interface to upload and scan Kubernetes YAML files for configuration errors. View alert histories, configure system settings, or manage static policies. Provide an admin panel for advanced security operations.

By combining deep learning anomaly detection, static rule checks via Cilium, and granular logging through Tetragon, KubeSecure delivers a holistic approach to Kubernetes security. The system continuously adapts to new threats while providing a clear, intuitive interface for security analysts and DevOps teams.

---

## 🧰 Tech Stack
- Python, Pytorch, FastAPI
- Firebase
- Docker, Kubernetes

---

## 💻 Setup & Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/muhammadhani18/KubeSecure
   cd KubeSecure

2. **Setup the architecture**
    ```bash
    bash install.sh
    bash setup.sh

3. **Clone frontend**
    ```bash
    git clone https://github.com/muhammadhani18/KubeSecure-Frontend
    npm install
    npm run dev