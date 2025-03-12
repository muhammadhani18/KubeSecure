#!/bin/bash

# Function to check if a command exists
check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo "❌ Error: '$1' is not installed. Please install it and try again."
        exit 1
    fi
}

# Check for required tools
echo "🔍 Checking if required tools are installed..."
check_command kind
check_command docker
check_command kubectl
echo "✅ All required tools are installed."

# Create Kubernetes cluster using Kind
echo "🚀 Creating Kind cluster..."
kind create cluster --config kind-config.yaml

# Add Helm repositories
echo "🔄 Adding Helm repositories..."
helm repo add cilium https://helm.cilium.io
helm repo update

# Install Tetragon
echo "📦 Installing Tetragon..."
helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --set tetragon.enableBTF=true \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true \
  --set tetragon.enableKernelEvents=true \
  --set tetragon.enableTracingPolicies=true \
  --set tetragon.bpf.mountPath=/sys/fs/bpf

echo "✅ Installed Tetragon."

# Install Prometheus and Grafana
echo "📊 Installing Prometheus and Grafana..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

kubectl create ns monitoring

helm install monitoring prometheus-community/kube-prometheus-stack \
-n monitoring \
-f ./grafana_prometheus/custom_kube_prometheus_stack.yml

echo "✅ Installed Prometheus and Grafana."
echo "🚀 Grafana username: admin and Password: prom-operator"
echo "🎉 Installation completed successfully!"
