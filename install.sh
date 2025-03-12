kind create cluster --config kind-config.yaml

helm repo add cilium https://helm.cilium.io
helm repo update

echo Installing Tetragon

helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --set tetragon.enableBTF=true \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true \
  --set tetragon.enableKernelEvents=true \
  --set tetragon.enableTracingPolicies=true \
  --set tetragon.bpf.mountPath=/sys/fs/bpf

echo "Installed Tetragon"

echo Installing Prometheus and Grafana

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

kubectl create ns monitoring

helm install monitoring prometheus-community/kube-prometheus-stack \
-n monitoring \
-f ./grafana_prometheus/custom_kube_prometheus_stack.yml

echo Installed Prometheus and Grafana