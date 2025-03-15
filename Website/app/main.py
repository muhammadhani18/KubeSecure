from fastapi import FastAPI, Request, Form,UploadFile, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from subprocess import run, PIPE
import re
import subprocess
import sys
import signal
import threading
import queue
import json
import datetime
import yaml
import tempfile
import os
import datetime 
from kubernetes import client, config
from pydantic import BaseModel
from typing import Dict, List
 
app = FastAPI()
# Load Kubernetes config (use 'inClusterConfig()' if running inside a cluster)
config.load_kube_config()

v1 = client.CoreV1Api()


# Define response model
class ClusterInfoResponse(BaseModel):
    totalNodes: int
    totalPods: int
    totalNamespaces: int
    podsPerNamespace: Dict[str, int]
    nodeStatuses: Dict[str, int]
    resourceUsage: List[Dict[str, str]]


# Mount static files at "/static"
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up templates
templates = Jinja2Templates(directory="templates")

# Hardcoded users
users_db = {
    "usman@gmail.com": "12345"
}

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "message": ""})

@app.get("/alerts", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("alerts.html", {"request": request, "message": ""})

@app.post("/login", response_class=HTMLResponse)
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    if email in users_db and users_db[email] == password:
        # Redirect to welcome page on successful login
        return templates.TemplateResponse("home.html", {"request": request})
    else:
        # Return to login page with error message
        return templates.TemplateResponse("index.html", {"request": request, "message": "Invalid email or password."})

@app.post("/signup", response_class=HTMLResponse)
def signup(request: Request, email: str = Form(...), password: str = Form(...)):
    if email in users_db:
        return templates.TemplateResponse("index.html", {"request": request, "message": "User already exists."})
    else:
        users_db[email] = password
        return RedirectResponse(url="/home", status_code=303)

@app.get("/home", response_class=HTMLResponse)
def welcome(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

# New route for pods table
@app.get("/table", response_class=HTMLResponse)
def show_pods_table(request: Request):
    return templates.TemplateResponse("pods.html", {"request": request})

@app.get("/api/cluster-info", response_model=ClusterInfoResponse)
async def get_cluster_info():
    # Get all namespaces
    namespaces = v1.list_namespace().items
    total_namespaces = len(namespaces)

    # Get all pods
    pods = v1.list_pod_for_all_namespaces().items
    total_pods = len(pods)

    # Get all nodes
    nodes = v1.list_node().items
    total_nodes = len(nodes)

    # Count pods per namespace
    pods_per_namespace = {}
    for pod in pods:
        ns = pod.metadata.namespace
        pods_per_namespace[ns] = pods_per_namespace.get(ns, 0) + 1

    # Node status breakdown
    node_statuses = {"Ready": 0, "Not Ready": 0, "Unknown": 0}
    for node in nodes:
        for condition in node.status.conditions:
            if condition.type == "Ready":
                node_statuses["Ready" if condition.status == "True" else "Not Ready"] += 1
                break
        else:
            node_statuses["Unknown"] += 1  # No Ready condition found

    # CPU & Memory usage per namespace
    resource_usage = []
    for ns in namespaces:
        namespace_name = ns.metadata.name
        cpu_usage = memory_usage = 0
        for pod in pods:
            if pod.metadata.namespace == namespace_name:
                for container in pod.spec.containers:
                    if container.resources.requests:
                        cpu_usage += int(container.resources.requests.get("cpu", "0m").rstrip("m")) / 1000
                        memory_usage += int(container.resources.requests.get("memory", "0Mi").rstrip("Mi"))
        resource_usage.append({
            "namespace": namespace_name,
            "cpu": f"{cpu_usage:.2f} cores",
            "memory": f"{memory_usage} Mi"
        })

    return {
        "totalNodes": total_nodes,
        "totalPods": total_pods,
        "totalNamespaces": total_namespaces,
        "podsPerNamespace": pods_per_namespace,
        "nodeStatuses": node_statuses,
        "resourceUsage": resource_usage
    }


@app.get("/api/pods")
def get_pods():
    try:
        # Run the kubectl command
        result = run(['kubectl', 'get', 'pods', '-A'], stdout=PIPE, text=True)
        output = result.stdout

        # Parse the output to extract Namespace, Name, and Ready columns
        pods = []
        lines = output.split('\n')
        for line in lines[1:]:  # Skip the header row
            if line.strip():
                columns = line.split()
                namespace = columns[0]
                name = columns[1]
                ready = columns[2]
                
                # # Exclude entries where namespace is "kube-system"
                # if namespace != "kube-system" and namespace != "local-path-storage":
                #     pods.append({"namespace": namespace, "name": name, "ready": ready})

        return pods
    except Exception as e:
        return {"error": str(e)}
    

def load_events():
    try:
        # Read the events from the events.json file
        with open("./events.json", "r") as f:
            events = json.load(f)
        return events
    except Exception as e:
        return {"error": str(e)}
    

def filter_events(events, minutes):
    time_threshold = datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes)
    return [event for event in events if datetime.datetime.fromisoformat(event["timestamp"]) >= time_threshold]

@app.get("/events", response_class=HTMLResponse)
def show_events(request: Request, minutes: int = Query(5, description="Filter events from the last N minutes")):
    events = load_events()
    filtered_events = filter_events(events, minutes)
    return templates.TemplateResponse("events.html", {"request": request, "events": filtered_events})
    
    
    
    
def load_yaml(file_path):
    """Load a YAML file and return its content."""
    try:
        with open(file_path, 'r') as f:
            return list(yaml.safe_load_all(f))
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Error parsing YAML file: {e}")

def detect_code_smells(manifests):
    """Detect Kubernetes code smells in the given YAML manifests."""
    smells = []

    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue

        kind = manifest.get("kind", "Unknown")
        metadata = manifest.get("metadata", {})
        name = metadata.get("name", "Unknown")
        namespace = metadata.get("namespace", "default")
        spec = manifest.get("spec", {})

        # Detect hardcoded values (e.g., using 'latest' tag in images)
        if "containers" in spec:
            for container in spec["containers"]:
                image = container.get("image", "")
                if ":latest" in image or image == "latest":
                    smells.append(
                        f"[Hardcoded Value] {kind}/{name} in namespace {namespace} uses 'latest' tag for image {image}."
                    )

        # Detect missing resource requests and limits
        if "containers" in spec:
            for container in spec["containers"]:
                resources = container.get("resources", {})
                if "requests" not in resources or "limits" not in resources:
                    smells.append(
                        f"[Resource Smell] {kind}/{name} in namespace {namespace} is missing resource requests or limits."
                    )

        # Detect overprivileged pods
        if kind == "Pod" and spec.get("securityContext", {}).get("privileged", False):
            smells.append(
                f"[Overprivileged Pod] {kind}/{name} in namespace {namespace} is running as privileged."
            )

        # Detect missing probes
        if "containers" in spec:
            for container in spec["containers"]:
                if "livenessProbe" not in container:
                    smells.append(
                        f"[Health Check] {kind}/{name} in namespace {namespace} is missing a livenessProbe."
                    )
                if "readinessProbe" not in container:
                    smells.append(
                        f"[Health Check] {kind}/{name} in namespace {namespace} is missing a readinessProbe."
                    )

        # Detect large ConfigMaps
        if kind == "ConfigMap":
            data = manifest.get("data", {})
            if len(data) > 100:  # Arbitrary threshold
                smells.append(
                    f"[Large ConfigMap] {kind}/{name} in namespace {namespace} has a large number of entries ({len(data)})."
                )

        # Detect secrets in plain text
        if kind == "Secret":
            data = manifest.get("data", {})
            if any(len(value) > 100 for value in data.values()):  # Arbitrary threshold
                smells.append(
                    f"[Secret Smell] {kind}/{name} in namespace {namespace} has potentially large plain-text entries."
                )

        # Detect using default namespace
        if namespace == "default":
            smells.append(f"[Namespace Smell] {kind}/{name} is in the default namespace.")

        # Detect running as root
        if "containers" in spec:
            for container in spec["containers"]:
                security_context = container.get("securityContext", {})
                if security_context.get("runAsUser", 0) == 0:
                    smells.append(
                        f"[Security Risk] {kind}/{name} in namespace {namespace} runs as root (runAsUser=0)."
                    )

        # Detect privilege escalation
        if "containers" in spec:
            for container in spec["containers"]:
                security_context = container.get("securityContext", {})
                if security_context.get("allowPrivilegeEscalation", True):
                    smells.append(
                        f"[Security Risk] {kind}/{name} in namespace {namespace} allows privilege escalation."
                    )

        # Detect wildcard roles in RoleBindings/ClusterRoleBindings
        if kind in ["RoleBinding", "ClusterRoleBinding"]:
            subjects = manifest.get("subjects", [])
            for subject in subjects:
                if subject.get("kind") == "Group" and subject.get("name") in ["system:authenticated", "system:unauthenticated"]:
                    smells.append(
                        f"[RBAC Smell] {kind}/{name} in namespace {namespace} binds a role to a wildcard group ({subject.get('name')})."
                    )

        # Detect use of hostPath (which can break container isolation)
        if "volumes" in spec:
            for volume in spec["volumes"]:
                if "hostPath" in volume:
                    smells.append(
                        f"[Security Risk] {kind}/{name} in namespace {namespace} uses a hostPath volume, which can compromise security."
                    )

        # Detect high replica count for Deployments
        if kind == "Deployment":
            replicas = spec.get("replicas", 1)
            if replicas > 100:  # Arbitrary high threshold
                smells.append(
                    f"[Scaling Issue] {kind}/{name} in namespace {namespace} has a high replica count ({replicas}), which might be excessive."
                )

        # Detect containers without security policies
        if "containers" in spec:
            for container in spec["containers"]:
                security_context = container.get("securityContext", {})
                if not security_context:
                    smells.append(
                        f"[Security Risk] {kind}/{name} in namespace {namespace} lacks a security context."
                    )

    return smells


@app.get("/yaml-validate", response_class=HTMLResponse)
def show_pods_table(request: Request):
    return templates.TemplateResponse("checkSmell.html", {"request": request})

@app.post("/api/detect-smells")
async def detect_smells(file: UploadFile):
    """Endpoint to detect Kubernetes code smells from a YAML file."""
    if not file.filename.endswith(('.yaml', '.yml')):
        raise HTTPException(status_code=400, detail="File must be a YAML file.")

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as temp_file:
            temp_file.write(await file.read())
            temp_file_path = temp_file.name

        manifests = load_yaml(temp_file_path)
        smells = detect_code_smells(manifests)
        os.remove(temp_file_path)

        return {"smells": smells}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

@app.get("/policy", response_class=HTMLResponse)
def show_pods_table(request: Request):
    return templates.TemplateResponse("policy.html", {"request": request})
