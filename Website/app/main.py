from fastapi import FastAPI, Request, Form,UploadFile, Query, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
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
import yaml
import tempfile
import os
import datetime 
from kubernetes import client, config
from pydantic import BaseModel
from typing import Dict, List
import yaml 
import firebase_admin
from firebase_admin import credentials, db
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError, jwt


app = FastAPI()


# Allow all origins, all methods, and all headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods
    allow_headers=["*"],  # Allows all headers
)


cred = credentials.Certificate('service-key.json')
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://kube-2e93f-default-rtdb.firebaseio.com/'
})


# Load Kubernetes config (use 'inClusterConfig()' if running inside a cluster)
# config.load_kube_config()
# v1 = client.CoreV1Api()
# apps_v1 = client.AppsV1Api()

# Define response model
class ClusterInfoResponse(BaseModel):
    totalNodes: int
    totalPods: int
    totalNamespaces: int
    podsPerNamespace: Dict[str, int]
    nodeStatuses: Dict[str, int]
    resourceUsage: List[Dict[str, str]]


# Hardcoded users
users_db = {
    "usman@gmail.com": "12345678"
}

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return "Fast api server running"



# Secret key for JWT encoding & decoding
SECRET_KEY = "c@tsRul3D0gsDr0ol"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

# Hardcoded user credentials
HARD_CODED_USERNAME = "hani@gmail.com"
HARD_CODED_PASSWORD = "12345678"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != HARD_CODED_USERNAME or form_data.password != HARD_CODED_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": form_data.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {"message": "You have access to this protected route", "user": username}




@app.get("/get-alerts")
async def get_alerts():
    """Fetch alerts from Firebase Realtime Database"""
    alerts_ref = db.reference("alerts")
    alerts_data = alerts_ref.get()

    if not alerts_data:
        return {"message": "No alerts found"}

    # Convert Firebase dict to a list for easy frontend handling
    alerts_list = [{"id": key, "message": value.get("message", ""), "timestamp": value.get("timestamp", 0)}
                   for key, value in alerts_data.items()]

    return {"alerts": alerts_list}



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



@app.post("/api/enforce-policy")
async def enforce_policy(
    policy_name: str = Form(...), 
    command_name: str = Form(...)
):
    policy_yaml = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {"name": policy_name},
        "spec": {
            "kprobes": [
                {
                    "call": "sys_execve",
                    "syscall": True,
                    "args": [{"index": 0, "type": "string"}],
                    "selectors": [
                        {
                            "matchArgs": [
                                {"index": 0, "operator": "Equal", "values": [command_name]}
                            ],
                            "matchActions": [{"action": "Sigkill"}],
                        }
                    ],
                }
            ]
        },
    }

    try:
        # Create a temporary YAML file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml", mode="wb") as temp_file:
            yaml_content = yaml.dump(policy_yaml, default_flow_style=False)
            temp_file.write(yaml_content.encode('utf-8'))  # 🔧 Encode string to bytes
            temp_file_path = temp_file.name

        # Apply the YAML using kubectl
        process = subprocess.run(
            ["kubectl", "apply", "-f", temp_file_path], capture_output=True, text=True
        )

        if process.returncode == 0:
            return JSONResponse(content={"message": "Policy applied successfully!"})
        else:
            raise HTTPException(status_code=400, detail=process.stderr)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/get-policies")
async def get_policies():
    try:
        process = subprocess.run(
            ["kubectl", "get", "tracingpolicies.cilium.io", "-o", "yaml"],
            capture_output=True,
            text=True
        )

        if process.returncode != 0:
            raise HTTPException(status_code=400, detail=process.stderr)

        policies_yaml = yaml.safe_load(process.stdout)
        applied_policies = policies_yaml.get("items", [])

        formatted_policies = []

        for policy in applied_policies:
            name = policy.get("metadata", {}).get("name", "Unknown")
            kprobes = policy.get("spec", {}).get("kprobes", [])

            parsed_kprobes = []
            for kprobe in kprobes:
                call = kprobe.get("call", "Unknown")
                syscall = kprobe.get("syscall", False)
                selectors = kprobe.get("selectors", [])

                match_commands = []
                actions = []

                for selector in selectors:
                    match_args = selector.get("matchArgs", [])
                    for arg in match_args:
                        if arg.get("index") == 0 and arg.get("operator") == "Equal":
                            match_commands.extend(arg.get("values", []))

                    match_actions = selector.get("matchActions", [])
                    for action in match_actions:
                        actions.append(action.get("action", "Unknown"))

                parsed_kprobes.append({
                    "call": call,
                    "syscall": syscall,
                    "match_commands": match_commands,
                    "actions": actions
                })

            formatted_policies.append({
                "name": name,
                "kprobes": parsed_kprobes
            })

        return JSONResponse(content={"policies": formatted_policies})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    
REVERT_COMMAND = [
    "kubectl", "patch", "ingress", "calculator-ingress", "-n", "default", "--type=json",
    "-p", '[{"op": "remove", "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-rps"},'
          '{"op": "remove", "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-burst"},'
          '{"op": "remove", "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-connections"}]'
]

@app.post("/revert_rate_limit")
def revert_rate_limit():
    try:
        subprocess.run(REVERT_COMMAND, check=True)
        return {"message": "Rate limiting reverted successfully"},200
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to revert rate limiting: {e}"},500


@app.post("/apply_rate_limit")
def apply_rate_limit(user_value: int = Form(...)):
    # Construct the JSON patch payload
    patch_data = json.dumps([
        {"op": "add", "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-rps", "value": str(user_value)},
        {"op": "add", "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-burst", "value": str(user_value + 10)},
        {"op": "add", "path": "/metadata/annotations/nginx.ingress.kubernetes.io~1limit-connections", "value": str(user_value + 20)}
    ])

    # Construct the command
    patch_command = [
        "kubectl", "patch", "ingress", "calculator-ingress", "-n", "default", "--type=json",
        "-p", patch_data
    ]

    try:
        subprocess.run(patch_command, check=True)
        return {"message": "Rate limiting applied successfully"},200
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to apply rate limiting: {e}"},500
    
    

@app.get("/cluster-info")
def get_cluster_info() -> Dict:
    try:
        nodes = v1.list_node().items
        pods = v1.list_pod_for_all_namespaces().items
        namespaces = v1.list_namespace().items
        deployments = apps_v1.list_deployment_for_all_namespaces().items
        events = v1.list_event_for_all_namespaces().items

        # Count resources
        node_count = len(nodes)
        pod_count = len(pods)
        namespace_count = len(namespaces)
        deployment_count = len(deployments)

        # Node status
        ready_nodes = sum(1 for node in nodes if any(
            status.status == "True" and status.type == "Ready" for status in node.status.conditions))

        # Pod status
        running_pods = sum(1 for pod in pods if pod.status.phase == "Running")
        pending_pods = pod_count - running_pods

        # Resource usage (Dummy values, real usage requires metrics server)
        cpu_usage = "42%"
        memory_usage = "68%"
        storage_usage = "35%"

        # Events (last 5)
        event_list = [{
            "type": event.type,
            "resource": event.involved_object.name,
            "message": event.message,
            "time": event.last_timestamp if event.last_timestamp else "Unknown"
        } for event in sorted(events, key=lambda x: x.last_timestamp or "0", reverse=True)[:5]]

        # Organizing pods by namespace
        namespace_pods = {}
        for pod in pods:
            ns = pod.metadata.namespace
            pod_info = {
                "name": pod.metadata.name,
                "status": pod.status.phase,
                "node": pod.spec.node_name,
                "ip": pod.status.pod_ip,
                "containers": [container.name for container in pod.spec.containers]
            }
            if ns not in namespace_pods:
                namespace_pods[ns] = []
            namespace_pods[ns].append(pod_info)

        return {
            "nodes": {"total": node_count, "ready": ready_nodes},
            "pods": {"total": pod_count, "running": running_pods, "pending": pending_pods},
            "resources": {"cpu": cpu_usage, "memory": memory_usage, "storage": storage_usage},
            "deployments": deployment_count,
            "events": event_list,
            "namespaces": [
                {
                    "name": ns.metadata.name,
                    "pods": namespace_pods.get(ns.metadata.name, [])
                }
                for ns in namespaces
            ]
        }

    except Exception as e:
        return {"error": str(e)}
    
