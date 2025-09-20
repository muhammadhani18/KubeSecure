import subprocess
import tempfile
import yaml
from fastapi import APIRouter, Form, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, constr


router = APIRouter(prefix="/api", tags=["policies"])


@router.post("/enforce-policy")
async def enforce_policy(policy_name: str = Form(...), command_name: str = Form(...)):
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
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml", mode="wb") as temp_file:
            yaml_content = yaml.dump(policy_yaml, default_flow_style=False)
            temp_file.write(yaml_content.encode("utf-8"))
            temp_file_path = temp_file.name

        process = subprocess.run(["kubectl", "apply", "-f", temp_file_path], capture_output=True, text=True)

        if process.returncode == 0:
            return JSONResponse(content={"message": "Policy applied successfully!"})
        else:
            raise HTTPException(status_code=400, detail=process.stderr)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/get-policies")
async def get_policies():
    try:
        process = subprocess.run(
            ["kubectl", "get", "tracingpolicies.cilium.io", "-o", "yaml"], capture_output=True, text=True
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

                parsed_kprobes.append(
                    {"call": call, "syscall": syscall, "match_commands": match_commands, "actions": actions}
                )

            formatted_policies.append({"name": name, "kprobes": parsed_kprobes})

        return JSONResponse(content={"policies": formatted_policies})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class DeletePolicyRequest(BaseModel):
    policy_name: constr(strip_whitespace=True, min_length=1)


@router.delete("/delete-policy")
async def delete_policy(req: DeletePolicyRequest):
    try:
        completed = subprocess.run(
            ["kubectl", "delete", "tracingpolicy", req.policy_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="kubectl timed out while attempting to delete the policy")

    if completed.returncode != 0:
        raise HTTPException(
            status_code=400, detail=f"kubectl error: {completed.stderr.strip() or 'Unknown error'}"
        )

    return {"message": "deleted"}


