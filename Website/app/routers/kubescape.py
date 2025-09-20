import logging
import subprocess
import re
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scan", tags=["kubescape"]) 


def _parse_non_verbose_output(text: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {"framework": None, "controls": {}, "severity_breakdown": {}, "control_summaries": []}

    # Framework
    m = re.search(r"Framework scanned:\s*(.+)", text)
    if m:
        data["framework"] = m.group(1).strip()

    # Controls totals box
    m_ctrls = re.search(
        r"Controls\s*\│\s*(\d+)\s*\│[\s\S]*?Passed\s*\│\s*(\d+)\s*\│[\s\S]*?Failed\s*\│\s*(\d+)\s*\│[\s\S]*?Action Required\s*\│\s*(\d+)",
        text,
    )
    if m_ctrls:
        data["controls"] = {
            "total": int(m_ctrls.group(1)),
            "passed": int(m_ctrls.group(2)),
            "failed": int(m_ctrls.group(3)),
            "action_required": int(m_ctrls.group(4)),
        }

    # Severity breakdown box
    m_sev = re.search(
        r"Failed resources by severity:[\s\S]*?Critical\s*\│\s*(\d+)[\s\S]*?High\s*\│\s*(\d+)[\s\S]*?Medium\s*\│\s*(\d+)[\s\S]*?Low\s*\│\s*(\d+)",
        text,
    )
    if m_sev:
        data["severity_breakdown"] = {
            "critical": int(m_sev.group(1)),
            "high": int(m_sev.group(2)),
            "medium": int(m_sev.group(3)),
            "low": int(m_sev.group(4)),
        }

    # Control summary table rows
    in_table = False
    for line in text.splitlines():
        if (
            "Control name" in line
            and "Failed resources" in line
            and "Compliance score" in line
        ):
            in_table = True
            continue
        if in_table and line.strip().startswith("└"):
            in_table = False
            continue
        if in_table and line.strip().startswith("│"):
            mrow = re.match(
                r"^\s*│\s*(?P<severity>[^│]+?)\s*│\s*(?P<control>[^│]+?)\s*│\s*(?P<failed>\d+)\s*│\s*(?P<all>\d+)\s*│\s*(?P<score>[^│]+?)\s*│\s*$",
                line,
            )
            if mrow:
                data["control_summaries"].append(
                    {
                        "severity": mrow.group("severity").strip(),
                        "control": mrow.group("control").strip(),
                        "failed_resources": int(mrow.group("failed")),
                        "all_resources": int(mrow.group("all")),
                        "compliance_score": mrow.group("score").strip(),
                    }
                )

    return data


def _parse_verbose_output(text: str) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {"framework": None, "resources": [], "summary": _parse_non_verbose_output(text)}

    # Resource blocks separated by a line of #'s
    blocks = re.split(r"^#{10,}\s*$", text, flags=re.MULTILINE)
    for block in blocks:
        kind_m = re.search(r"\bKind:\s*(.+)", block)
        name_m = re.search(r"\bName:\s*(.+)", block)
        ns_m = re.search(r"\bNamespace:\s*(.+)", block)
        if not (kind_m and name_m and ns_m):
            continue
        resource = {
            "kind": kind_m.group(1).strip(),
            "name": name_m.group(1).strip(),
            "namespace": ns_m.group(1).strip(),
            "control_findings": [],
        }

        # Find per-resource control table
        in_table = False
        for line in block.splitlines():
            if (
                "Control name" in line
                and "Docs" in line
                and "Assisted remediation" in line
            ):
                in_table = True
                continue
            if in_table and line.strip().startswith("└"):
                in_table = False
                continue
            if in_table and line.strip().startswith("│"):
                mrow = re.match(
                    r"^\s*│\s*(?P<severity>[^│]+?)\s*│\s*(?P<control>[^│]+?)\s*│\s*(?P<docs>[^│]+?)\s*│\s*(?P<remediation>[^│]+?)\s*│\s*$",
                    line,
                )
                if mrow:
                    resource["control_findings"].append(
                        {
                            "severity": mrow.group("severity").strip(),
                            "control": mrow.group("control").strip(),
                            "docs": mrow.group("docs").strip(),
                            "remediation": mrow.group("remediation").strip(),
                        }
                    )

        parsed["resources"].append(resource)

    # Framework name
    m = re.search(r"Framework scanned:\s*(.+)", text)
    if m:
        parsed["framework"] = m.group(1).strip()

    return parsed


@router.post("/kubescape")
def scan_with_kubescape(verbose: bool = Query(default=False)):
    try:
        command = ["kubescape", "scan", "framework", "nsa"]
        if verbose:
            command.append("--verbose")
        logger.info("Starting kubescape scan%s", " (verbose)" if verbose else "")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=False,
                timeout=1800,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.error("Kubescape scan timed out")
            raise HTTPException(status_code=408, detail="Kubescape scan timed out")
        except FileNotFoundError:
            logger.error("kubescape CLI not found in PATH")
            raise HTTPException(status_code=500, detail="kubescape CLI not found. Ensure it is installed and in PATH.")

        if result.returncode != 0:
            stderr_text = (result.stderr or b"").decode("utf-8", errors="replace")
            error_message = stderr_text.strip() or "Unknown error occurred"
            logger.error(f"Kubescape scan failed: {error_message}")
            raise HTTPException(status_code=500, detail=f"Kubescape scan failed: {error_message}")

        output_text = (result.stdout or b"").decode("utf-8", errors="replace")
        logger.info("Kubescape scan completed successfully")

        parsed = _parse_verbose_output(output_text) if verbose else _parse_non_verbose_output(output_text)
        return {"message": "Scan completed", "verbose": verbose, "output": parsed}

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Unexpected error during kubescape scan: {exc}")
        raise HTTPException(status_code=500, detail="Failed to run kubescape scan due to an unexpected error")


