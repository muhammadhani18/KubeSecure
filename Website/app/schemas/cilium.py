from typing import List, Optional, Dict

from pydantic import BaseModel, Field


class L4Rule(BaseModel):
	protocol: str = Field(..., description="Protocol, e.g., TCP or UDP")
	port: int = Field(..., ge=1, le=65535)


class L4PolicyRequest(BaseModel):
	name: str = Field(..., description="Policy name")
	namespace: str = Field(..., description="Namespace to apply policy in")
	selector: Dict[str, str] = Field(..., description="Pod label selector for endpoints the policy applies to")
	# List of allowed L4 rules (ingress). For egress L4, we could extend later.
	l4: List[L4Rule]


class HTTPEndpointRule(BaseModel):
	method: Optional[str] = Field(None, description="HTTP method to allow, e.g., GET/POST. If omitted, any method.")
	path: Optional[str] = Field(None, description="HTTP path regex to allow. If omitted, any path.")


class L7PolicyRequest(BaseModel):
	name: str
	namespace: str
	selector: Dict[str, str]
	# L7 policies usually sit on top of an L4 port (e.g., HTTP on tcp/80)
	port: int = Field(..., ge=1, le=65535)
	protocol: str = Field("TCP", description="L4 protocol for the port, typically TCP")
	# HTTP-only for now; could add Kafka/DNS later
	http: List[HTTPEndpointRule]


