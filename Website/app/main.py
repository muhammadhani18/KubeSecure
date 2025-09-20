import logging
import hashlib
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi import Depends
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from .routers import auth as auth_router
from .routers import alerts as alerts_router
from .routers import events as events_router
from .routers import smells as smells_router
from .routers import policies as policies_router
from .routers import rate_limit as rate_limit_router
from .routers import cluster as cluster_router
from .routers import service_map as service_map_router
from .routers import scan as scan_router
from .routers import health as health_router
from .routers import logs as logs_router
from .routers import cilium as cilium_router
from .routers import cilium_policies as cilium_policies_router
from .core.mongo import get_db
from .routers import kubescape as kubescape_router
from .core.auth import get_password_hash
from .routers import kubeconfig as kubeconfig_router
from .core.k8s import get_k8s_clients
from .core.auth import decode_token
from .core.middleware import JWTAuthMiddleware

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def collect_logs_once():
	core_v1, _, _ = get_k8s_clients()
	if core_v1 is None:
		logger.debug("Skipping log collection: Kubernetes client unavailable")
		return
	db = get_db()
	user = db.users.find_one({"email": "hani@gmail.com"})
	if not user:
		return
	user_id = str(user["_id"])  # For association; store as string

	# List pods across namespaces
	try:
		pods = core_v1.list_pod_for_all_namespaces().items
	except Exception as exc:
		logger.debug(f"Failed to list pods: {exc}")
		return

	for pod in pods:
		ns = pod.metadata.namespace
		pod_name = pod.metadata.name
		container_names = [c.name for c in (pod.spec.containers or [])]
		if getattr(pod.spec, "init_containers", None):
			container_names += [c.name for c in pod.spec.init_containers]

		for container_name in container_names:
			try:
				# Fetch only recent small tail to detect changes
				log_text = core_v1.read_namespaced_pod_log(
					name=pod_name,
					namespace=ns,
					container=container_name,
					since_seconds=10,
					timestamps=True,
					tail_lines=200,
				)
				lines = log_text.splitlines() if log_text else []
				if not lines:
					continue

				# Deduplicate: compute a simple content hash of recent lines
				fingerprint = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
				content_key = {
					"user_id": user_id,
					"namespace": ns,
					"pod": pod_name,
					"container": container_name,
					"fingerprint": fingerprint,
				}
				existing = db.logs.find_one(content_key)
				if existing:
					continue

				db.logs.insert_one({
					**content_key,
					"lines": lines,
				})
			except Exception as exc:
				# Swallow errors per container to keep job resilient
				logger.debug(f"Error collecting logs for {ns}/{pod_name}:{container_name}: {exc}")
				continue


@asynccontextmanager
async def lifespan(app: FastAPI):
	# Startup: ensure default user and start background log collector
	logger.info("Application startup: initializing services")
	try:
		db = get_db()
		# Ensure default user exists and has the expected password
		db.users.update_one(
			{"email": "hani@gmail.com"},
			{"$set": {"password_hash": get_password_hash("12345678")}},
			upsert=True,
		)
		logger.info("Default user ensured and password reset at startup")
	except Exception as exc:
		logger.warning(f"Startup: could not ensure default user: {exc}")

	stop_event = asyncio.Event()

	async def _log_loop():
		while not stop_event.is_set():
			try:
				collect_logs_once()
			except Exception:
				pass
			try:
				await asyncio.wait_for(stop_event.wait(), timeout=5.0)
			except asyncio.TimeoutError:
				continue

	task = asyncio.create_task(_log_loop())
	logger.info("Background log collector task started")
	try:
		yield
	finally:
		stop_event.set()
		try:
			await task
		except Exception:
			pass


app = FastAPI(lifespan=lifespan)

# CORS – permissive for now (adjust in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT middleware – protect all routes except login & signup
app.add_middleware(
	JWTAuthMiddleware,
	exempt_paths={"/api/login", "/api/signup", "/health"},
)


@app.get("/health")
def root():
    return "Fast api server running"


# Routers
app.include_router(auth_router.router)
app.include_router(alerts_router.router)
app.include_router(events_router.router)
app.include_router(smells_router.router)
app.include_router(policies_router.router)
app.include_router(rate_limit_router.router)
app.include_router(cluster_router.router)
app.include_router(service_map_router.router)
app.include_router(scan_router.router)
app.include_router(health_router.router)
app.include_router(logs_router.router)
app.include_router(cilium_router.router)
app.include_router(cilium_policies_router.router)
app.include_router(kubescape_router.router)
app.include_router(kubeconfig_router.router)