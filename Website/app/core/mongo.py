import os
from typing import Any

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
import logging


_client: MongoClient | None = None
logger = logging.getLogger(__name__)


def get_mongo_client() -> MongoClient:
	global _client
	if _client is None:
		mongo_url = os.getenv("MONGO_URL", "mongodb://admin:admin@localhost:27017/?authSource=admin")
		# Shorten initial connect timeout so startup does not hang long if DB is unavailable
		_client = MongoClient(mongo_url, serverSelectionTimeoutMS=2000)
		try:
			# Trigger server selection to validate connectivity early
			_client.admin.command("ping")
		except ServerSelectionTimeoutError:
			logger.warning("Could not connect to MongoDB at startup; continuing. Some features will be disabled.")
	return _client


def get_db() -> Any:
	return get_mongo_client()["kubesecure"]

