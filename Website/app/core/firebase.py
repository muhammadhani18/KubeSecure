import firebase_admin
from firebase_admin import credentials, db
from .config import FIREBASE_DB_URL, FIREBASE_SERVICE_KEY_PATH


def init_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate(FIREBASE_SERVICE_KEY_PATH)
        firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_DB_URL})


def get_db_ref(path: str):
    init_firebase()
    return db.reference(path)


