from datetime import timedelta


# JWT configuration
SECRET_KEY = "c@tsRul3D0gsDr0ol"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
ACCESS_TOKEN_EXPIRE = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

# Firebase
FIREBASE_SERVICE_KEY_PATH = "service-key.json"
FIREBASE_DB_URL = "https://kube-2e93f-default-rtdb.firebaseio.com/"


