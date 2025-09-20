import os
import base64
from typing import Optional

from cryptography.fernet import Fernet



def get_fernet(key_env_var: str = "KUBECONFIG_ENC_KEY") -> Fernet:
    key = os.getenv(key_env_var)
    if not key:
        raise ValueError(f"Missing encryption key in environment variable: {key_env_var}")
    # Expect a urlsafe base64-encoded 32-byte key (Fernet standard)
    try:
        # If the provided key looks like hex or plain text, fail fast with clear message
        # Otherwise create the Fernet instance which validates key format
        _ = base64.urlsafe_b64decode(key)
        return Fernet(key)
    except Exception as exc:
        raise ValueError(
            "Invalid Fernet key format. Provide a urlsafe base64-encoded 32-byte key."
        ) from exc


def encrypt_bytes(data: bytes, key_env_var: str = "KUBECONFIG_ENC_KEY") -> bytes:
    return get_fernet(key_env_var).encrypt(data)


def decrypt_bytes(token: bytes, key_env_var: str = "KUBECONFIG_ENC_KEY") -> bytes:
    return get_fernet(key_env_var).decrypt(token)


