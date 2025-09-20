from typing import Callable, Iterable, Optional, Set

from jose import jwt, JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import SECRET_KEY, ALGORITHM


class JWTAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, exempt_paths: Optional[Iterable[str]] = None):
        super().__init__(app)
        self.exempt_paths: Set[str] = set(exempt_paths or [])

    async def dispatch(self, request: Request, call_next: Callable[[Request], Response]) -> Response:
        # Allow CORS preflight without auth
        if request.method == "OPTIONS":
            return await call_next(request)

        # Exempt specific paths
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        # Expect Authorization: Bearer <token>
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username:
                return JSONResponse({"detail": "Invalid token"}, status_code=401)
            # Optionally attach user info to scope/state
            request.state.user = username
        except JWTError:
            return JSONResponse({"detail": "Invalid token"}, status_code=401)

        return await call_next(request)


