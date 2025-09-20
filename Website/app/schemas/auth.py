from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SignupRequest(BaseModel):
    email: str
    password: str


