import re
from pydantic import BaseModel, EmailStr, field_validator


def validate_password(v: str) -> str:
    """
    Validates that the password meets the following criteria:
    """
    if len(v) < 8:
        raise ValueError("Password must contain at least 8 characters.")

    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter.")

    if not re.search(r"\d", v):
        raise ValueError("Password must contain at least one digit.")

    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lower letter.")
    if not re.search(r"[@$!%*?#&]", v):
        raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
    return v


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return validate_password(v)


class UserRegistrationResponseSchema(UserBase):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return validate_password(v)


class MessageResponseSchema(BaseModel):
    message: str
