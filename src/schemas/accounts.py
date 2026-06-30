from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        accounts_validators.validate_email(v)
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        accounts_validators.validate_password_strength(v)
        return v


class UserRegistrationResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        accounts_validators.validate_password_strength(v)
        return v


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
