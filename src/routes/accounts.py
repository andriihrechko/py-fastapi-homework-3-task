from datetime import datetime, timezone
from typing import cast, Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    user_data: UserRegistrationRequestSchema,
):
    user_exists_stmt = select(UserModel).where(
        UserModel.email == user_data.email
    )
    user_exists_result = await db.execute(user_exists_stmt)
    user_exists = user_exists_result.scalar()
    if user_exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        group_stmt = select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
        group_result = await db.execute(group_stmt)
        group = group_result.scalars().first()

        db_user = UserModel().create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=group.id,
        )
        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return db_user


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    activation_data: UserActivationRequestSchema,
):
    user_stmt = select(UserModel).where(
        UserModel.email == activation_data.email
    )
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user_token_stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == activation_data.token,
    )
    user_token_result = await db.execute(user_token_stmt)
    user_token = user_token_result.scalars().first()

    if user_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, user_token.expires_at).replace(
        tzinfo=timezone.utc
    )
    if expires_at < datetime.now(timezone.utc):
        delete_stmt = delete(ActivationTokenModel).where(
            ActivationTokenModel.id == user_token.id,
        )
        await db.execute(delete_stmt)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    delete_stmt = delete(ActivationTokenModel).where(
        ActivationTokenModel.id == user_token.id,
    )
    await db.execute(delete_stmt)
    await db.commit()
    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
async def request_password_reset(
    db: Annotated[AsyncSession, Depends(get_db)],
    reset_data: PasswordResetRequestSchema,
):
    user_stmt = select(UserModel).where(UserModel.email == reset_data.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    success_response = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    if user is None or not user.is_active:
        return success_response

    delete_stmt = delete(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    await db.execute(delete_stmt)

    reset_token = PasswordResetTokenModel(user_id=user.id)
    db.add(reset_token)
    await db.commit()

    return success_response


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def password_reset(
    db: Annotated[AsyncSession, Depends(get_db)],
    reset_data: PasswordResetCompleteRequestSchema,
):
    user_stmt = select(UserModel).where(UserModel.email == reset_data.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    reset_token_stmt = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id,
    )
    reset_token_result = await db.execute(reset_token_stmt)
    reset_token = reset_token_result.scalars().first()

    if reset_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    if reset_data.token != reset_token.token:
        delete_stmt = delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.token == reset_token.token,
        )
        await db.execute(delete_stmt)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = cast(datetime, user_token.expires_at).replace(
        tzinfo=timezone.utc
    )
    if expires_at < datetime.now(timezone.utc):
        delete_stmt = delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.id == reset_token.id,
        )
        await db.execute(delete_stmt)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = reset_data.password
        delete_stmt = delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.id == reset_token.id,
        )
        await db.execute(delete_stmt)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )
    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    db: Annotated[AsyncSession, Depends(get_db)],
    user_data: UserLoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user_stmt = select(UserModel).where(UserModel.email == user_data.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    try:
        user_id = user.id
        refresh_token = jwt_manager.create_refresh_token({"user_id": user_id})
        access_token = jwt_manager.create_access_token({"user_id": user_id})

        token = RefreshTokenModel.create(
            token=refresh_token,
            user_id=user_id,
            days_valid=settings.LOGIN_TIME_DAYS,
        )

        db.add(token)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh(
    db: Annotated[AsyncSession, Depends(get_db)],
    token_data: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_refresh_token = jwt_manager.decode_refresh_token(
            token_data.refresh_token
        )
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    user_id = decoded_refresh_token.get("user_id")

    refresh_token_stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == token_data.refresh_token,
    )
    refresh_token_result = await db.execute(refresh_token_stmt)
    refresh_token = refresh_token_result.scalars().first()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_stmt = select(UserModel).where(UserModel.id == user_id)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token({"user_id": user_id})
    return TokenRefreshResponseSchema(access_token=new_access_token)
