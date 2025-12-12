from datetime import datetime, timezone, timedelta
import uuid

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload


router = APIRouter()

from config import get_jwt_auth_manager, get_settings

settings = get_settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/accounts/login")

from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)

from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    MessageResponseSchema
)

from security.passwords import hash_password, verify_password



async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: AsyncSession = Depends(get_db),
        jwt_manager=Depends(get_jwt_auth_manager)
) -> UserModel:
    try:
        payload = jwt_manager.decode_access_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = payload.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user



@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    if result.scalars().first():
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")

    group_result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    default_group = group_result.scalars().first()

    if not default_group:
        raise HTTPException(status_code=500, detail="Default user group not found.")

    try:
        new_user = UserModel(
            email=user_data.email,
            _hashed_password=hash_password(user_data.password),
            group_id=default_group.id,
            is_active=False
        )
        db.add(new_user)
        await db.flush()

        token_str = str(uuid.uuid4())
        activation_token = ActivationTokenModel(
            user_id=new_user.id,
            token=token_str,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)

        return new_user
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_account(
        payload: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == payload.email)
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_record = user.activation_token
    if not token_record or token_record.token != payload.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
        payload: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager=Depends(get_jwt_auth_manager)
):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
        user = result.scalars().first()

        if not user or not verify_password(payload.password, user._hashed_password):
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="User account is not activated.")

        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token_str = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_token_entry = RefreshTokenModel(
            user_id=user.id,
            token=refresh_token_str,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.add(refresh_token_entry)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer"
        }
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
        payload: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager=Depends(get_jwt_auth_manager)
):
    try:
        token_data = jwt_manager.decode_refresh_token(payload.refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")

    user_id = token_data.get("user_id")

    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token))
    stored_token = result.scalars().first()

    if not stored_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    if stored_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Token has expired.")

    user_result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = user_result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": user.id})

    return {"access_token": new_access_token}


@router.post("/password-reset/request/")
async def request_password_reset(
        payload: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    generic_response = {"message": "If you are registered, you will receive an email with instructions."}

    result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    user = result.scalars().first()

    if not user or not user.is_active:
        return generic_response

    existing_tokens = await db.execute(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    for token in existing_tokens.scalars():
        await db.delete(token)

    token_str = str(uuid.uuid4())
    reset_token = PasswordResetTokenModel(
        user_id=user.id,
        token=token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    db.add(reset_token)
    await db.commit()

    return generic_response


@router.post("/reset-password/complete/")
async def reset_password_complete(
        payload: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
        user = result.scalars().first()

        if not user.is_active:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        token_result = await db.execute(
            select(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        token_record = token_result.scalars().first()

        if token_record and token_record.token != payload.token:
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        if not token_record:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user._hashed_password = hash_password(payload.password)
        await db.delete(token_record)
        await db.commit()

        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")