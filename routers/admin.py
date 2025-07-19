from fastapi import APIRouter, Depends, HTTPException, status
from typing import Annotated, Optional
from schemas import UserCreate, UserPublic, UserInDB
from security import get_password_hash, get_current_admin_user
import database as Db

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.get("/get_users")
async def get_users(admin: Annotated[UserPublic, Depends(get_current_admin_user)]) -> list[UserPublic]:
    users = Db.get_all_users()
    return list(users)

@router.post("/create_user")
async def create_user(user_data: UserCreate, admin: Annotated[UserPublic, Depends(get_current_admin_user)]) -> UserPublic:
    db_user = Db.get_user(user_data.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten kayıtlı.")
    hashed_password = get_password_hash(user_data.password)
    user_in_db = UserInDB(**user_data.model_dump(), hashed_password=hashed_password)
    new_user = Db.add_user(**user_in_db.model_dump())
    user_dict = Db.get_user(user_data.username)
    return UserPublic(**user_dict) if user_dict else None

@router.delete("/delete_user/{username}")
async def delete_user(username: str, admin: Annotated[UserPublic, Depends(get_current_admin_user)]) -> dict:
    if username == admin['username']:
        raise HTTPException(status_code=400, detail="Admin kendi kendini silemez.")
    delete_result = Db.delete_user(username)
    if delete_result.get("status") == "success":
        return {"message": f"{username} kullanıcısı başarıyla silindi."}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{username} adlı kullanıcı bulunamadı")

@router.post("/admin_check")
async def admin_check() -> UserPublic:
    admin_user = Db.get_admin()
    return admin_user