import uuid
import bcrypt
from fastapi import APIRouter, Depends, HTTPException

from database import get_db
from models.user import User
from pydantic_schemas.user_create import UserCreate
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from pydantic_schemas.user_login import UserLogin


router = APIRouter()


@router.post("/signup", status_code=201)
async def signup_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the user already exists in the database
    user_db = db.query(User).filter(User.email == user.email).first()
    if user_db:
        raise HTTPException(
            status_code=400, detail="User with the same email already exists!"
        )

    # Hash the password
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())

    new_user = User(
        id=str(uuid.uuid4()), name=user.name, email=user.email, password=hashed_password
    )
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create user")

    return {"id": new_user.id, "name": new_user.name, "email": new_user.email}


@router.post("/login")
async def login_user(user: UserLogin, db: Session = Depends(get_db)):
    # Check if the user with same email and password exists or not
    user_db = db.query(User).filter(User.email == user.email).first()
    if not user_db:
        raise HTTPException(
            status_code=400, detail="User with this email does not exist!"
        )

    # Password matching or not
    is_match = bcrypt.checkpw(user.password.encode(), user_db.password)  # type: ignore
    if not is_match:
        raise HTTPException(status_code=400, detail="Incorrect password!")
    return user_db
