from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import current_user
from app.models import User
from app.schemas import LoginIn, ProfileUpdate, TokenOut, UserOut
from app.security import create_token, hash_password, verify_password

router = APIRouter(prefix='/api/auth', tags=['Xác thực'])


@router.post('/login', response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=body.username).first()
    if user is None or not user.is_active or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'Sai tên đăng nhập hoặc mật khẩu')
    return TokenOut(access_token=create_token(user.id, user.role), user=UserOut.model_validate(user))


@router.get('/me', response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.put('/me', response_model=UserOut)
def update_me(body: ProfileUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    data = body.model_dump(exclude_unset=True)
    new_pw, cur_pw = data.pop('new_password', None), data.pop('current_password', None)
    if new_pw:
        if not cur_pw or not verify_password(cur_pw, user.password_hash):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Mật khẩu hiện tại không đúng')
        user.password_hash = hash_password(new_pw)
    for k, v in data.items():
        setattr(user, k, v)
    db.commit()
    return user
