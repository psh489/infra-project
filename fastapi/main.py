import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- 1. 환경 변수 (AWS Secrets Manager 주입용) ---
# os.environ을 사용하여 설정이 누락되었을 때 바로 에러를 발생시킵니다.
try:
    DB_USER = os.environ["DB_USER"]
    DB_PASS = os.environ["DB_PASS"]
    DB_HOST = os.environ["DB_HOST"]
    DB_NAME = os.environ["DB_NAME"]
    SECRET_KEY = os.environ["JWT_SECRET"] # 세 훈님이 정해서 Secrets Manager에 넣을 값
except KeyError as e:
    # 어떤 환경변수가 빠졌는지 명확하게 출력합니다.
    raise RuntimeError(f"필수 환경 변수 설정 누락: {e}. Secrets Manager를 확인하세요.")

DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:3306/{DB_NAME}"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 

# --- 2. 보안 및 DB 초기화 ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="ST6 Cloud Member API")

# --- 3. Pydantic 모델 ---
class UserSignup(BaseModel):
    user_id: str
    password: str
    username: str
    email: Optional[EmailStr] = None

class UserLogin(BaseModel):
    user_id: str
    password: str

class PasswordUpdate(BaseModel):
    current_password: str
    new_password: str

# --- 4. 종속성 함수 ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="로그인 정보가 유효하지 않거나 만료되었습니다.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    query = text("SELECT user_id, username, email FROM users WHERE user_id = :u_id")
    user = db.execute(query, {"u_id": user_id}).fetchone()
    if user is None:
        raise credentials_exception
    return user

# --- 5. API 엔드포인트 ---

@app.get("/")
def health_check():
    return {"status": "ok", "message": "API is healthy"}

@app.post("/api/signup")
def signup(user: UserSignup, db=Depends(get_db)):
    check_query = text("SELECT user_id FROM users WHERE user_id = :u_id")
    if db.execute(check_query, {"u_id": user.user_id}).fetchone():
        raise HTTPException(status_code=400, detail="이미 등록된 아이디입니다.")
    
    hashed_pwd = pwd_context.hash(user.password)
    db.execute(text("INSERT INTO users (user_id, password, username, email) VALUES (:u_id, :pwd, :name, :email)"),
               {"u_id": user.user_id, "pwd": hashed_pwd, "name": user.username, "email": user.email})
    db.commit()
    return {"message": "가입 성공"}

@app.post("/api/login")
def login(user: UserLogin, db=Depends(get_db)):
    db_user = db.execute(text("SELECT user_id, password, username FROM users WHERE user_id = :u_id"), 
                         {"u_id": user.user_id}).fetchone()
    if not db_user or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="인증 실패")
    
    access_token = jwt.encode({"sub": db_user.user_id}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer", "username": db_user.username}

@app.get("/api/me")
def read_me(current_user=Depends(get_current_user)):
    return {"user_id": current_user.user_id, "username": current_user.username}

@app.put("/api/password")
def update_password(data: PasswordUpdate, current_user=Depends(get_current_user), db=Depends(get_db)):
    db_pwd = db.execute(text("SELECT password FROM users WHERE user_id = :u"), {"u": current_user.user_id}).fetchone()[0]
    if not pwd_context.verify(data.current_password, db_pwd):
        raise HTTPException(status_code=400, detail="비밀번호 불일치")
    db.execute(text("UPDATE users SET password = :p WHERE user_id = :u"), 
               {"p": pwd_context.hash(data.new_password), "u": current_user.user_id})
    db.commit()
    return {"message": "변경 완료"}

@app.delete("/api/user")
def delete_account(current_user=Depends(get_current_user), db=Depends(get_db)):
    db.execute(text("DELETE FROM users WHERE user_id = :u"), {"u": current_user.user_id})
    db.commit()
    return {"message": "탈퇴 완료"}

# --- 6. 서버 실행 ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)