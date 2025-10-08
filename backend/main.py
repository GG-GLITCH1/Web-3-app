from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import logging
import os

# ---------------- CONFIG ----------------
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production-2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
MAX_BCRYPT_PASSWORD_LENGTH = 72  # bcrypt max bytes length

# ---------------- LOGGING ----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("web3_api")

# ---------------- DATABASE ----------------
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in SQLALCHEMY_DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------------- MODELS ----------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

# Create tables
try:
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Database tables created successfully")
except Exception as e:
    logger.error(f"❌ Database initialization failed: {e}")

# ---------------- SCHEMAS ----------------
class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

# ---------------- UTILS ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Truncate password to 72 bytes and hash with bcrypt."""
    pw_bytes = password.encode("utf-8")[:MAX_BCRYPT_PASSWORD_LENGTH]
    truncated = pw_bytes.decode("utf-8", errors="ignore")
    return pwd_context.hash(truncated)

def verify_password(plain: str, hashed: str) -> bool:
    """Verify password safely."""
    pw_bytes = plain.encode("utf-8")[:MAX_BCRYPT_PASSWORD_LENGTH]
    truncated = pw_bytes.decode("utf-8", errors="ignore")
    return pwd_context.verify(truncated, hashed)

# ---------------- AUTH ----------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise credentials_exception
    return user

# ---------------- FASTAPI APP ----------------
app = FastAPI(
    title="Official G.G Web3 API",
    version="2.1.0",
    description="Production-stable FastAPI backend with secure password handling and JWT authentication.",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for testing; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- ROUTES ----------------
@app.get("/")
def root():
    return {
        "message": "🔥 Official G.G Web3 API is RUNNING!",
        "status": "active",
        "version": "2.1.0",
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "database": "connected",
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    logger.info(f"🧾 Signup attempt: {user.username}")

    if len(user.password.encode("utf-8")) > MAX_BCRYPT_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password too long (max {MAX_BCRYPT_PASSWORD_LENGTH} bytes)",
        )

    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_pw)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    logger.info(f"✅ User created: {user.username}")
    return db_user

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    logger.info(f"🧾 Login attempt: {form_data.username}")
    
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        logger.warning(f"❌ User not found: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    try:
        if not verify_password(form_data.password, user.hashed_password):
            logger.warning(f"❌ Invalid password for user: {form_data.username}")
            raise HTTPException(status_code=401, detail="Invalid username or password")
    except Exception as e:
        logger.error(f"💥 Password verification failed: {e}")
        raise HTTPException(status_code=500, detail="Internal password verification error")

    try:
        access_token = create_access_token(data={"sub": user.username})
        logger.info(f"✅ Login successful: {form_data.username}")
        
        user_out = UserOut.from_orm(user)
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_out
        }
    except Exception as e:
        logger.error(f"💥 Token generation failed: {e}")
        raise HTTPException(status_code=500, detail="Token generation error")

@app.get("/me", response_model=UserOut)
def read_me(current_user: User = Depends(get_current_user)):
    return UserOut.from_orm(current_user)

# ---------------- MAIN ----------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
