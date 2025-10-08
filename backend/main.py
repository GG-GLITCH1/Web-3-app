   from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import requests
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------- CONFIG ----------------
SECRET_KEY = "your-secret-key-change-in-production-2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
MAX_BCRYPT_PASSWORD_LENGTH = 72  # bcrypt max input size

# ---------------- DATABASE ----------------
SQLALCHEMY_DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------------- MODELS ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

# Create tables
try:
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Database tables created successfully")
except Exception as e:
    logger.error(f"❌ Database error: {e}")

# ---------------- SCHEMAS ----------------
class UserBase(BaseModel):
    username: str
    email: str

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
    """
    Truncate password to 72 bytes and hash with bcrypt.
    """
    # Truncate by bytes length, not characters
    password_bytes = password.encode('utf-8')[:MAX_BCRYPT_PASSWORD_LENGTH]
    truncated_password = password_bytes.decode('utf-8', errors='ignore')
    return pwd_context.hash(truncated_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Truncate plain password to 72 bytes and verify against hash.
    """
    password_bytes = plain_password.encode('utf-8')[:MAX_BCRYPT_PASSWORD_LENGTH]
    truncated_password = password_bytes.decode('utf-8', errors='ignore')
    return pwd_context.verify(truncated_password, hashed_password)

# ---------------- AUTH ----------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
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
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# ---------------- FASTAPI APP ----------------
app = FastAPI(
    title="Official G.G Web3 API - DEBUG MODE",
    version="2.0.0",
    description="Fixed version with proper error handling and password fixes"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for debugging
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- HEALTH CHECK ----------------
@app.get("/")
def root():
    return {
        "message": "🔥 Official G.G Web3 API is RUNNING!",
        "status": "active",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "database": "connected",
        "timestamp": datetime.utcnow().isoformat()
    }

# ---------------- AUTH ROUTES ----------------
@app.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    logger.info(f"🔄 Signup attempt for user: {user.username}")

    # Check password length before processing
    if len(user.password.encode('utf-8')) > MAX_BCRYPT_PASSWORD_LENGTH:
        logger.warning(f"❌ Password too long: {len(user.password.encode('utf-8'))} bytes")
        raise HTTPException(
            status_code=400,
            detail=f"Password cannot exceed {MAX_BCRYPT_PASSWORD_LENGTH} bytes. Please use a shorter password."
        )
    
    if db.query(User).filter(User.username == user.username).first():
        logger.warning(f"❌ Username already exists: {user.username}")
        raise HTTPException(status_code=400, detail="Username already registered")
    
    if db.query(User).filter(User.email == user.email).first():
        logger.warning(f"❌ Email already exists: {user.email}")
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pw = hash_password(user.password)
    
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_pw)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    logger.info(f"✅ User created successfully: {user.username}")
    return db_user

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    logger.info(f"🔄 Login attempt for user: {form_data.username}")
    
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        logger.warning(f"❌ User not found: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"❌ Invalid password for user: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    access_token = create_access_token(data={"sub": user.username})
    logger.info(f"✅ Login successful: {form_data.username}")
    
    user_out = UserOut.from_orm(user)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_out
    }

@app.get("/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return UserOut.from_orm(current_user)

# (Your other endpoints unchanged...)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

