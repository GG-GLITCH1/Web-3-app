from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, ConfigDict
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import logging

# -----------------------------------------------------------
# LOGGING SETUP
# -----------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("web3_api")

# -----------------------------------------------------------
# CONFIG
# -----------------------------------------------------------
SECRET_KEY = "your-secret-key-change-in-production-2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
MAX_BCRYPT_PASSWORD_LENGTH = 72  # bcrypt limit

# -----------------------------------------------------------
# DATABASE SETUP
# -----------------------------------------------------------
SQLALCHEMY_DATABASE_URL = "sqlite:///./app.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)


try:
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Database tables created successfully")
except Exception as e:
    logger.error(f"❌ Database initialization failed: {e}")

# -----------------------------------------------------------
# SCHEMAS (Pydantic v2)
# -----------------------------------------------------------
class UserBase(BaseModel):
    username: str
    email: str


class UserCreate(UserBase):
    password: str


class UserOut(UserBase):
    id: int
    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut


# -----------------------------------------------------------
# UTILS
# -----------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Safely hash password (truncate to 72 bytes for bcrypt)."""
    password_bytes = password.encode("utf-8")[:MAX_BCRYPT_PASSWORD_LENGTH]
    truncated_password = password_bytes.decode("utf-8", errors="ignore")
    return pwd_context.hash(truncated_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Safely verify password (truncate to 72 bytes)."""
    password_bytes = plain_password.encode("utf-8")[:MAX_BCRYPT_PASSWORD_LENGTH]
    truncated_password = password_bytes.decode("utf-8", errors="ignore")
    return pwd_context.verify(truncated_password, hashed_password)


# -----------------------------------------------------------
# AUTH
# -----------------------------------------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create JWT access token."""
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
    """Decode JWT and get current user from DB."""
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


# -----------------------------------------------------------
# FASTAPI APP
# -----------------------------------------------------------
app = FastAPI(
    title="Official G.G Web3 API - DEBUG MODE",
    version="2.0.1",
    description="Stable API with JWT auth, bcrypt fixes, and full FastAPI compatibility.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ For production, replace with frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------
# HEALTH ENDPOINTS
# -----------------------------------------------------------
@app.get("/")
def root():
    return {
        "message": "🔥 Official G.G Web3 API is RUNNING!",
        "status": "active",
        "version": "2.0.1",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "database": "connected",
        "timestamp": datetime.utcnow().isoformat(),
    }


# -----------------------------------------------------------
# AUTH ROUTES
# -----------------------------------------------------------
@app.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    logger.info(f"🧾 Signup attempt: {user.username}")

    # Password length safety
    if len(user.password.encode("utf-8")) > MAX_BCRYPT_PASSWORD_LENGTH:
        logger.warning("❌ Password exceeds bcrypt length limit.")
        raise HTTPException(
            status_code=400,
            detail=f"Password cannot exceed {MAX_BCRYPT_PASSWORD_LENGTH} bytes.",
        )

    # Check duplicates
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Save user
    hashed_pw = hash_password(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_pw)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    logger.info(f"✅ User created: {user.username}")
    return db_user


@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    logger.info(f"🔐 Login attempt: {form_data.username}")

    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"❌ Invalid login: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    try:
        access_token = create_access_token(data={"sub": user.username})
        user_out = UserOut.model_validate(user)  # ✅ Pydantic v2
        logger.info(f"✅ Login successful: {form_data.username}")
        return {"access_token": access_token, "token_type": "bearer", "user": user_out}
    except Exception as e:
        logger.error(f"💥 Token generation failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during login")


@app.get("/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return UserOut.model_validate(current_user)


# -----------------------------------------------------------
# ENTRY POINT
# -----------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
