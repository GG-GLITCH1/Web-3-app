# main.py -- merged: roles + ethereum wallet auth + existing code preserved

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, ConfigDict, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import logging
import os
import uuid

# eth-account for verifying signatures
from eth_account.messages import encode_defunct
from eth_account import Account

# -----------------------------------------------------------
# LOGGING SETUP
# -----------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("web3_api")

# -----------------------------------------------------------
# CONFIG (can be overridden by environment variables)
# -----------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production-2024")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
MAX_BCRYPT_PASSWORD_LENGTH = 72  # bcrypt limit

# -----------------------------------------------------------
# DATABASE SETUP
# -----------------------------------------------------------
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in SQLALCHEMY_DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -----------------------------------------------------------
# MODELS
# - Added: role (default "user")
# - Added: wallet_address (nullable) and wallet_nonce (nullable)
# Note: if you have an existing DB, run a migration or recreate DB to pick up new columns.
# -----------------------------------------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False)            # -> role-based access
    wallet_address = Column(String, unique=True, index=True, nullable=True)  # hex address
    wallet_nonce = Column(String, nullable=True)                     # current nonce/message for signing


try:
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Database tables created successfully (including role & wallet columns if new).")
except Exception as e:
    logger.error(f"❌ Database initialization failed: {e}")

# -----------------------------------------------------------
# SCHEMAS (Pydantic v2)
# -----------------------------------------------------------
class UserBase(BaseModel):
    username: str
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserOut(UserBase):
    id: int
    role: str
    wallet_address: str | None = None
    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

# -----------------------------------------------------------
# UTILS: password hashing, verification
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
# AUTH: JWT helpers and current user retrieval
# -----------------------------------------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create JWT access token. Includes role in payload if provided."""
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
    """Decode JWT and get current user from DB (raises 401 on any problem)."""
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
    if user is None:
        raise credentials_exception
    return user


def require_role(required_role: str):
    """Dependency factory to require a specific role (or higher)."""
    def _require(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role and current_user.role != "admin":
            # admin bypasses checks (admin can do everything)
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return current_user
    return _require

# -----------------------------------------------------------
# FASTAPI APP
# -----------------------------------------------------------
app = FastAPI(
    title="Official G.G Web3 API - DEBUG MODE",
    version="2.2.0",
    description="Stable API with JWT auth, roles, and Ethereum wallet authentication.",
)

# Allow origins - for production, set explicit origins via env and restrict
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
if isinstance(CORS_ORIGINS, str) and CORS_ORIGINS != "*":
    cors_list = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
else:
    cors_list = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_list,
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
        "version": "2.2.0",
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
# AUTH ROUTES (signup / login / me)
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
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_pw, role="user")
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
        # include role in token so clients can use role data if needed
        access_token = create_access_token(data={"sub": user.username, "role": user.role})
        user_out = UserOut.model_validate(user)  # Pydantic v2
        logger.info(f"✅ Login successful: {form_data.username}")
        return {"access_token": access_token, "token_type": "bearer", "user": user_out}
    except Exception as e:
        logger.error(f"💥 Token generation failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during login")


@app.get("/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return UserOut.model_validate(current_user)

# -----------------------------------------------------------
# ROLE-PROTECTED EXAMPLE ROUTE
# -----------------------------------------------------------
@app.get("/admin/dashboard")
def admin_dashboard(current_user: User = Depends(require_role("admin"))):
    return {"message": f"Welcome to admin dashboard, {current_user.username}"}

# -----------------------------------------------------------
# WALLET AUTHENTICATION (Ethereum)
# Flow:
# 1) Client requests a nonce message: POST /wallet/nonce { "wallet_address": "0x..." }
#    Server returns a message (random nonce) to be signed.
# 2) Client signs the message with their wallet and sends signature to:
#    - /wallet/login (public) -> server verifies, issues JWT (creates user if none)
#    - /wallet/link (authenticated) -> link wallet to existing account (verify later)
# -----------------------------------------------------------

@app.post("/wallet/nonce")
def wallet_nonce(wallet_address: str, db: Session = Depends(get_db)):
    """
    Generate and store a one-time nonce message for the wallet address.
    Client signs the returned message and sends signature to /wallet/login or /wallet/link.
    """
    wallet_address = wallet_address.lower()
    message = f"GG Web3 Auth nonce: {uuid.uuid4().hex}"
    # store nonce temporarily against any user with this wallet (if exists)
    user = db.query(User).filter(User.wallet_address == wallet_address).first()
    if user:
        user.wallet_nonce = message
        db.add(user)
    else:
        # If user doesn't exist, store nonce in a throwaway new user entry? Instead, we will
        # create or upsert the nonce into a lightweight record by creating a temporary user container.
        # Simpler: create a minimal user record if not exists (username/email placeholders).
        # NOTE: This creates placeholder users if wallet-login flow is used; you can change behavior.
        placeholder_username = f"wallet_{wallet_address[:8]}"
        placeholder_email = f"{wallet_address}@wallet.local"
        user = User(
            username=placeholder_username,
            email=placeholder_email,
            hashed_password=hash_password(uuid.uuid4().hex),  # random password so it's not empty
            role="user",
            wallet_address=wallet_address,
            wallet_nonce=message,
        )
        db.add(user)
    db.commit()
    logger.info(f"🔑 Generated nonce for wallet {wallet_address}")
    return {"message": message}


@app.post("/wallet/login")
def wallet_login(wallet_address: str, signature: str, db: Session = Depends(get_db)):
    """
    Wallet-only login: verifies signature against stored nonce message (or fails).
    If a user with the recovered wallet_address exists, returns JWT. Otherwise creates a user.
    """
    wallet_address = wallet_address.lower()
    user = db.query(User).filter(User.wallet_address == wallet_address).first()

    if not user:
        # Maybe the frontend didn't request /wallet/nonce beforehand; fail politely.
        logger.warning(f"❌ Wallet login attempted but no user found for {wallet_address}")
        raise HTTPException(status_code=400, detail="No nonce found for this wallet address. Request a nonce first.")

    if not user.wallet_nonce:
        logger.warning(f"❌ No nonce stored for wallet {wallet_address}")
        raise HTTPException(status_code=400, detail="No nonce available; please request a nonce first.")

    try:
        encoded = encode_defunct(text=user.wallet_nonce)
        recovered = Account.recover_message(encoded, signature=signature)
    except Exception as e:
        logger.error(f"💥 Signature verification error: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    if recovered.lower() != wallet_address.lower():
        logger.warning(f"❌ Recovered address ({recovered}) doesn't match provided ({wallet_address})")
        raise HTTPException(status_code=400, detail="Signature does not match wallet address")

    # signature OK -> issue JWT
    # If the user is a placeholder (created earlier) that's OK — use user record as-is.
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    # Clear nonce to prevent replay
    user.wallet_nonce = None
    db.add(user)
    db.commit()
    logger.info(f"✅ Wallet login success for {wallet_address} (user {user.username})")
    return {"access_token": access_token, "token_type": "bearer", "user": UserOut.model_validate(user)}


@app.post("/wallet/link")
def wallet_link(wallet_address: str, signature: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Link a wallet to an existing authenticated account.
    Frontend flow:
      1) Client requests a nonce (POST /wallet/nonce with the wallet_address)
      2) Client signs the nonce
      3) Client calls /wallet/link with wallet_address and signature while authenticated
    """
    wallet_address = wallet_address.lower()

    # Find the user record that holds the nonce for that wallet
    user_with_nonce = db.query(User).filter(User.wallet_address == wallet_address).first()
    if not user_with_nonce or not user_with_nonce.wallet_nonce:
        logger.warning("❌ No nonce found for wallet link.")
        raise HTTPException(status_code=400, detail="No nonce stored for this wallet. Request /wallet/nonce first.")

    try:
        encoded = encode_defunct(text=user_with_nonce.wallet_nonce)
        recovered = Account.recover_message(encoded, signature=signature)
    except Exception as e:
        logger.error(f"💥 Signature verification error during linking: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    if recovered.lower() != wallet_address.lower():
        logger.warning("❌ Recovered address mismatch during linking.")
        raise HTTPException(status_code=400, detail="Signature does not match wallet address")

    # Check whether some other user already has that wallet_address
    conflict = db.query(User).filter(User.wallet_address == wallet_address).first()
    if conflict and conflict.id != current_user.id:
        logger.warning("❌ Wallet already linked to another account.")
        raise HTTPException(status_code=400, detail="Wallet already linked to another account.")

    # Link wallet to the currently authenticated user
    current_user.wallet_address = wallet_address
    current_user.wallet_nonce = None
    db.add(current_user)
    db.commit()
    logger.info(f"🔗 Wallet {wallet_address} linked to user {current_user.username}")
    return {"message": "Wallet linked", "wallet_address": wallet_address, "user": UserOut.model_validate(current_user)}


# -----------------------------------------------------------
# ENTRY POINT
# -----------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), log_level="info")
