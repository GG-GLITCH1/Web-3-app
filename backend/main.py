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
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------- CONFIG ----------------
SECRET_KEY = "your-secret-key-change-in-production-2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ---------------- DATABASE ----------------
SQLALCHEMY_DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
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

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ---------------- AUTH ----------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: timedelta = None):
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

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
    description="Fixed version with proper error handling"
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

# ---------------- AUTH ROUTES (FIXED) ----------------
@app.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    try:
        logger.info(f"🔄 Signup attempt for user: {user.username}")
        
        # Check if user exists
        existing_user = db.query(User).filter(User.username == user.username).first()
        if existing_user:
            logger.warning(f"❌ Username already exists: {user.username}")
            raise HTTPException(status_code=400, detail="Username already registered")
        
        existing_email = db.query(User).filter(User.email == user.email).first()
        if existing_email:
            logger.warning(f"❌ Email already exists: {user.email}")
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create user
        hashed_pw = hash_password(user.password)
        db_user = User(username=user.username, email=user.email, hashed_password=hashed_pw)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        logger.info(f"✅ User created successfully: {user.username}")
        return db_user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"🚨 Signup error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
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
        
        return {
            "access_token": access_token, 
            "token_type": "bearer",
            "user": user
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"🚨 Login error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.get("/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# ---------------- SIMPLIFIED PRICE API ----------------
@app.get("/prices/{token_id}")
def get_token_price(token_id: str):
    """Get token price from CoinGecko - SIMPLIFIED"""
    try:
        logger.info(f"🔄 Fetching price for: {token_id}")
        
        # Convert token_id to CoinGecko format
        coin_id = token_id.lower()
        
        url = f"https://api.coingecko.com/api/v3/simple/price?ids={coin_id}&vs_currencies=usd"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            logger.warning(f"❌ Price API error for {token_id}: {response.status_code}")
            # Return mock data for testing
            return {
                "token": token_id,
                "price_usd": 2500.0 if token_id.lower() == "ethereum" else 1.5,
                "source": "mock_data",
                "message": "Real API failed, using mock data"
            }
        
        data = response.json()
        
        if coin_id not in data:
            logger.warning(f"❌ Token not found: {token_id}")
            raise HTTPException(status_code=404, detail="Token not found")
            
        return {
            "token": token_id,
            "price_usd": data[coin_id]['usd'],
            "source": "coingecko"
        }
        
    except Exception as e:
        logger.error(f"🚨 Price fetch error: {str(e)}")
        # Fallback to mock data
        return {
            "token": token_id,
            "price_usd": 2500.0 if token_id.lower() == "ethereum" else 1.5,
            "source": "mock_fallback",
            "error": str(e)
        }

# ---------------- MOCK WEB3 ENDPOINTS (FOR NOW) ----------------
@app.get("/web3/status")
def web3_status():
    """Web3 connection status"""
    return {
        "status": "connected",
        "message": "✅ Web3 services are available",
        "network": "Ethereum Mainnet",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/wallet/balance/{address}")
def get_wallet_balance(address: str):
    """Mock wallet balance endpoint"""
    try:
        logger.info(f"🔄 Fetching balance for: {address}")
        
        # Simple address validation
        if not address.startswith("0x") or len(address) != 42:
            raise HTTPException(status_code=400, detail="Invalid Ethereum address format")
        
        # Return mock data for now
        return {
            "success": True,
            "wallet_address": address,
            "eth_balance": 2.5,  # Mock ETH balance
            "tokens": [
                {
                    "symbol": "STEVE",
                    "name": "Stevedeeve Token",
                    "balance": 1000.0,
                    "contract_address": "0x957dffb1b074953392bc2e587a472967342788ff"
                }
            ],
            "message": "Mock data - Real Web3 integration in progress",
            "source": "mock_data"
        }
        
    except Exception as e:
        logger.error(f"🚨 Wallet balance error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Balance check failed: {str(e)}")

# ---------------- DEBUG ENDPOINTS ----------------
@app.get("/debug/database")
def debug_database(db: Session = Depends(get_db)):
    """Check database status"""
    try:
        users = db.query(User).all()
        return {
            "database": "connected",
            "total_users": len(users),
            "users": [{"id": u.id, "username": u.username, "email": u.email} for u in users],
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "database": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

@app.get("/debug/endpoints")
def list_endpoints():
    """List all available endpoints"""
    endpoints = []
    for route in app.routes:
        if hasattr(route, "methods"):
            endpoints.append({
                "path": route.path,
                "methods": list(route.methods),
                "name": getattr(route, "name", "N/A")
            })
    return {"endpoints": endpoints}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
