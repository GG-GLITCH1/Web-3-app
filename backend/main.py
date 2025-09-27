from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel, ConfigDict
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from web3 import Web3
import requests
import os
from dotenv import load_dotenv

load_dotenv()

# ---------------- DATABASE SETUP ----------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./steevedeeve.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------------- MODELS ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    wallet_address = Column(String, nullable=True)
    created_at = Column(String, default=lambda: datetime.utcnow().isoformat())

try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print(f"Database setup note: {e}")

# ---------------- SCHEMAS (Pydantic v2) ----------------
class UserBase(BaseModel):
    username: str
    email: str
    
    model_config = ConfigDict(from_attributes=True)  # Replaces orm_mode

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    wallet_address: str | None = None

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

class WalletConnect(BaseModel):
    address: str

# ---------------- UTILS ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ---------------- AUTH ----------------
SECRET_KEY = os.getenv("SECRET_KEY", "steevedeeve-super-secret-key-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
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

# ---------------- WEB3 SETUP ----------------
STEVEDEEVE_CONTRACT = "0x957dffb1b074953392bc2e587a472967342788ff"

RPC_ENDPOINTS = [
    "https://eth-mainnet.public.blastapi.io",
    "https://rpc.ankr.com/eth",
    "https://cloudflare-eth.com"
]

ERC20_ABI = [
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"}
]

def get_web3():
    for rpc_url in RPC_ENDPOINTS:
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 10}))
            if w3.is_connected():
                return w3
        except:
            continue
    raise Exception("All RPC endpoints failed")

# ---------------- FASTAPI APP ----------------
app = FastAPI(
    title="steevedeeve Web3 API",
    description="A powerful Web3 portfolio tracker by steevedeeve",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- ROUTES ----------------
@app.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pw = hash_password(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_pw)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    access_token = create_access_token(data={"sub": user.username})
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": user
    }

@app.get("/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/me/wallet")
def connect_wallet(wallet: WalletConnect, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    w3 = get_web3()
    if not w3.is_address(wallet.address):
        raise HTTPException(status_code=400, detail="Invalid Ethereum address")
    
    current_user.wallet_address = wallet.address
    db.commit()
    return {"message": "Wallet connected successfully", "address": wallet.address}

@app.get("/prices/{token_id}")
def get_token_price(token_id: str):
    url = f"https://api.coingecko.com/api/v3/simple/price?ids={token_id}&vs_currencies=usd"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if token_id not in data:
            raise HTTPException(status_code=404, detail="Token not found")
            
        return {"token": token_id, "price_usd": data[token_id]['usd']}
    except requests.RequestException:
        raise HTTPException(status_code=500, detail="Failed to fetch price data")

@app.get("/wallet/balance/{address}")
def get_wallet_balance(address: str):
    w3 = get_web3()
    
    if not w3.is_connected():
        raise HTTPException(status_code=500, detail="Blockchain connection failed")
    
    if not w3.is_address(address):
        raise HTTPException(status_code=400, detail="Invalid Ethereum address")
    
    try:
        # ETH Balance
        eth_balance = w3.eth.get_balance(w3.to_checksum_address(address))
        eth_balance_ether = w3.from_wei(eth_balance, 'ether')
        
        # Token Balance
        contract = w3.eth.contract(
            address=w3.to_checksum_address(STEVEDEEVE_CONTRACT), 
            abi=ERC20_ABI
        )
        
        token_balance = contract.functions.balanceOf(w3.to_checksum_address(address)).call()
        decimals = contract.functions.decimals().call()
        token_balance_normalized = token_balance / (10 ** decimals)
        token_symbol = contract.functions.symbol().call()
        
        return {
            "wallet_address": address,
            "eth_balance": float(eth_balance_ether),
            "tokens": [
                {
                    "symbol": token_symbol,
                    "balance": float(token_balance_normalized),
                    "contract_address": STEVEDEEVE_CONTRACT
                }
            ]
        }
        
    except Exception as e:
        return {"error": f"Error fetching balance: {str(e)}"}

@app.get("/")
def root():
    return {
        "message": "steevedeeve Web3 API is running!", 
        "version": "2.0.0",
        "developer": "steevedeeve",
        "documentation": "/docs"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
