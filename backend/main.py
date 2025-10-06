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
from dotenv import load_dotenv

load_dotenv()

# ---------------- CONFIG ----------------
INFURA_KEY = os.getenv("INFURA_KEY", "your_infura_key_here")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey-change-in-production")
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
    wallet_address = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# ---------------- SCHEMAS ----------------
class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    wallet_address: str = None
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

class WalletConnect(BaseModel):
    address: str

# ---------------- UTILS ----------------
# FIX: Use a different hashing method that doesn't have the 72-byte limit
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

def hash_password(password: str):
    # Truncate password to 72 characters if longer (bcrypt limit)
    if len(password) > 72:
        password = password[:72]
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    # Truncate password to 72 characters if longer (bcrypt limit)
    if len(plain_password) > 72:
        plain_password = plain_password[:72]
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

# ---------------- WEB3 SETUP ----------------
STEVEDEEVE_CONTRACT = "0x957dffb1b074953392bc2e587a472967342788ff"
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function"
    }
]

def get_web3():
    rpc_url = f"https://mainnet.infura.io/v3/{INFURA_KEY}"
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    return w3

# ---------------- FASTAPI APP ----------------
app = FastAPI(title="Official G.G Web3 API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Changed to allow all for testing
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
    
    # FIX: Password length check
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
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
    # Validate Ethereum address
    w3 = get_web3()
    if not w3.is_address(wallet.address):
        raise HTTPException(status_code=400, detail="Invalid Ethereum address")
    
    current_user.wallet_address = wallet.address
    db.commit()
    return {"message": "Wallet connected successfully", "address": wallet.address}

@app.get("/prices/{token_id}")
def get_token_price(token_id: str):
    """Get token price from CoinGecko"""
    url = f"https://api.coingecko.com/api/v3/simple/price?ids={token_id}&vs_currencies=usd"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if token_id not in data or 'usd' not in data[token_id]:
            raise HTTPException(status_code=404, detail="Token not found")
            
        return {"token": token_id, "price_usd": data[token_id]['usd']}
    except requests.RequestException:
        raise HTTPException(status_code=500, detail="Failed to fetch price data")

@app.get("/wallet/balance/{address}")
def get_wallet_balance(address: str):
    """Get ETH balance and token balances for a wallet"""
    w3 = get_web3()
    
    if not w3.is_connected():
        raise HTTPException(status_code=500, detail="Blockchain connection failed")
    
    if not w3.is_address(address):
        raise HTTPException(status_code=400, detail="Invalid Ethereum address")
    
    try:
        # Get ETH balance
        eth_balance = w3.eth.get_balance(w3.to_checksum_address(address))
        eth_balance_ether = w3.from_wei(eth_balance, 'ether')
        
        # Get Stevedeeve token balance
        contract = w3.eth.contract(
            address=w3.to_checksum_address(STEVEDEEVE_CONTRACT), 
            abi=ERC20_ABI
        )
        
        token_balance = contract.functions.balanceOf(w3.to_checksum_address(address)).call()
        decimals = contract.functions.decimals().call()
        token_balance_normalized = token_balance / (10 ** decimals)
        token_symbol = contract.functions.symbol().call()
        token_name = contract.functions.name().call()
        
        return {
            "wallet_address": address,
            "eth_balance": float(eth_balance_ether),
            "tokens": [
                {
                    "symbol": token_symbol,
                    "name": token_name,
                    "balance": float(token_balance_normalized),
                    "contract_address": STEVEDEEVE_CONTRACT
                }
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching balance: {str(e)}")

@app.get("/")
def root():
    return {"message": "Official G.G Web3 API is running!", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
