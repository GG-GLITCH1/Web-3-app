import React, { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

const API = axios.create({
  baseURL: process.env.REACT_APP_API_URL || "http://localhost:8000",
});

API.interceptors.request.use((req) => {
  const token = localStorage.getItem("token");
  if (token) {
    req.headers.Authorization = `Bearer ${token}`;
  }
  return req;
});

API.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("token");
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

function App() {
  const [page, setPage] = useState("login");
  const [formData, setFormData] = useState({ username: "", email: "", password: "" });
  const [user, setUser] = useState(null);
  const [portfolio, setPortfolio] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      fetchUserData();
    }
  }, []);

  const fetchUserData = async () => {
    try {
      const userRes = await API.get("/me");
      setUser(userRes.data);
      setPage("dashboard");
      
      if (userRes.data.wallet_address) {
        fetchPortfolio(userRes.data.wallet_address);
      }
    } catch (err) {
      console.error("Failed to fetch user data:", err);
    }
  };

  const fetchPortfolio = async (address) => {
    try {
      const portfolioRes = await API.get(`/portfolio/${address}`);
      setPortfolio(portfolioRes.data);
    } catch (err) {
      console.error("Failed to fetch portfolio:", err);
    }
  };

  const handleInputChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    
    try {
      await API.post("/signup", formData);
      alert("Account created successfully! Please login.");
      setFormData({ username: "", email: "", password: "" });
      setPage("login");
    } catch (err) {
      setError(err.response?.data?.detail || "Signup failed");
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    
    try {
      const loginData = new URLSearchParams();
      loginData.append('username', formData.username);
      loginData.append('password', formData.password);
      
      const res = await API.post("/login", loginData, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      localStorage.setItem("token", res.data.access_token);
      setUser(res.data.user);
      setPage("dashboard");
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    setUser(null);
    setPortfolio(null);
    setPage("login");
  };

  const connectWallet = async () => {
    if (!window.ethereum) {
      alert("Please install MetaMask to connect your wallet!");
      return;
    }

    try {
      setLoading(true);
      const accounts = await window.ethereum.request({ 
        method: "eth_requestAccounts" 
      });
      
      const address = accounts[0];
      
      await API.post("/me/wallet", { address });
      
      const userRes = await API.get("/me");
      setUser(userRes.data);
      fetchPortfolio(address);
      
    } catch (err) {
      setError("Failed to connect wallet");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (page === "signup") {
    return (
      <div className="app-container">
        <div className="auth-box">
          <div className="header">
            <h1>🚀 steevedeeve Web3</h1>
            <p>Portfolio Tracker</p>
          </div>
          
          {error && <div className="error-message">{error}</div>}
          
          <form onSubmit={handleSignup} className="auth-form">
            <input 
              name="username" 
              placeholder="Username" 
              value={formData.username} 
              onChange={handleInputChange} 
              required 
            />
            <input 
              name="email" 
              type="email" 
              placeholder="Email" 
              value={formData.email} 
              onChange={handleInputChange} 
              required 
            />
            <input 
              name="password" 
              type="password" 
              placeholder="Password" 
              value={formData.password} 
              onChange={handleInputChange} 
              required 
            />
            <button type="submit" disabled={loading}>
              {loading ? "Creating Account..." : "Sign Up"}
            </button>
          </form>
          
          <p className="auth-switch" onClick={() => setPage("login")}>
            Already have an account? Login here
          </p>
        </div>
      </div>
    );
  }

  if (page === "login") {
    return (
      <div className="app-container">
        <div className="auth-box">
          <div className="header">
            <h1>🚀 steevedeeve Web3</h1>
            <p>Portfolio Tracker</p>
          </div>
          
          {error && <div className="error-message">{error}</div>}
          
          <form onSubmit={handleLogin} className="auth-form">
            <input 
              name="username" 
              placeholder="Username" 
              value={formData.username} 
              onChange={handleInputChange} 
              required 
            />
            <input 
              name="password" 
              type="password" 
              placeholder="Password" 
              value={formData.password} 
              onChange={handleInputChange} 
              required 
            />
            <button type="submit" disabled={loading}>
              {loading ? "Logging in..." : "Login"}
            </button>
          </form>
          
          <p className="auth-switch" onClick={() => setPage("signup")}>
            Don't have an account? Sign up
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      <div className="dashboard">
        <div className="dashboard-header">
          <h1>📊 steevedeeve Portfolio Dashboard</h1>
          <button onClick={handleLogout} className="logout-btn">Logout</button>
        </div>

        {user && (
          <div className="user-card">
            <h3>Welcome, {user.username}!</h3>
            <p>Email: {user.email}</p>
            {user.wallet_address ? (
              <p className="wallet-address">
                🔗 Wallet: {user.wallet_address.slice(0, 8)}...{user.wallet_address.slice(-6)}
              </p>
            ) : (
              <p>No wallet connected</p>
            )}
          </div>
        )}

        <div className="wallet-section">
          <h3>🔗 Connect Your Wallet</h3>
          <button 
            onClick={connectWallet} 
            disabled={loading}
            className="connect-btn"
          >
            {loading ? "Connecting..." : 
             user?.wallet_address ? "Wallet Connected ✅" : "Connect MetaMask"}
          </button>
        </div>

        {portfolio && (
          <div className="portfolio-section">
            <h3>💰 Portfolio Overview</h3>
            <div className="portfolio-value">
              <h2>Total Value: ${portfolio.total_value?.toFixed(2) || "0.00"}</h2>
            </div>
            
            <div className="portfolio-breakdown">
              <h4>Asset Breakdown</h4>
              <div className="assets-grid">
                <div className="asset-card">
                  <span>Ethereum</span>
                  <span>${portfolio.breakdown?.ethereum?.toFixed(2) || "0.00"}</span>
                </div>
                {portfolio.breakdown?.tokens && Object.entries(portfolio.breakdown.tokens).map(([symbol, value]) => (
                  <div key={symbol} className="asset-card">
                    <span>{symbol}</span>
                    <span>${value?.toFixed(2) || "0.00"}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        <div className="footer">
          <p>Built with ❤️ by steevedeeve & official G•G'(@/</p>
          <p>Web3 Portfolio Tracker v2.0</p>
        </div>
      </div>
    </div>
  );
}

export default App;
