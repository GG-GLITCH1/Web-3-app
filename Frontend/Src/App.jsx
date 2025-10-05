import React, { useState, useEffect } from "react";
import axios from "axios";

// ✅ USE YOUR ACTUAL BACKEND URL
const API = axios.create({
  baseURL: "https://web-3-app-3.onrender.com",
});

// Request interceptor for auth tokens
API.interceptors.request.use((req) => {
  const token = localStorage.getItem("token");
  if (token) {
    req.headers.Authorization = `Bearer ${token}`;
  }
  return req;
});

// Response interceptor for error handling
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
  const [prices, setPrices] = useState({ eth: null, btc: null });
  const [wallet, setWallet] = useState({ address: null, balance: null, tokens: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Check if user is already logged in
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      fetchUserData();
    }
  }, []);

  const fetchUserData = async () => {
    try {
      const [userRes, ethPriceRes] = await Promise.all([
        API.get("/me"),
        API.get("/prices/ethereum")
      ]);
      
      setUser(userRes.data);
      setPrices(prev => ({ ...prev, eth: ethPriceRes.data.price_usd }));
      setPage("dashboard");
    } catch (err) {
      console.error("Failed to fetch user data:", err);
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
      alert("Signup successful! Please login.");
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
      const loginForm = new URLSearchParams();
      loginForm.append('username', formData.username);
      loginForm.append('password', formData.password);
      
      const res = await API.post("/login", loginForm, {
        headers: { 
          "Content-Type": "application/x-www-form-urlencoded" 
        }
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
    setWallet({ address: null, balance: null, tokens: [] });
    setPage("login");
  };

  const connectWallet = async () => {
    if (!window.ethereum) {
      alert("Please install MetaMask!");
      return;
    }

    try {
      setLoading(true);
      const accounts = await window.ethereum.request({ 
        method: "eth_requestAccounts" 
      });
      
      const address = accounts[0];
      setWallet(prev => ({ ...prev, address }));
      
      // Save wallet to user profile
      await API.post("/me/wallet", { address });
      
      // Fetch wallet balances
      const balanceRes = await API.get(`/wallet/balance/${address}`);
      setWallet(prev => ({ ...prev, ...balanceRes.data }));
      
    } catch (err) {
      setError("Failed to connect wallet");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Add some basic styling
  const styles = {
    container: {
      maxWidth: '800px',
      margin: '0 auto',
      padding: '20px',
      fontFamily: 'monospace'
    },
    form: {
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
      marginBottom: '20px'
    },
    input: {
      padding: '10px',
      border: '1px solid #00ff00',
      background: 'transparent',
      color: '#00ff00',
      borderRadius: '5px',
      fontSize: '16px'
    },
    button: {
      padding: '12px 24px',
      border: '1px solid #00ff00',
      background: '#00ff00',
      color: '#000',
      borderRadius: '5px',
      cursor: 'pointer',
      fontWeight: 'bold',
      fontSize: '16px'
    },
    error: {
      color: '#ff0066',
      margin: '10px 0',
      padding: '10px',
      border: '1px solid #ff0066',
      borderRadius: '5px'
    },
    section: {
      margin: '20px 0',
      padding: '20px',
      border: '1px solid #00ff00',
      borderRadius: '10px'
    },
    link: {
      color: '#00ff00',
      cursor: 'pointer',
      textDecoration: 'underline',
      marginTop: '15px',
      display: 'block'
    }
  };

  // Render methods
  if (page === "signup") {
    return (
      <div style={styles.container}>
        <h2>🔥 Official G.G - Sign Up</h2>
        {error && <div style={styles.error}>{error}</div>}
        
        <form style={styles.form} onSubmit={handleSignup}>
          <input 
            style={styles.input}
            name="username" 
            placeholder="Username" 
            value={formData.username} 
            onChange={handleInputChange} 
            required 
          />
          <input 
            style={styles.input}
            name="email" 
            type="email" 
            placeholder="Email" 
            value={formData.email} 
            onChange={handleInputChange} 
            required 
          />
          <input 
            style={styles.input}
            name="password" 
            type="password" 
            placeholder="Password" 
            value={formData.password} 
            onChange={handleInputChange} 
            required 
          />
          <button style={styles.button} type="submit" disabled={loading}>
            {loading ? "Creating Account..." : "Sign Up"}
          </button>
        </form>
        
        <span style={styles.link} onClick={() => setPage("login")}>
          Already have an account? Login
        </span>
      </div>
    );
  }

  if (page === "login") {
    return (
      <div style={styles.container}>
        <h2>🔥 Official G.G - Login</h2>
        {error && <div style={styles.error}>{error}</div>}
        
        <form style={styles.form} onSubmit={handleLogin}>
          <input 
            style={styles.input}
            name="username" 
            placeholder="Username" 
            value={formData.username} 
            onChange={handleInputChange} 
            required 
          />
          <input 
            style={styles.input}
            name="password" 
            type="password" 
            placeholder="Password" 
            value={formData.password} 
            onChange={handleInputChange} 
            required 
          />
          <button style={styles.button} type="submit" disabled={loading}>
            {loading ? "Logging in..." : "Login"}
          </button>
        </form>
        
        <span style={styles.link} onClick={() => setPage("signup")}>
          Don't have an account? Sign up
        </span>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <h2>🔥 Official G.G Dashboard</h2>
      
      {user && (
        <div style={styles.section}>
          <h3>Welcome, {user.username}!</h3>
          <p>Email: {user.email}</p>
          {user.wallet_address && <p>Wallet: {user.wallet_address}</p>}
        </div>
      )}

      <div style={styles.section}>
        <h3>💰 Market Prices</h3>
        {prices.eth && <p>ETH: ${prices.eth}</p>}
        {prices.btc && <p>BTC: ${prices.btc}</p>}
      </div>

      <div style={styles.section}>
        <h3>🔗 Wallet Connection</h3>
        <button 
          style={styles.button} 
          onClick={connectWallet} 
          disabled={loading || !window.ethereum}
        >
          {loading ? "Connecting..." : wallet.address ? 
            `Connected: ${wallet.address.slice(0, 6)}...${wallet.address.slice(-4)}` : 
            "Connect MetaMask"}
        </button>

        {wallet.eth_balance !== null && (
          <div style={{marginTop: '15px'}}>
            <p>ETH Balance: {wallet.eth_balance}</p>
            {wallet.tokens && wallet.tokens.map(token => (
              <p key={token.symbol}>
                {token.name} ({token.symbol}): {token.balance}
              </p>
            ))}
          </div>
        )}
      </div>

      <button style={{...styles.button, background: 'transparent', color: '#00ff00'}} onClick={handleLogout}>
        Logout
      </button>
    </div>
  );
}

export default App;
