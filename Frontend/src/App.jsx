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

  // Check if user is already logged in.
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
      
import React, { useState, useEffect } from "react";
import axios from "axios";

// API configuration with better error handling
const API = axios.create({
  baseURL: "https://web-3-app-3.onrender.com",
  timeout: 15000,
});

// Request interceptor
API.interceptors.request.use((req) => {
  const token = localStorage.getItem("token");
  if (token) {
    req.headers.Authorization = `Bearer ${token}`;
  }
  return req;
});

// Response interceptor
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
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Check if user is already logged in
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      checkAuth();
    }
  }, []);

  const checkAuth = async () => {
    try {
      const response = await API.get("/me");
      setUser(response.data);
      setPage("dashboard");
    } catch (err) {
      localStorage.removeItem("token");
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
      console.log("Attempting signup...", formData);
      const response = await API.post("/signup", {
        username: formData.username,
        email: formData.email,
        password: formData.password
      });
      
      console.log("Signup successful:", response.data);
      alert("Signup successful! Please login.");
      setFormData({ username: "", email: "", password: "" });
      setPage("login");
    } catch (err) {
      console.error("SIGNUP ERROR:", err);
      const errorMessage = err.response?.data?.detail || err.message || "Signup failed. Please try again.";
      setError(errorMessage);
      alert("Signup failed: " + errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    
    try {
      console.log("Attempting login...", formData.username);
      
      // Use URLSearchParams for form data
      const formDataEncoded = new URLSearchParams();
      formDataEncoded.append('username', formData.username);
      formDataEncoded.append('password', formData.password);
      
      const response = await API.post("/login", formDataEncoded, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
      
      console.log("Login successful:", response.data);
      localStorage.setItem("token", response.data.access_token);
      setUser(response.data.user);
      setPage("dashboard");
    } catch (err) {
      console.error("LOGIN ERROR:", err);
      const errorMessage = err.response?.data?.detail || err.message || "Login failed. Please try again.";
      setError(errorMessage);
      alert("Login failed: " + errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    setUser(null);
    setPage("login");
  };

  // Simple styling
  const styles = {
    container: {
      maxWidth: '400px',
      margin: '50px auto',
      padding: '20px',
      fontFamily: 'Arial, sans-serif'
    },
    form: {
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
      marginBottom: '20px'
    },
    input: {
      padding: '10px',
      border: '1px solid #ccc',
      borderRadius: '5px',
      fontSize: '16px'
    },
    button: {
      padding: '12px',
      border: 'none',
      background: '#007bff',
      color: 'white',
      borderRadius: '5px',
      cursor: 'pointer',
      fontSize: '16px'
    },
    error: {
      color: 'red',
      margin: '10px 0'
    },
    link: {
      color: '#007bff',
      cursor: 'pointer',
      textAlign: 'center'
    }
  };

  // Render methods
  if (page === "signup") {
    return (
      <div style={styles.container}>
        <h2>Sign Up</h2>
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
        
        <p style={styles.link} onClick={() => setPage("login")}>
          Already have an account? Login
        </p>
      </div>
    );
  }

  if (page === "login") {
    return (
      <div style={styles.container}>
        <h2>Login</h2>
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
        
        <p style={styles.link} onClick={() => setPage("signup")}>
          Don't have an account? Sign up
        </p>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <h2>Dashboard</h2>
      
      {user && (
        <div>
          <h3>Welcome, {user.username}!</h3>
          <p>Email: {user.email}</p>
        </div>
      )}

      <button style={styles.button} onClick={handleLogout}>
        Logout
      </button>
    </div>
  );
}

export default App;
