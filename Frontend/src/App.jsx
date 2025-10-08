import React, { useState, useEffect } from "react";
import axios from "axios";
import { Routes, Route, Navigate, useNavigate } from "react-router-dom";
import AdminDashboard from "./pages/AdminDashboard";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.MODE === "development"
    ? "/api"
    : "https://web-3-app-3.onrender.com");

const API = axios.create({ baseURL: API_BASE_URL });

API.interceptors.request.use((req) => {
  const token = localStorage.getItem("token");
  if (token) req.headers.Authorization = `Bearer ${token}`;
  return req;
});

API.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("token");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

function App() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [prices, setPrices] = useState({ eth: null });
  const [wallet, setWallet] = useState({ address: null, eth_balance: null });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
  });

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) fetchUserData();
  }, []);

  const fetchUserData = async () => {
    try {
      const [userRes, ethRes] = await Promise.all([
        API.get("/me"),
        API.get("/prices/ethereum"),
      ]);
      setUser(userRes.data);
      setPrices({ eth: ethRes.data.price_usd });
    } catch (err) {
      console.error("Fetch user failed:", err);
    }
  };

  const handleInputChange = (e) =>
    setFormData({ ...formData, [e.target.name]: e.target.value });

  const handleSignup = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await API.post("/signup", formData);
      alert("Signup successful! Please login.");
      setFormData({ username: "", email: "", password: "" });
      navigate("/login");
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
      const form = new URLSearchParams();
      form.append("username", formData.username);
      form.append("password", formData.password);

      const res = await API.post("/login", form, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });

      localStorage.setItem("token", res.data.access_token);
      setUser(res.data.user);
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    setUser(null);
    navigate("/login");
  };

  const connectWallet = async () => {
    if (!window.ethereum) return alert("Please install MetaMask!");
    try {
      setLoading(true);
      const accounts = await window.ethereum.request({
        method: "eth_requestAccounts",
      });
      const address = accounts[0];
      setWallet({ address });

      await API.post("/me/wallet", { address });
      const balanceRes = await API.get(`/wallet/balance/${address}`);
      setWallet((prev) => ({ ...prev, ...balanceRes.data }));
    } catch (err) {
      setError("Failed to connect wallet");
    } finally {
      setLoading(false);
    }
  };

  const styles = {
    container: { maxWidth: "800px", margin: "auto", padding: "20px" },
    form: { display: "flex", flexDirection: "column", gap: "10px" },
    input: {
      padding: "10px",
      border: "1px solid #00ff00",
      background: "transparent",
      color: "#00ff00",
      borderRadius: "5px",
    },
    button: {
      padding: "12px",
      border: "1px solid #00ff00",
      background: "#00ff00",
      color: "#000",
      borderRadius: "5px",
      fontWeight: "bold",
      cursor: "pointer",
    },
    link: {
      color: "#00ff00",
      cursor: "pointer",
      textDecoration: "underline",
    },
  };

  const isAdmin = user?.role === "admin";

  return (
    <Routes>
      {/* Login Page */}
      <Route
        path="/login"
        element={
          <div style={styles.container}>
            <h2>🔥 G.G Login</h2>
            {error && <p style={{ color: "red" }}>{error}</p>}
            <form style={styles.form} onSubmit={handleLogin}>
              <input
                name="username"
                placeholder="Username"
                style={styles.input}
                value={formData.username}
                onChange={handleInputChange}
              />
              <input
                name="password"
                type="password"
                placeholder="Password"
                style={styles.input}
                value={formData.password}
                onChange={handleInputChange}
              />
              <button style={styles.button} disabled={loading}>
                {loading ? "Logging in..." : "Login"}
              </button>
            </form>
            <p style={styles.link} onClick={() => navigate("/signup")}>
              Don't have an account? Sign up
            </p>
          </div>
        }
      />

      {/* Signup Page */}
      <Route
        path="/signup"
        element={
          <div style={styles.container}>
            <h2>🔥 G.G Sign Up</h2>
            {error && <p style={{ color: "red" }}>{error}</p>}
            <form style={styles.form} onSubmit={handleSignup}>
              <input
                name="username"
                placeholder="Username"
                style={styles.input}
                value={formData.username}
                onChange={handleInputChange}
              />
              <input
                name="email"
                type="email"
                placeholder="Email"
                style={styles.input}
                value={formData.email}
                onChange={handleInputChange}
              />
              <input
                name="password"
                type="password"
                placeholder="Password"
                style={styles.input}
                value={formData.password}
                onChange={handleInputChange}
              />
              <button style={styles.button} disabled={loading}>
                {loading ? "Creating Account..." : "Sign Up"}
              </button>
            </form>
            <p style={styles.link} onClick={() => navigate("/login")}>
              Already have an account? Login
            </p>
          </div>
        }
      />

      {/* Dashboard */}
      <Route
        path="/dashboard"
        element={
          !user ? (
            <Navigate to="/login" />
          ) : (
            <div style={styles.container}>
              <h2>🔥 G.G Dashboard</h2>
              <p>Welcome, {user.username}</p>
              <p>Role: {user.role}</p>
              <p>ETH: ${prices.eth}</p>
              <button style={styles.button} onClick={connectWallet}>
                {wallet.address
                  ? `Wallet: ${wallet.address.slice(0, 8)}...`
                  : "Connect MetaMask"}
              </button>
              {isAdmin && (
                <button
                  style={styles.button}
                  onClick={() => navigate("/admin")}
                >
                  Go to Admin Panel
                </button>
              )}
              <button
                style={{
                  ...styles.button,
                  background: "transparent",
                  color: "#00ff00",
                }}
                onClick={handleLogout}
              >
                Logout
              </button>
            </div>
          )
        }
      />

      {/* Admin Page (Protected) */}
      <Route
        path="/admin"
        element={
          isAdmin ? <AdminDashboard user={user} /> : <Navigate to="/login" />
        }
      />

      {/* Redirect root */}
      <Route path="*" element={<Navigate to="/login" />} />
    </Routes>
  );
}

export default App;
