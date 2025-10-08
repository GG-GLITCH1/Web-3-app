import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from "react-router-dom";
import axios from "axios";

const API = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "/api",
});

// Auth token interceptor
API.interceptors.request.use((req) => {
  const token = localStorage.getItem("token");
  if (token) req.headers.Authorization = `Bearer ${token}`;
  return req;
});

function LoginPage({ setUser }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const res = await API.post("/login", new URLSearchParams(form), {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      localStorage.setItem("token", res.data.access_token);
      setUser(res.data.user);
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed");
    }
  };

  return (
    <div style={styles.container}>
      <h2>🔥 Login</h2>
      {error && <div style={styles.error}>{error}</div>}
      <form style={styles.form} onSubmit={handleLogin}>
        <input
          style={styles.input}
          placeholder="Username"
          name="username"
          value={form.username}
          onChange={(e) => setForm({ ...form, username: e.target.value })}
        />
        <input
          style={styles.input}
          type="password"
          placeholder="Password"
          name="password"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
        />
        <button style={styles.button}>Login</button>
      </form>
      <Link to="/signup" style={styles.link}>Create account</Link>
    </div>
  );
}

function SignupPage() {
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const handleSignup = async (e) => {
    e.preventDefault();
    try {
      await API.post("/signup", form);
      setDone(true);
    } catch (err) {
      setError(err.response?.data?.detail || "Signup failed");
    }
  };

  if (done)
    return (
      <div style={styles.container}>
        <h3>Account created successfully!</h3>
        <Link to="/" style={styles.link}>Go to login</Link>
      </div>
    );

  return (
    <div style={styles.container}>
      <h2>🔥 Sign Up</h2>
      {error && <div style={styles.error}>{error}</div>}
      <form style={styles.form} onSubmit={handleSignup}>
        <input style={styles.input} placeholder="Username" name="username" onChange={(e) => setForm({ ...form, username: e.target.value })} />
        <input style={styles.input} placeholder="Email" name="email" onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <input style={styles.input} type="password" placeholder="Password" name="password" onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <button style={styles.button}>Sign Up</button>
      </form>
    </div>
  );
}

function Dashboard({ user, logout }) {
  return (
    <div style={styles.container}>
      <h2>🔥 Welcome {user.username}</h2>
      <p>Role: {user.role}</p>
      <Link to="/admin" style={styles.link}>Go to Admin Panel</Link>
      <button style={styles.button} onClick={logout}>Logout</button>
    </div>
  );
}

function AdminPanel({ user, logout }) {
  if (user.role !== "admin") return <Navigate to="/" />;
  return (
    <div style={styles.container}>
      <h2>🛠 Admin Dashboard</h2>
      <p>Welcome, {user.username}! You have full privileges.</p>
      <button style={styles.button} onClick={logout}>Logout</button>
      <Link to="/" style={styles.link}>Back to Dashboard</Link>
    </div>
  );
}

function NotFound() {
  return (
    <div style={styles.container}>
      <h2>404 — Page Not Found</h2>
      <Link to="/" style={styles.link}>Go Home</Link>
    </div>
  );
}

function App() {
  const [user, setUser] = useState(null);

  const logout = () => {
    localStorage.removeItem("token");
    setUser(null);
  };

  return (
    <Router>
      <Routes>
        {!user ? (
          <>
            <Route path="/" element={<LoginPage setUser={setUser} />} />
            <Route path="/signup" element={<SignupPage />} />
            <Route path="*" element={<Navigate to="/" />} />
          </>
        ) : (
          <>
            <Route path="/" element={<Dashboard user={user} logout={logout} />} />
            <Route path="/admin" element={<AdminPanel user={user} logout={logout} />} />
            <Route path="*" element={<NotFound />} />
          </>
        )}
      </Routes>
    </Router>
  );
}

const styles = {
  container: { maxWidth: 600, margin: "50px auto", fontFamily: "monospace", color: "#00ff00", textAlign: "center" },
  form: { display: "flex", flexDirection: "column", gap: 10, marginTop: 20 },
  input: { padding: 10, border: "1px solid #00ff00", background: "transparent", color: "#00ff00" },
  button: { padding: 10, border: "1px solid #00ff00", background: "#00ff00", color: "#000", cursor: "pointer" },
  error: { color: "red", marginTop: 10 },
  link: { display: "block", marginTop: 15, color: "#00ff00", textDecoration: "underline" },
};

export default App;
