// src/pages/AdminDashboard.jsx
import React from "react";
import { useNavigate } from "react-router-dom";

const AdminDashboard = ({ user }) => {
  const navigate = useNavigate();

  const styles = {
    container: {
      maxWidth: "800px",
      margin: "auto",
      padding: "20px",
      fontFamily: "monospace",
    },
    button: {
      padding: "12px",
      border: "1px solid #00ff00",
      background: "#00ff00",
      color: "#000",
      borderRadius: "5px",
      fontWeight: "bold",
      cursor: "pointer",
      marginRight: "10px",
    },
  };

  return (
    <div style={styles.container}>
      <h2>🛠️ Admin Control Panel</h2>
      <p>Welcome, {user.username}! (Role: {user.role})</p>

      <div style={{ margin: "20px 0" }}>
        <button style={styles.button}>View All Users</button>
        <button style={styles.button}>Manage Wallet Verifications</button>
        <button style={styles.button}>View Server Logs</button>
      </div>

      <button
        style={{
          ...styles.button,
          background: "transparent",
          color: "#00ff00",
        }}
        onClick={() => navigate("/dashboard")}
      >
        Back to Dashboard
      </button>
    </div>
  );
};

export default AdminDashboard;
