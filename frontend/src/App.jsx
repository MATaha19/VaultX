import { useEffect, useState } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [page, setPage] = useState(
    localStorage.getItem("vaultx_token")
      ? "dashboard"
      : "login"
  );

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [token, setToken] = useState(
    localStorage.getItem("vaultx_token") || ""
  );

  const [currentUser, setCurrentUser] = useState(
    localStorage.getItem("vaultx_username") || ""
  );

  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const [selectedFile, setSelectedFile] = useState(null);
  const [recipient, setRecipient] = useState("");

  const [expiration, setExpiration] = useState("24");
  const [customHours, setCustomHours] = useState("");

  const [receivedFiles, setReceivedFiles] = useState([]);
  const [sentFiles, setSentFiles] = useState([]);

  const [loading, setLoading] = useState(false);

  const totalFiles =
    receivedFiles.length + sentFiles.length;

  useEffect(() => {
    const savedToken =
      localStorage.getItem("vaultx_token");

    const savedUsername =
      localStorage.getItem("vaultx_username");

    if (savedToken && savedUsername) {
      setToken(savedToken);
      setCurrentUser(savedUsername);
      setPage("dashboard");

      loadFiles(savedToken);
    }
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();

    setError("");
    setMessage("");
    setLoading(true);

    try {
      const formData = new URLSearchParams();

      formData.append(
        "username",
        username.trim()
      );

      formData.append(
        "password",
        password
      );

      const response = await fetch(
        `${API_URL}/auth/login`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/x-www-form-urlencoded",
          },
          body: formData,
        }
      );

      const data = await response.json();

      if (!response.ok) {
        let detail =
          "Invalid username or password";

        if (typeof data.detail === "string") {
          detail = data.detail;
        } else if (Array.isArray(data.detail)) {
          detail = data.detail
            .map(
              (item) =>
                item.msg || "Invalid input"
            )
            .join(", ");
        }

        throw new Error(detail);
      }

      if (!data.access_token) {
        throw new Error(
          "Login succeeded but no access token was returned."
        );
      }

      const accessToken =
        data.access_token;

      const loggedInUsername =
        data.username ||
        username.trim();

      localStorage.setItem(
        "vaultx_token",
        accessToken
      );

      localStorage.setItem(
        "vaultx_username",
        loggedInUsername
      );

      setToken(accessToken);
      setCurrentUser(loggedInUsername);

      setUsername("");
      setPassword("");

      setPage("dashboard");
      setMessage("Login successful.");

      await loadFiles(accessToken);
    } catch (err) {
      console.error(err);

      setError(
        err.message || "Login failed."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();

    setError("");
    setMessage("");
    setLoading(true);

    try {
      const response = await fetch(
        `${API_URL}/auth/register`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username: username.trim(),
            email: email.trim(),
            password,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        let detail =
          "Registration failed.";

        if (typeof data.detail === "string") {
          detail = data.detail;
        } else if (Array.isArray(data.detail)) {
          detail = data.detail
            .map(
              (item) =>
                item.msg || "Invalid input"
            )
            .join(", ");
        }

        throw new Error(detail);
      }

      setUsername("");
      setEmail("");
      setPassword("");

      setMessage(
        "Account created successfully. Please login."
      );

      setPage("login");
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Registration failed."
      );
    } finally {
      setLoading(false);
    }
  };

  const loadFiles = async (authToken) => {
    if (!authToken) {
      return;
    }

    try {
      const receivedResponse =
        await fetch(
          `${API_URL}/files/my-files`,
          {
            method: "GET",
            headers: {
              Authorization:
                `Bearer ${authToken}`,
            },
          }
        );

      if (
        receivedResponse.status === 401
      ) {
        handleSessionExpired();
        return;
      }

      if (receivedResponse.ok) {
        const data =
          await receivedResponse.json();

        setReceivedFiles(
          Array.isArray(data.files)
            ? data.files
            : []
        );
      }

      const sentResponse =
        await fetch(
          `${API_URL}/files/sent`,
          {
            method: "GET",
            headers: {
              Authorization:
                `Bearer ${authToken}`,
            },
          }
        );

      if (
        sentResponse.status === 401
      ) {
        handleSessionExpired();
        return;
      }

      if (sentResponse.ok) {
        const data =
          await sentResponse.json();

        setSentFiles(
          Array.isArray(data.files)
            ? data.files
            : []
        );
      }
    } catch (err) {
      console.error(
        "File list error:",
        err
      );
    }
  };

  const handleSessionExpired = () => {
    localStorage.removeItem(
      "vaultx_token"
    );

    localStorage.removeItem(
      "vaultx_username"
    );

    setToken("");
    setCurrentUser("");

    setReceivedFiles([]);
    setSentFiles([]);

    setPage("login");

    setError(
      "Your session has expired. Please login again."
    );
  };

  const getExpirationHours = () => {
    if (expiration === "custom") {
      return Number(customHours);
    }

    return Number(expiration);
  };

  const handleUpload = async (e) => {
    e.preventDefault();

    setError("");
    setMessage("");

    if (!token) {
      handleSessionExpired();
      return;
    }

    if (!selectedFile) {
      setError(
        "Please select a file."
      );
      return;
    }

    if (!recipient.trim()) {
      setError(
        "Please enter recipient username."
      );
      return;
    }

    const hours =
      getExpirationHours();

    if (
      !Number.isFinite(hours) ||
      hours <= 0
    ) {
      setError(
        "Please enter a valid expiration period."
      );
      return;
    }

    if (hours > 168) {
      setError(
        "Maximum expiration is 168 hours (7 days)."
      );
      return;
    }

    setLoading(true);

    try {
      const formData =
        new FormData();

      formData.append(
        "file",
        selectedFile
      );

      formData.append(
        "recipient_username",
        recipient.trim()
      );

      formData.append(
        "expiration_hours",
        String(hours)
      );

      const response =
        await fetch(
          `${API_URL}/files/upload`,
          {
            method: "POST",
            headers: {
              Authorization:
                `Bearer ${token}`,
            },
            body: formData,
          }
        );

      if (response.status === 401) {
        handleSessionExpired();
        return;
      }

      const data =
        await response.json();

      if (!response.ok) {
        let detail =
          "File transfer failed.";

        if (
          typeof data.detail ===
          "string"
        ) {
          detail = data.detail;
        }

        throw new Error(detail);
      }

      setMessage(
        "File encrypted and sent successfully."
      );

      setSelectedFile(null);
      setRecipient("");
      setExpiration("24");
      setCustomHours("");

      const fileInput =
        document.getElementById(
          "file-upload"
        );

      if (fileInput) {
        fileInput.value = "";
      }

      await loadFiles(token);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "File transfer failed."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (
    fileId,
    filename
  ) => {
    setError("");
    setMessage("");

    if (!token) {
      handleSessionExpired();
      return;
    }

    setLoading(true);

    try {
      const response =
        await fetch(
          `${API_URL}/files/${fileId}/download`,
          {
            method: "GET",
            headers: {
              Authorization:
                `Bearer ${token}`,
            },
          }
        );

      if (response.status === 401) {
        handleSessionExpired();
        return;
      }

      if (!response.ok) {
        let detail =
          "Download failed.";

        try {
          const data =
            await response.json();

          if (
            typeof data.detail ===
            "string"
          ) {
            detail = data.detail;
          }
        } catch {}

        throw new Error(detail);
      }

      const blob =
        await response.blob();

      const url =
        window.URL.createObjectURL(
          blob
        );

      const link =
        document.createElement("a");

      link.href = url;

      link.download =
        filename ||
        "downloaded_file";

      document.body.appendChild(
        link
      );

      link.click();

      link.remove();

      window.URL.revokeObjectURL(
        url
      );

      setMessage(
        "File decrypted and downloaded successfully."
      );
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Download failed."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (
    fileId
  ) => {
    setError("");
    setMessage("");

    if (!token) {
      handleSessionExpired();
      return;
    }

    const confirmed =
      window.confirm(
        "Are you sure you want to revoke this file? The recipient will no longer be able to download it."
      );

    if (!confirmed) {
      return;
    }

    setLoading(true);

    try {
      const response =
        await fetch(
          `${API_URL}/files/${fileId}`,
          {
            method: "DELETE",
            headers: {
              Authorization:
                `Bearer ${token}`,
            },
          }
        );

      if (response.status === 401) {
        handleSessionExpired();
        return;
      }

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail ===
          "string"
            ? data.detail
            : "Failed to revoke file."
        );
      }

      setMessage(
        "File transfer revoked successfully."
      );

      await loadFiles(token);
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Failed to revoke file."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem(
      "vaultx_token"
    );

    localStorage.removeItem(
      "vaultx_username"
    );

    setToken("");
    setCurrentUser("");

    setReceivedFiles([]);
    setSentFiles([]);

    setUsername("");
    setEmail("");
    setPassword("");

    setSelectedFile(null);
    setRecipient("");

    setExpiration("24");
    setCustomHours("");

    setMessage("");
    setError("");

    setPage("login");
  };

  const formatFileSize = (
    bytes
  ) => {
    if (!bytes) {
      return "0 Bytes";
    }

    const units = [
      "Bytes",
      "KB",
      "MB",
      "GB",
    ];

    const index = Math.min(
      Math.floor(
        Math.log(bytes) /
          Math.log(1024)
      ),
      units.length - 1
    );

    return `${(
      bytes /
      Math.pow(1024, index)
    ).toFixed(2)} ${
      units[index]
    }`;
  };

  const formatDate = (
    date
  ) => {
    if (!date) {
      return "Unknown";
    }

    const parsedDate =
      new Date(date);

    if (
      Number.isNaN(
        parsedDate.getTime()
      )
    ) {
      return "Unknown";
    }

    return parsedDate.toLocaleString(
      "en-IN"
    );
  };

  if (page === "login") {
    return (
      <div className="app">
        <div className="login-card">

          <div className="logo">
            🔐
          </div>

          <h1>VaultX</h1>

          <p className="subtitle">
            Secure End-to-End File Transfer
          </p>

          {message && (
            <div className="success">
              {message}
            </div>
          )}

          {error && (
            <div className="error">
              {error}
            </div>
          )}

          <form
            onSubmit={handleLogin}
          >
            <label>
              Username
            </label>

            <input
              type="text"
              placeholder="Enter username"
              value={username}
              onChange={(e) =>
                setUsername(
                  e.target.value
                )
              }
              required
              autoComplete="username"
            />

            <label>
              Password
            </label>

            <input
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) =>
                setPassword(
                  e.target.value
                )
              }
              required
              autoComplete="current-password"
            />

            <button
              type="submit"
              disabled={loading}
            >
              {loading
                ? "Signing in..."
                : "Login"}
            </button>
          </form>

          <button
            type="button"
            className="secondary-button register-switch"
            onClick={() => {
              setError("");
              setMessage("");
              setUsername("");
              setEmail("");
              setPassword("");
              setPage("register");
            }}
          >
            Create New Account
          </button>

          <div className="security-note">
            🔒 AES-256-GCM • RSA-2048 • SHA-256
          </div>

        </div>
      </div>
    );
  }

  if (page === "register") {
    return (
      <div className="app">
        <div className="login-card">

          <div className="logo">
            🔐
          </div>

          <h1>Create Account</h1>

          <p className="subtitle">
            Create your secure VaultX account
          </p>

          {message && (
            <div className="success">
              {message}
            </div>
          )}

          {error && (
            <div className="error">
              {error}
            </div>
          )}

          <form
            onSubmit={handleRegister}
          >
            <label>
              Username
            </label>

            <input
              type="text"
              placeholder="Choose a username"
              value={username}
              onChange={(e) =>
                setUsername(
                  e.target.value
                )
              }
              required
            />

            <label>
              Email
            </label>

            <input
              type="email"
              placeholder="Enter your email"
              value={email}
              onChange={(e) =>
                setEmail(
                  e.target.value
                )
              }
              required
            />

            <label>
              Password
            </label>

            <input
              type="password"
              placeholder="Minimum 6 characters"
              value={password}
              onChange={(e) =>
                setPassword(
                  e.target.value
                )
              }
              required
              minLength={6}
            />

            <button
              type="submit"
              disabled={loading}
            >
              {loading
                ? "Creating account..."
                : "Create Account"}
            </button>
          </form>

          <button
            type="button"
            className="secondary-button register-switch"
            onClick={() => {
              setError("");
              setMessage("");
              setUsername("");
              setEmail("");
              setPassword("");
              setPage("login");
            }}
          >
            Back to Login
          </button>

          <div className="security-note">
            🔑 RSA-2048 key pair generated automatically
          </div>

        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">

      <header className="topbar">

        <div>
          <h1>
            VaultX Dashboard
          </h1>

          <span>
            Secure End-to-End File Transfer System
          </span>
        </div>

        <div className="user-area">

          <div className="logged-user">

            <strong>
              {currentUser}
            </strong>

            <span>
              Authenticated User
            </span>

          </div>

          <button
            className="logout"
            onClick={handleLogout}
          >
            Logout
          </button>

        </div>

      </header>

      <main className="content">

        {message && (
          <div className="success">
            {message}
          </div>
        )}

        {error && (
          <div className="error">
            {error}
          </div>
        )}

        {/* DASHBOARD OVERVIEW */}

        <section className="dashboard-overview">

          <div className="overview-heading">
            <h2>
              Dashboard Overview
            </h2>

            <p>
              Monitor your secure file transfers.
            </p>
          </div>

          <div className="stats-grid">

            <div className="stat-card">

              <div className="stat-icon">
                📤
              </div>

              <div>
                <strong>
                  {sentFiles.length}
                </strong>

                <span>
                  Files Sent
                </span>
              </div>

            </div>

            <div className="stat-card">

              <div className="stat-icon">
                📥
              </div>

              <div>
                <strong>
                  {receivedFiles.length}
                </strong>

                <span>
                  Files Received
                </span>
              </div>

            </div>

            <div className="stat-card">

              <div className="stat-icon">
                🔐
              </div>

              <div>
                <strong>
                  {totalFiles}
                </strong>

                <span>
                  Total Transfers
                </span>
              </div>

            </div>

          </div>

        </section>

        {/* SEND FILE */}

        <section className="card">

          <div className="section-header">

            <div>
              <h2>
                📤 Send Secure File
              </h2>

              <p>
                Your file is encrypted before
                storage using AES-256-GCM.
              </p>
            </div>

          </div>

          <form
            onSubmit={handleUpload}
          >

            <label>
              Select File
            </label>

            <input
              id="file-upload"
              type="file"
              onChange={(e) =>
                setSelectedFile(
                  e.target.files?.[0] ||
                  null
                )
              }
              required
            />

            {selectedFile && (
              <div className="selected-file">

                Selected:

                <strong>
                  {selectedFile.name}
                </strong>

                <span>
                  {formatFileSize(
                    selectedFile.size
                  )}
                </span>

              </div>
            )}

            <label>
              Recipient Username
            </label>

            <input
              type="text"
              placeholder="Enter recipient username"
              value={recipient}
              onChange={(e) =>
                setRecipient(
                  e.target.value
                )
              }
              required
            />

            <label>
              File Expiration
            </label>

            <select
              value={expiration}
              onChange={(e) =>
                setExpiration(
                  e.target.value
                )
              }
            >
              <option value="1">
                1 Hour
              </option>

              <option value="6">
                6 Hours
              </option>

              <option value="12">
                12 Hours
              </option>

              <option value="24">
                24 Hours
              </option>

              <option value="48">
                48 Hours
              </option>

              <option value="72">
                72 Hours
              </option>

              <option value="168">
                7 Days
              </option>

              <option value="custom">
                Custom
              </option>
            </select>

            {expiration === "custom" && (
              <input
                type="number"
                min="1"
                max="168"
                placeholder="Hours (1–168)"
                value={customHours}
                onChange={(e) =>
                  setCustomHours(
                    e.target.value
                  )
                }
                required
              />
            )}

            <button
              type="submit"
              disabled={loading}
            >
              {loading
                ? "Encrypting & Sending..."
                : "🔒 Encrypt & Send File"}
            </button>

          </form>

        </section>

        {/* RECEIVED FILES */}

        <section className="card">

          <div className="section-header">

            <div>
              <h2>
                📥 Received Files
              </h2>

              <p>
                Files securely sent to you.
              </p>
            </div>

            <button
              className="small-button secondary-button"
              onClick={() =>
                loadFiles(token)
              }
              disabled={loading}
            >
              ↻ Refresh
            </button>

          </div>

          {receivedFiles.length === 0 ? (

            <div className="empty">

              <div className="empty-icon">
                📭
              </div>

              <strong>
                No received files
              </strong>

              <span>
                Files sent to your account
                will appear here.
              </span>

            </div>

          ) : (

            <div className="file-list">

              {receivedFiles.map(
                (file) => (

                  <div
                    className="file-item"
                    key={file.file_id}
                  >

                    <div className="file-info">

                      <strong>
                        📄 {file.filename}
                      </strong>

                      <span>
                        From:{" "}
                        <b>
                          {file.sender}
                        </b>
                      </span>

                      <span>
                        Size:{" "}
                        {formatFileSize(
                          file.file_size
                        )}
                      </span>

                      <span>
                        Uploaded:{" "}
                        {formatDate(
                          file.uploaded_at
                        )}
                      </span>

                      <span>
                        Expires:{" "}
                        {formatDate(
                          file.expires_at
                        )}
                      </span>

                    </div>

                    <button
                      onClick={() =>
                        handleDownload(
                          file.file_id,
                          file.filename
                        )
                      }
                      disabled={loading}
                    >
                      🔓 Download
                    </button>

                  </div>

                )
              )}

            </div>

          )}

        </section>

        {/* SENT FILES */}

        <section className="card">

          <div className="section-header">

            <div>
              <h2>
                📤 Sent Files
              </h2>

              <p>
                Files you have securely transferred.
              </p>
            </div>

            <button
              className="small-button secondary-button"
              onClick={() =>
                loadFiles(token)
              }
              disabled={loading}
            >
              ↻ Refresh
            </button>

          </div>

          {sentFiles.length === 0 ? (

            <div className="empty">

              <div className="empty-icon">
                📭
              </div>

              <strong>
                No sent files
              </strong>

              <span>
                Files you send will appear here.
              </span>

            </div>

          ) : (

            <div className="file-list">

              {sentFiles.map(
                (file) => (

                  <div
                    className="file-item"
                    key={file.file_id}
                  >

                    <div className="file-info">

                      <strong>
                        📄 {file.filename}
                      </strong>

                      <span>
                        To:{" "}
                        <b>
                          {file.recipient}
                        </b>
                      </span>

                      <span>
                        Size:{" "}
                        {formatFileSize(
                          file.file_size
                        )}
                      </span>

                      <span>
                        Uploaded:{" "}
                        {formatDate(
                          file.uploaded_at
                        )}
                      </span>

                      <span>
                        Expires:{" "}
                        {formatDate(
                          file.expires_at
                        )}
                      </span>

                    </div>

                    <button
                      className="danger"
                      onClick={() =>
                        handleRevoke(
                          file.file_id
                        )
                      }
                      disabled={loading}
                    >
                      🗑 Revoke
                    </button>

                  </div>

                )
              )}

            </div>

          )}

        </section>

        {/* SECURITY */}

        <section className="security-card">

          <h2>
            🛡 VaultX Security
          </h2>

          <p className="security-description">
            VaultX uses multiple cryptographic
            layers to protect transferred files.
          </p>

          <div className="security-grid">

            <div>
              <strong>
                AES-256-GCM
              </strong>

              <span>
                File Encryption
              </span>
            </div>

            <div>
              <strong>
                RSA-2048
              </strong>

              <span>
                AES Key Protection
              </span>
            </div>

            <div>
              <strong>
                SHA-256
              </strong>

              <span>
                Integrity Verification
              </span>
            </div>

            <div>
              <strong>
                JWT
              </strong>

              <span>
                Authentication
              </span>
            </div>

          </div>

        </section>

      </main>

    </div>
  );
}

export default App;