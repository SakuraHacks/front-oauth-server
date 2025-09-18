// server.js
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

// In-memory store (for demo only — use a DB in production)
const authCodes = new Map();
const tokens = new Map();

// Fake client & user (replace with your logic)
const CLIENT_ID = "c46ef6b0f2c305936119";
const CLIENT_SECRET = "ef956a9354265df8ecbf1e5d881ec8ad802b490f";
const REDIRECT_URI = "https://app.frontapp.com/oauth/callback";

// ---------------- AUTHORIZATION ENDPOINT ----------------
app.get("/authorize", (req, res) => {
  const { client_id, redirect_uri, state } = req.query;

  // Validate client
  if (client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
    return res.status(400).send("Invalid client or redirect URI");
  }

  // Normally you'd show a login/consent screen here
  // For demo, auto-approve
  const code = crypto.randomBytes(16).toString("hex");
  authCodes.set(code, { client_id, user_id: "123" });

  // Redirect back to Front with code + state
  res.redirect(`${redirect_uri}?code=${code}&state=${state}`);
});

// ---------------- TOKEN ENDPOINT ----------------
app.post("/token", (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;

  // Validate client
  if (client_id !== CLIENT_ID || client_secret !== CLIENT_SECRET) {
    return res.status(401).json({ error: "invalid_client" });
  }

  if (grant_type === "authorization_code") {
    const data = authCodes.get(code);
    if (!data || redirect_uri !== REDIRECT_URI) {
      return res.status(400).json({ error: "invalid_grant" });
    }

    // Exchange code for tokens
    const accessToken = crypto.randomBytes(24).toString("hex");
    const refreshToken = crypto.randomBytes(24).toString("hex");

    tokens.set(accessToken, { user_id: data.user_id });

    return res.json({
      access_token: accessToken,
      token_type: "bearer",
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: "read write"
    });
  }

  if (grant_type === "refresh_token") {
    // Issue new access token
    const accessToken = crypto.randomBytes(24).toString("hex");
    return res.json({
      access_token: accessToken,
      token_type: "bearer",
      expires_in: 3600
    });
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

app.listen(3000, () => {
  console.log("OAuth server running at http://localhost:3000");
});
