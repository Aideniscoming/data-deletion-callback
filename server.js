import express from "express";
import crypto from "crypto";
import "dotenv/config";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- Helper: Decode base64url ---
function base64UrlDecode(str) {
  return Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

// --- Health check ---
app.get("/", (req, res) => {
  res.send("✅ Facebook Data Deletion Server is running!");
});

// --- Facebook Data Deletion Callback ---
app.post("/fb-deletion-callback", (req, res) => {
  try {
    const signedRequest = req.body.signed_request;
    if (!signedRequest) return res.status(400).json({ error: "No signed_request" });

    const [encodedSig, payload] = signedRequest.split(".");
    if (!encodedSig || !payload) return res.status(400).json({ error: "Malformed signed_request" });

    // Decode payload
    const data = JSON.parse(base64UrlDecode(payload));

    // Verify signature
    const expectedSig = crypto
      .createHmac("sha256", process.env.APP_SECRET)
      .update(payload)
      .digest();

    const sig = Buffer.from(encodedSig.replace(/-/g, "+").replace(/_/g, "/"), "base64");

    if (!crypto.timingSafeEqual(sig, expectedSig)) {
      return res.status(403).json({ error: "Invalid signature" });
    }

    const userId = data.user_id;
    if (!userId) return res.status(400).json({ error: "Missing user_id in payload" });

    // Generate confirmation code & status URL
    const confirmationCode = `del_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const BASE_URL = process.env.BASE_URL || "https://your-app-url.com";
    const statusUrl = `${BASE_URL}/deletion-status?code=${confirmationCode}`;

    // Respond to Facebook
    res.status(200).json({
      url: statusUrl,
      confirmation_code: confirmationCode,
    });

    // Optional: log to console
    console.log(`Deletion requested for user: ${userId}, code: ${confirmationCode}`);

  } catch (err) {
    console.error("❌ Error handling deletion callback:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- Deletion Status Page ---
app.get("/deletion-status", (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("<h3>Missing confirmation code.</h3>");

  res.send(`
    <h2>✅ Data Deletion Status</h2>
    <p>Your deletion request has been received.</p>
    <p><b>Confirmation Code:</b> ${code}</p>
  `);
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
