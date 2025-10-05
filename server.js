// server.js
import express from "express";
import crypto from "crypto";
import "dotenv/config";
import admin from "firebase-admin";
import fs from "fs";
import path from "path";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- Initialize Firebase Admin SDK ---
const serviceAccountPath = path.resolve("firebase-service-account.json");

admin.initializeApp({
  credential: admin.credential.cert(
    JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"))
  ),
});

const db = admin.firestore();

// --- Helper: Decode base64url ---
function base64UrlDecode(str) {
  return Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

// --- Delete user data from Firestore ---
async function deleteUserData(userId) {
  try {
    const userRef = db.collection("users").doc(userId);
    const doc = await userRef.get();

    if (!doc.exists) {
      console.log(`No data found for user ${userId}`);
      return { deleted: false, message: "No user data found" };
    } else {
      await userRef.delete();
      console.log(`Deleted data for user ${userId}`);
      return { deleted: true, message: "User data deleted successfully" };
    }
  } catch (error) {
    console.error(`Error deleting user ${userId}:`, error);
    return { deleted: false, message: error.message };
  }
}

// --- Health check ---
app.get("/", (req, res) => {
  res.send("✅ Facebook Data Deletion Server is running!");
});

// --- Facebook Data Deletion Callback ---
app.post("/fb-deletion-callback", async (req, res) => {
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

    // Generate confirmation and status link
    const confirmationCode = `del_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const BASE_URL = process.env.BASE_URL || "https://data-deletion-callback.onrender.com";
    const statusUrl = `${BASE_URL}/deletion-status?code=${confirmationCode}`;

    // Respond immediately to Facebook (required)
    res.status(200).json({
      url: statusUrl,
      confirmation_code: confirmationCode,
    });

    // Perform deletion asynchronously (doesn’t block FB response)
    const result = await deleteUserData(userId);

    // Optional: Log deletion in Firestore for audit
    await db.collection("deletion_logs").doc(confirmationCode).set({
      userId,
      status: result.deleted ? "completed" : "not_found",
      message: result.message,
      timestamp: new Date().toISOString(),
    });

  } catch (err) {
    console.error("❌ Error handling deletion callback:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- Deletion Status Page ---
app.get("/deletion-status", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("<h3>Missing confirmation code.</h3>");

  try {
    const logRef = db.collection("deletion_logs").doc(code);
    const logDoc = await logRef.get();

    if (!logDoc.exists) {
      return res.send(`
        <h2>🕓 Data Deletion Status</h2>
        <p>Your request is being processed. Please check back later.</p>
        <p><b>Confirmation Code:</b> ${code}</p>
      `);
    }

    const { status, message, userId } = logDoc.data();
    res.send(`
      <h2>✅ Data Deletion Status</h2>
      <p><b>Status:</b> ${status}</p>

      <p><b>Message:</b> ${message}</p>
      <p><b>User ID:</b> ${userId}</p>
      <p><b>Confirmation Code:</b> ${code}</p>
    `);
  } catch (err) {
    console.error("❌ Error fetching deletion log:", err);
    res.status(500).send("<h3>Internal Server Error</h3>");
  }
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
