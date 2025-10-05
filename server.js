import express from "express";
import crypto from "crypto";
import "dotenv/config";

const app = express();
app.use(express.urlencoded({ extended: true }));

function base64UrlDecode(str) {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), "base64").toString("utf8");
}
app.get("/", (req, res) => {
  res.send("Server is alive 🚀");
});
app.post("/fb-deletion-callback", (req, res) => {
  const signedRequest = req.body.signed_request;
  if (!signedRequest) return res.json({ error: "No signed request" });

  const [encodedSig, payload] = signedRequest.split(".");
  const data = JSON.parse(base64UrlDecode(payload));

  // Verify signature with your App Secret
  const expectedSig = crypto
    .createHmac("sha256", process.env.APP_SECRET) // put APP_SECRET in .env
    .update(payload)
    .digest();
  const sig = Buffer.from(base64UrlDecode(encodedSig), "binary");

  if (!crypto.timingSafeEqual(sig, expectedSig)) {
    return res.json({ error: "Invalid signature" });
  }

  const userId = data.user_id;

  // TODO: delete user data in DB here

  const confirmationCode = `del_${Date.now()}`;
  const statusUrl = `https://yourwebsite.com/deletion-status?code=${confirmationCode}`;

  res.json({
    url: statusUrl,
    confirmation_code: confirmationCode
  });
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
