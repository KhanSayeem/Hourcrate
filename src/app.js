const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const express = require("express");
const https = require("https");
const path = require("path");
const { authMiddleware, optionalAuthMiddleware } = require("./auth");
const fastspring = require("./fastspring");

const DEFAULT_FASTSPRING_STORE_URL = "https://hourcrate.test.onfastspring.com";
const DEFAULT_FASTSPRING_PRODUCT_PATH = "Hourcrate";

const SESSION_TTL_HOURS = 24 * 7;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = new Set(["accounts.google.com", "https://accounts.google.com"]);

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

function isProductionEnv() {
  return process.env.NODE_ENV === "production";
}

function getSessionCookieOptions(expiresAt) {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: isProductionEnv(),
    expires: expiresAt,
  };
}

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  return header.split(";").reduce((acc, pair) => {
    const [k, v] = pair.split("=").map((s) => s.trim());
    if (k && v) acc[k] = decodeURIComponent(v);
    return acc;
  }, {});
}

function toBase64Url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlToBuffer(value) {
  if (typeof value !== "string") return Buffer.alloc(0);
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, "base64");
}

function decodeBase64UrlJson(value) {
  const buffer = base64UrlToBuffer(value);
  return JSON.parse(buffer.toString("utf8"));
}

function createSignedState(state, mode, secret) {
  const issuedAt = Date.now().toString();
  const payload = `${state}.${issuedAt}.${mode}`;
  const signature = toBase64Url(crypto.createHmac("sha256", secret).update(payload).digest());
  return `${payload}.${signature}`;
}

function verifySignedState(value, secret) {
  if (typeof value !== "string") return null;
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const [state, issuedAt, mode, signature] = parts;
  if (!state || !issuedAt || !signature) return null;
  const payload = `${state}.${issuedAt}.${mode}`;
  const expected = toBase64Url(crypto.createHmac("sha256", secret).update(payload).digest());
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }
  const issuedAtMs = Number(issuedAt);
  if (!Number.isFinite(issuedAtMs)) return null;
  if (Date.now() - issuedAtMs > OAUTH_STATE_TTL_MS) return null;
  return { state, mode };
}

function getDatabaseInfo() {
  try {
    const url = new URL(process.env.DATABASE_URL);
    return {
      host: url.host,
      database: url.pathname ? url.pathname.replace(/^\//, "") : "",
    };
  } catch {
    return null;
  }
}

function createApp(pool, config = {}) {
  const app = express();
  app.use(
    express.json({
      verify: (req, res, buf) => {
        req.rawBody = buf.toString();
      },
    })
  );
  app.use(express.urlencoded({ extended: false }));
  app.use(express.static(path.join(__dirname, "public")));

  const userTimeZone = config.userTimeZone || process.env.USER_TIMEZONE || "UTC";
  const googleOverrides = config.googleOAuth || {};

  app.get("/", optionalAuthMiddleware(pool), (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res
      .status(200)
      .send(renderLandingPage({ isAuthenticated: Boolean(req.userId) }));
  });

  app.get("/whoami", optionalAuthMiddleware(pool), async (req, res) => {
    if (!req.userId) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const userResult = await pool.query(
      "SELECT email, is_paid FROM users WHERE id = $1",
      [req.userId]
    );
    if (userResult.rowCount === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const dbInfo = getDatabaseInfo();
    return res.json({
      user: {
        id: req.userId,
        email: userResult.rows[0].email,
        is_paid: userResult.rows[0].is_paid === true,
      },
      environment: {
        database: dbInfo?.database || null,
        db_host: dbInfo?.host || null,
      },
    });
  });

  app.get("/signup", optionalAuthMiddleware(pool), async (req, res) => {
    if (req.userId) {
      return res.redirect("/dashboard");
    }
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(renderSignupPage());
  });

  app.post("/signup", optionalAuthMiddleware(pool), async (req, res) => {
    if (req.userId) {
      return res.redirect("/dashboard");
    }

    const { email, password } = req.body || {};
    const normalizedEmail = normalizeEmail(email);
    const prefersHtml = requestExpectsHtml(req) && !requestExpectsJson(req);

    const errors = [];
    if (!normalizedEmail) {
      errors.push("EMAIL REQUIRED");
    }
    if (typeof password !== "string" || password.length < 8) {
      errors.push("PASSWORD TOO SHORT (MIN 8 CHARS)");
    }
    if (errors.length > 0) {
      if (prefersHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res
          .status(400)
          .send(renderSignupPage(errors[0], { email: normalizedEmail }));
      }
      return res.status(400).json({ errors });
    }

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );
    if (existingUser.rowCount > 0) {
      const message =
        'ACCOUNT EXISTS. <a href="/login">LOG IN</a>';
      if (prefersHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(409).send(renderSignupPage(message, { email: normalizedEmail }));
      }
      return res
        .status(409)
        .json({ error: "Account already exists", login: "/login" });
    }

    const hash = await bcrypt.hash(password, 10);
    const userResult = await pool.query(
      "INSERT INTO users (email, password_hash, is_paid) VALUES ($1, $2, false) RETURNING id, email",
      [normalizedEmail, hash]
    );

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + SESSION_TTL_HOURS * 3600 * 1000);
    await pool.query(
      "INSERT INTO sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)",
      [userResult.rows[0].id, token, expiresAt]
    );
    res.cookie("session_token", token, getSessionCookieOptions(expiresAt));
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(201).send(renderSignupSuccessPage());
  });

  app.get("/pricing", optionalAuthMiddleware(pool), (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(renderPricingPage());
  });

  app.get("/upgrade", optionalAuthMiddleware(pool), (req, res) => {
    const storeUrl = process.env.FASTSPRING_STORE_URL || DEFAULT_FASTSPRING_STORE_URL;
    const productPath =
      process.env.FASTSPRING_PRODUCT_PATH || DEFAULT_FASTSPRING_PRODUCT_PATH;
    const usingDefaults =
      !process.env.FASTSPRING_STORE_URL || !process.env.FASTSPRING_PRODUCT_PATH;

    if (req.user && req.user.isPaid) {
      return res.redirect("/dashboard");
    }

    if (storeUrl && productPath) {
      try {
        // Construct FastSpring Web Storefront URL
        // Format: https://STORE.onfastspring.com/PRODUCT-PATH
        const baseUrl = storeUrl.endsWith("/") ? storeUrl : storeUrl + "/";
        const checkoutUrl = new URL(productPath, baseUrl);

        if (req.user) {
          if (req.userId) {
            checkoutUrl.searchParams.set("tags", `userId:${req.userId}`);
          }
          if (req.user.email) {
        
            checkoutUrl.searchParams.set("email", req.user.email); // Pre-fill email
          }
        }

        if (usingDefaults) {
          console.warn(
            "[FastSpring] Using bundled FastSpring defaults. Set FASTSPRING_STORE_URL and FASTSPRING_PRODUCT_PATH to override."
          );
        }
        return res.redirect(checkoutUrl.toString());
      } catch (error) {
        console.error("[FastSpring] Error constructing checkout URL:", error);
      }
    } else {
      console.warn(
        "[FastSpring] Missing environment variables: FASTSPRING_STORE_URL or FASTSPRING_PRODUCT_PATH"
      );
    }

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(
      renderInfoPage("GO PRO", [
        "UNLIMITED CLIENTS. HISTORY. EXPORTS. ALERTS",
        "PAYMENTS COMING SOON",
      ])
    );
  });

  app.post("/webhooks/fastspring", async (req, res) => {
    const signature = req.get("X-FS-Signature");
    const secret = process.env.FASTSPRING_HMAC_SECRET;

    console.log("[FastSpring] Webhook received");

    if (!secret) {
      console.error("[FastSpring] Missing FASTSPRING_HMAC_SECRET environment variable.");
      return res.status(500).send("Configuration Error");
    }

    if (!fastspring.verifySignature(req.rawBody, signature, secret)) {
      console.warn("[FastSpring] Invalid signature");
      try {
        const expected = crypto
          .createHmac("sha256", secret)
          .update(req.rawBody || "")
          .digest("base64");
        console.warn(`[FastSpring] Expected: ${expected}, Actual: ${signature}`);
      } catch (e) {
        console.error("[FastSpring] Error re-calculating signature for log:", e.message);
      }
      return res.status(401).send("Invalid signature");
    }

    try {
      const events = req.body.events;
      console.log("[FastSpring] Events:", JSON.stringify(events, null, 2));
      await fastspring.processWebhook(pool, events);
      return res.status(200).send("OK");
    } catch (err) {
      console.error("[FastSpring] Webhook processing failed", err);
      return res.status(500).send("Internal Error");
    }
  });

  app.get("/privacy", (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(
      renderPrivacyPage()
    );
  });

  app.get("/terms", (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(
      renderTermsPage()
    );
  });

  app.get("/login", optionalAuthMiddleware(pool), (req, res) => {
    if (req.userId) {
      return res.redirect("/dashboard");
    }
    const errorMessage =
      typeof req.query.error === "string" ? req.query.error : undefined;
    const showSignupLink = errorMessage === "User with this email does not exist";
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res
      .status(200)
      .send(renderLoginPage(errorMessage, { showSignupLink }));
  });

  app.get("/auth/google", optionalAuthMiddleware(pool), async (req, res) => {
    if (req.userId) {
      return res.redirect("/dashboard");
    }
    const googleConfig = getGoogleConfig(googleOverrides);
    if (!googleConfig) {
      return res.redirect(
        303,
        "/login?error=" + encodeURIComponent("Google sign-in is not configured.")
      );
    }

    const modeParam = typeof req.query.mode === "string" ? req.query.mode : "";
    const mode = modeParam === "signup" ? "signup" : "signin";
    const state = crypto.randomBytes(16).toString("hex");
    const signedState = createSignedState(state, mode, googleConfig.stateSecret);
    res.cookie("oauth_state", signedState, {
      httpOnly: true,
      sameSite: "lax",
      secure: isProductionEnv(),
      maxAge: OAUTH_STATE_TTL_MS,
    });

    const redirectUri = resolveRedirectUri(googleConfig.baseUrl, googleConfig.redirectPath);
    const url = new URL(GOOGLE_AUTH_URL);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", googleConfig.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("state", state);
    url.searchParams.set("access_type", "online");
    return res.redirect(303, url.toString());
  });

      app.get("/auth/google/callback", optionalAuthMiddleware(pool), async (req, res) => {
    try {
      if (req.userId) {
        return res.redirect("/dashboard");
      }
      const googleConfig = getGoogleConfig(googleOverrides);
      if (!googleConfig) {
        return res.redirect(
          303,
          "/login?error=" + encodeURIComponent("Google sign-in is not configured.")
        );
      }

      const prefersHtml = requestExpectsHtml(req) && !requestExpectsJson(req);
      if (!prefersHtml) {
        return res.status(400).json({ error: "OAuth callbacks must be HTML requests." });
      }

      const code = typeof req.query.code === "string" ? req.query.code : "";
      const state = typeof req.query.state === "string" ? req.query.state : "";
      if (!code || !state) {
        return res.redirect(
          303,
          "/login?error=" + encodeURIComponent("Google sign-in failed (missing params).")
        );
      }

      const cookies = parseCookies(req);
      const signedState = cookies.oauth_state;
      const expectedState = verifySignedState(signedState, googleConfig.stateSecret);
      res.clearCookie("oauth_state", {
        httpOnly: true,
        sameSite: "lax",
        secure: isProductionEnv(),
      });
      if (!expectedState || expectedState.state !== state) {
        return res.redirect(
          303,
          "/login?error=" + encodeURIComponent("Google sign-in failed (invalid state).")
        );
      }

      const oauthMode = expectedState.mode === "signup" ? "signup" : "signin";

      let tokenPayload;
      try {
        const redirectUri = resolveRedirectUri(googleConfig.baseUrl, googleConfig.redirectPath);
        const tokenResponse = await googleConfig.exchangeCodeForTokens({
          code,
          clientId: googleConfig.clientId,
          clientSecret: googleConfig.clientSecret,
          redirectUri,
        });
        tokenPayload = await googleConfig.verifyIdToken(
          tokenResponse.id_token,
          googleConfig.clientId
        );
      } catch (err) {
        console.error("[oauth] token exchange failed", err);
        return res.redirect(
          303,
          "/login?error=" + encodeURIComponent("Google sign-in failed (token exchange).")
        );
      }

      const googleSub = typeof tokenPayload.sub === "string" ? tokenPayload.sub : "";
      const email = typeof tokenPayload.email === "string" ? tokenPayload.email : "";
      const emailVerified =
        tokenPayload.email_verified === true || tokenPayload.email_verified === "true";
      const normalizedEmail = normalizeEmail(email);
      if (!googleSub || !normalizedEmail || !emailVerified) {
        return res.redirect(
          303,
          "/login?error=" + encodeURIComponent("Google sign-in failed (invalid profile).")
        );
      }

      const countResult = await pool.query("SELECT COUNT(*) AS count FROM users");
      const userCount = Number(countResult.rows[0].count);
      const isFirstUser = userCount === 0;

      if (oauthMode === "signup" || isFirstUser) {
        const existingUser = await pool.query(
          "SELECT id FROM users WHERE email = $1",
          [normalizedEmail]
        );
        if (existingUser.rowCount > 0) {
          return res.redirect(
            303,
            "/login?error=" + encodeURIComponent("Account already exists. Please sign in.")
          );
        }

        const insertResult = await pool.query(
          "INSERT INTO users (email, password_hash, google_sub, auth_provider, is_paid) VALUES ($1, $2, $3, 'google', false) RETURNING id",
          [normalizedEmail, null, googleSub]
        );
        const userId = insertResult.rows[0].id;
        const token = crypto.randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + SESSION_TTL_HOURS * 3600 * 1000);
        await pool.query(
          "INSERT INTO sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)",
          [userId, token, expiresAt]
        );
        res.cookie("session_token", token, getSessionCookieOptions(expiresAt));
        return res.redirect(303, "/dashboard");
      }

      const existingUser = await pool.query(
        "SELECT id, google_sub FROM users WHERE email = $1",
        [normalizedEmail]
      );

      if (existingUser.rowCount === 0) {
        return res.redirect(
          303,
          "/login?error=" + encodeURIComponent("User with this email does not exist")
        );
      }

      const user = existingUser.rows[0];
      if (user.google_sub && user.google_sub !== googleSub) {
        return res.redirect(
          303,
          "/login?error=" + encodeURIComponent("Google sign-in failed.")
        );
      }
      await pool.query(
        "UPDATE users SET google_sub = $1, auth_provider = 'google' WHERE id = $2",
        [user.google_sub || googleSub, user.id]
      );
      const userId = user.id;

      const token = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + SESSION_TTL_HOURS * 3600 * 1000);
      await pool.query(
        "INSERT INTO sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)",
        [userId, token, expiresAt]
      );
      res.cookie("session_token", token, getSessionCookieOptions(expiresAt));
      return res.redirect(303, "/dashboard");
    } catch (err) {
      console.error("[oauth] callback error", err);
      return res.redirect(
        303,
        "/login?error=" + encodeURIComponent("An error occurred during sign-in.")
      );
    }
  });

app.post("/users", optionalAuthMiddleware(pool), async (req, res) => {
    // Single-operator: allow creation only if no users exist.
    const { email, password } = req.body || {};
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail) {
      return res.status(400).json({ error: "email is required" });
    }
    if (typeof password !== "string" || password.length < 8) {
      return res
        .status(400)
        .json({ error: "password must be at least 8 characters" });
    }

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );
    if (existingUser.rowCount > 0) {
      return res.status(409).json({ error: "email already in use" });
    }

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
      [normalizedEmail, hash]
    );
    return res.status(201).json({ id: result.rows[0].id, email: result.rows[0].email });
  });

  app.post("/sessions", async (req, res) => {
    const { email, password } = req.body || {};
    const normalizedEmail = normalizeEmail(email);
    const prefersJson = requestExpectsJson(req);
    const prefersHtml = requestExpectsHtml(req) && !prefersJson;
    const debugAuth = process.env.DEBUG_AUTH === "true";

    if (!normalizedEmail || typeof password !== "string") {
      const debugPayload = debugAuth ? { reason: "missing_email_or_password" } : undefined;
      if (prefersHtml) {
        return renderLoginResponse(res, 400, "EMAIL AND PASSWORD REQUIRED");
      }
      return res.status(400).json({ error: "email and password are required", ...debugPayload });
    }
    const userResult = await pool.query(
      "SELECT id, password_hash FROM users WHERE email = $1",
      [normalizedEmail]
    );
    if (userResult.rowCount === 0) {
      console.warn("[login] email not found:", normalizedEmail);
      const debugPayload = debugAuth ? { reason: "email_not_found" } : undefined;
      if (prefersHtml) {
        return renderLoginResponse(res, 401, "INVALID CREDENTIALS");
      }
      return res.status(401).json({ error: "Invalid credentials", ...debugPayload });
    }
    const user = userResult.rows[0];
    if (typeof user.password_hash !== "string") {
      const debugPayload = debugAuth ? { reason: "password_not_set" } : undefined;
      if (prefersHtml) {
        return renderLoginResponse(res, 401, "INVALID CREDENTIALS");
      }
      return res.status(401).json({ error: "Invalid credentials", ...debugPayload });
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      console.warn("[login] password mismatch for", normalizedEmail);
      const debugPayload = debugAuth ? { reason: "password_mismatch" } : undefined;
      if (prefersHtml) {
        return renderLoginResponse(res, 401, "INVALID CREDENTIALS");
      }
      return res.status(401).json({ error: "Invalid credentials", ...debugPayload });
    }
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + SESSION_TTL_HOURS * 3600 * 1000);
    await pool.query(
      "INSERT INTO sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)",
      [user.id, token, expiresAt]
    );
    res.cookie("session_token", token, getSessionCookieOptions(expiresAt));
    if (prefersHtml) {
      return res.redirect(303, "/dashboard");
    }
    return res.status(201).json({ ok: true });
  });

  app.get("/logout", async (req, res) => {
    const prefersJson = requestExpectsJson(req);
    const prefersHtml = requestExpectsHtml(req) && !prefersJson;
    const cookies = parseCookies(req);
    const token = cookies["session_token"];

    if (token) {
      try {
        await pool.query("DELETE FROM sessions WHERE session_token = $1", [token]);
      } catch (err) {
        console.error("[logout] failed to delete session", err);
      }
    }

    res.clearCookie("session_token", {
      httpOnly: true,
      sameSite: "lax",
      secure: isProductionEnv(),
    });

    if (prefersHtml) {
      return res.redirect(303, "/");
    }
    return res.status(200).json({ ok: true });
  });

  app.use(authMiddleware(pool));

  app.get("/clients/new", async (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(
      renderNewClientPage({
        values: { name: "", monthly_hour_limit: "" },
      })
    );
  });

  app.post("/clients", async (req, res) => {
    const { name, monthly_hour_limit } = req.body || {};
    const prefersJson = requestExpectsJson(req);
    const prefersHtml = requestExpectsHtml(req) && !prefersJson;
    const userId = req.userId;

    const errors = [];
    if (typeof name !== "string" || !name.trim()) {
      errors.push("NAME REQUIRED");
    }
    const parsedLimit = Number(monthly_hour_limit);
    if (Number.isNaN(parsedLimit)) {
      errors.push("LIMIT MUST BE A NUMBER");
    } else if (!Number.isFinite(parsedLimit) || parsedLimit <= 0) {
      errors.push("LIMIT MUST BE > 0");
    } else if (!hasAtMostTwoDecimals(parsedLimit)) {
      errors.push("LIMIT MAX 2 DECIMALS");
    } else if (parsedLimit > 9999999.99) {
      errors.push("LIMIT TOO HIGH");
    }

    if (errors.length > 0) {
      if (prefersHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(400).send(
          renderNewClientPage({
            errorMessage: errors[0],
            values: {
              name: typeof name === "string" ? name : "",
              monthly_hour_limit:
                typeof monthly_hour_limit === "string"
                  ? monthly_hour_limit
                  : monthly_hour_limit == null
                    ? ""
                    : String(monthly_hour_limit),
            },
          })
        );
      }
      return res.status(400).json({ errors });
    }

    const clientName = name.trim();
    const clientLimit = parsedLimit.toFixed(2);

    const isPaidUser = req.user?.isPaid === true;
    if (!isPaidUser) {
      const countResult = await pool.query(
        "SELECT COUNT(*) AS count FROM clients WHERE user_id = $1",
        [userId]
      );
      const clientCount = Number(countResult.rows[0].count || 0);
      if (clientCount >= 2) {
        const limitMessage =
          "FREE PLAN LIMIT REACHED (2 CLIENTS). UPGRADE.";
        if (prefersHtml) {
          res.setHeader("Content-Type", "text/html; charset=utf-8");
          return res.status(403).send(
            renderNewClientPage({
              errorMessage: limitMessage,
              errorLink: { href: "/upgrade", text: "UPGRADE" },
              values: {
                name: typeof name === "string" ? name : "",
                monthly_hour_limit:
                  typeof monthly_hour_limit === "string"
                    ? monthly_hour_limit
                    : monthly_hour_limit == null
                      ? ""
                      : String(monthly_hour_limit),
              },
            })
          );
        }
        return res.status(403).json({
          error: limitMessage,
          pricing: "/upgrade",
        });
      }
    }

    const clientInsert =
      "INSERT INTO clients (name, user_id) VALUES ($1, $2) RETURNING id, name";
    const retainerInsert =
      "INSERT INTO retainers (client_id, monthly_hour_limit) VALUES ($1, $2)";

    try {
      await pool.query("BEGIN");
      const clientResult = await pool.query(clientInsert, [clientName, userId]);
      const clientId = clientResult.rows[0].id;
      await pool.query(retainerInsert, [clientId, clientLimit]);
      await pool.query("COMMIT");
      if (prefersHtml) {
        return res.redirect(303, "/dashboard");
      }
      return res.status(201).json({
        id: clientId,
        name: clientName,
        monthly_hour_limit: Number(clientLimit),
        hours_used: 0,
        hours_remaining: Number(clientLimit),
      });
    } catch (err) {
      await pool.query("ROLLBACK");
      console.error(err);
      if (prefersHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(500).send(
          renderNewClientPage({
            errorMessage: "SYSTEM ERROR",
            values: {
              name: typeof name === "string" ? name : "",
              monthly_hour_limit:
                typeof monthly_hour_limit === "string"
                  ? monthly_hour_limit
                  : monthly_hour_limit == null
                    ? ""
                    : String(monthly_hour_limit),
            },
          })
        );
      }
      return res.status(500).json({ error: "Internal error" });
    }
  });

  app.delete("/clients/:id", async (req, res) => {
    const clientId = Number(req.params.id);
    const userId = req.userId;
    if (!Number.isInteger(clientId) || clientId <= 0) {
      return res.status(400).json({ error: "Invalid client id" });
    }

    const clientResult = await pool.query(
      "SELECT id FROM clients WHERE id = $1 AND user_id = $2",
      [clientId, userId]
    );
    if (clientResult.rowCount === 0) {
      return res.status(404).json({ error: "Client not found" });
    }

    try {
      await pool.query("BEGIN");
      await pool.query("DELETE FROM time_entries WHERE client_id = $1", [
        clientId,
      ]);
      await pool.query("DELETE FROM retainers WHERE client_id = $1", [
        clientId,
      ]);
      await pool.query("DELETE FROM clients WHERE id = $1 AND user_id = $2", [
        clientId,
        userId,
      ]);
      await pool.query("COMMIT");
      return res.status(200).json({ message: "CLIENT DELETED" });
    } catch (err) {
      await pool.query("ROLLBACK");
      console.error(err);
      return res.status(500).json({ error: "Internal error" });
    }
  });

  app.get("/clients", async (req, res) => {
    const today = getTodayParts(userTimeZone);
    const monthRange = getMonthDateRange(today.year, today.month);
    const data = await fetchClientSummaries(pool, monthRange, {
      userId: req.userId,
    });
    return res.json({ clients: data });
  });

  app.get("/dashboard", async (req, res) => {
    const hasMonthParam =
      typeof req.query.month === "string" && req.query.month !== "";
    const monthParam = parseMonthParam(req.query.month);
    if (hasMonthParam && !monthParam) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(400).send(renderNotFoundPage("INVALID MONTH FORMAT"));
    }

    const today = getTodayParts(userTimeZone);
    const targetMonth = monthParam || { year: today.year, month: today.month };
    const isPaidUser = req.user?.isPaid === true;

    const requestedMonthIsCurrent =
      targetMonth.year === today.year && targetMonth.month === today.month;

    if (!isPaidUser && monthParam && !requestedMonthIsCurrent) {
      const message = "PAST MONTHS REQUIRE PRO PLAN.";
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res
        .status(403)
        .send(renderPlainMessagePage(message, { includeUpgrade: true }));
    }

    const monthRange = getMonthDateRange(targetMonth.year, targetMonth.month);
    const clients = await fetchClientSummaries(pool, monthRange, {
      userId: req.userId,
      includeAlerts: isPaidUser && requestedMonthIsCurrent,
      isCurrentMonth: requestedMonthIsCurrent,
      includeEntries: true,
    });
    const isCurrentMonth = requestedMonthIsCurrent;
    const html = renderDashboardPage(clients, {
      isCurrentMonth,
      monthLabel: formatMonthLabel(targetMonth.year, targetMonth.month, userTimeZone),
    });
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  });

  app.get("/export/current-month.csv", async (req, res) => {
    const isPaidUser = req.user?.isPaid === true;
    if (!isPaidUser) {
      const message = "EXPORTS REQUIRE PRO PLAN.";
      if (requestExpectsHtml(req)) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res
          .status(403)
          .send(renderPlainMessagePage(message, { includeUpgrade: true }));
      }
      return res.status(403).json({ error: message, pricing: "/upgrade" });
    }

    const today = getTodayParts(userTimeZone);
    const monthRange = getMonthDateRange(today.year, today.month);
    const clients = await fetchClientSummaries(pool, monthRange, {
      userId: req.userId,
    });
    const monthString = `${String(today.year).padStart(4, "0")}-${String(
      today.month
    ).padStart(2, "0")}`;

    const header = [
      "client_name",
      "monthly_hour_limit",
      "hours_used",
      "hours_remaining",
      "month",
    ];
    const rows = clients.map((client) => [
      client.name,
      numberToPlainString(client.monthly_hour_limit),
      numberToPlainString(client.hours_used),
      numberToPlainString(client.hours_remaining),
      monthString,
    ]);

    const csv = [header, ...rows]
      .map((row) => row.map(csvEscape).join(","))
      .join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="hourcrate-${monthString}.csv"`
    );
    return res.status(200).send(csv);
  });

  app.get("/clients/:id/entries/new", async (req, res) => {
    const clientId = Number(req.params.id);
    if (!Number.isInteger(clientId) || clientId <= 0) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(400).send(renderNotFoundPage("INVALID CLIENT ID"));
    }

    const clientResult = await pool.query(
      "SELECT id, name FROM clients WHERE id = $1 AND user_id = $2",
      [clientId, req.userId]
    );
    if (clientResult.rowCount === 0) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(404).send(renderNotFoundPage("CLIENT NOT FOUND"));
    }

    const today = getTodayParts(userTimeZone);
    const defaultDate = formatDateParts(today);

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(
      renderNewEntryPage({
        client: { id: clientId, name: clientResult.rows[0].name },
        values: { date: defaultDate, hours: "" },
      })
    );
  });

  app.post("/clients/:id/entries", async (req, res) => {
    const clientId = Number(req.params.id);
    if (!Number.isInteger(clientId) || clientId <= 0) {
      return res.status(400).json({ error: "Invalid client id" });
    }

    const { date, hours } = req.body || {};
    const prefersJson = requestExpectsJson(req);
    const prefersHtml = requestExpectsHtml(req) && !prefersJson;

    const errors = [];

    const parsedDate = parseDateString(date);
    if (!parsedDate) {
      errors.push("INVALID DATE FORMAT");
    }

    const parsedHours = Number(hours);
    if (Number.isNaN(parsedHours)) {
      errors.push("HOURS MUST BE A NUMBER");
    } else if (!Number.isFinite(parsedHours) || parsedHours <= 0) {
      errors.push("HOURS MUST BE > 0");
    } else if (!hasAtMostTwoDecimals(parsedHours)) {
      errors.push("HOURS MAX 2 DECIMALS");
    } else if (parsedHours > 9999999.99) {
      errors.push("HOURS TOO HIGH");
    }

    if (parsedDate) {
      const today = getTodayParts(userTimeZone);
      const currentMonthRange = {
        year: today.year,
        month: today.month,
        startDay: 1,
        endDay: daysInMonth(today.year, today.month),
      };

      if (
        parsedDate.year !== currentMonthRange.year ||
        parsedDate.month !== currentMonthRange.month
      ) {
        errors.push("DATE MUST BE CURRENT MONTH");
      } else if (parsedDate.day > today.day) {
        errors.push("NO FUTURE DATES");
      } else if (
        parsedDate.day < currentMonthRange.startDay ||
        parsedDate.day > currentMonthRange.endDay
      ) {
        errors.push("INVALID DAY");
      }
    }

    if (errors.length > 0) {
      if (prefersHtml) {
        const clientResult = await pool.query(
          "SELECT id, name FROM clients WHERE id = $1 AND user_id = $2",
          [clientId, req.userId]
        );
        if (clientResult.rowCount === 0) {
          res.setHeader("Content-Type", "text/html; charset=utf-8");
          return res.status(404).send(renderNotFoundPage("CLIENT NOT FOUND"));
        }
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(400).send(
          renderNewEntryPage({
            errorMessage: errors[0],
            client: { id: clientId, name: clientResult.rows[0].name },
            values: {
              date: typeof date === "string" ? date : "",
              hours:
                typeof hours === "string"
                  ? hours
                  : hours == null
                    ? ""
                    : String(hours),
            },
          })
        );
      }
      return res.status(400).json({ errors });
    }

    const clientResult = await pool.query(
      "SELECT id FROM clients WHERE id = $1 AND user_id = $2",
      [clientId, req.userId]
    );
    if (clientResult.rowCount === 0) {
      if (prefersHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(404).send(renderNotFoundPage("CLIENT NOT FOUND"));
      }
      return res.status(404).json({ error: "Client not found" });
    }

    try {
      const result = await pool.query(
        `INSERT INTO time_entries (client_id, entry_date, hours)
         VALUES ($1, $2, $3)
         RETURNING id, entry_date::text AS entry_date, hours`,
        [clientId, date, parsedHours.toFixed(2)]
      );
      if (prefersHtml) {
        return res.redirect(303, "/dashboard");
      }
      return res.status(201).json({
        id: result.rows[0].id,
        client_id: clientId,
        date: result.rows[0].entry_date,
        hours: Number(result.rows[0].hours),
      });
    } catch (err) {
      console.error(err);
      if (prefersHtml) {
        const clientNameResult = await pool.query(
          "SELECT id, name FROM clients WHERE id = $1 AND user_id = $2",
          [clientId, req.userId]
        );
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(500).send(
          renderNewEntryPage({
            errorMessage: "SYSTEM ERROR",
            client:
              clientNameResult.rowCount > 0
                ? { id: clientId, name: clientNameResult.rows[0].name }
                : { id: clientId, name: "" },
            values: {
              date: typeof date === "string" ? date : "",
              hours:
                typeof hours === "string"
                  ? hours
                  : hours == null
                    ? ""
                    : String(hours),
            },
          })
        );
      }
      return res.status(500).json({ error: "Internal error" });
    }
  });

  app.use((req, res) => {
    return res.status(404).json({ error: "Not found" });
  });

  return app;
}

function hasAtMostTwoDecimals(value) {
  const [, decimals = ""] = String(value).split(".");
  return decimals.length <= 2;
}

function parseDateString(value) {
  if (typeof value !== "string") return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  if (day > daysInMonth(year, month)) return null;
  return { year, month, day };
}

function getTodayParts(timeZone) {
  const fmt = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });
  const [yearStr, monthStr, dayStr] = fmt.format(new Date()).split("-");
  return {
    year: Number(yearStr),
    month: Number(monthStr),
    day: Number(dayStr),
  };
}

function daysInMonth(year, month) {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function formatDateParts(parts) {
  const y = String(parts.year).padStart(4, "0");
  const m = String(parts.month).padStart(2, "0");
  const d = String(parts.day).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function parseMonthParam(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  const match = /^(\d{4})-(\d{2})$/.exec(value.trim());
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  if (!isValidMonth(year, month)) return null;
  return { year, month };
}

function isValidMonth(year, month) {
  if (!Number.isInteger(year) || !Number.isInteger(month)) return false;
  if (year < 1 || year > 9999) return false;
  return month >= 1 && month <= 12;
}

function getMonthDateRange(year, month) {
  const startDate = formatDateParts({ year, month, day: 1 });
  let nextMonthYear = year;
  let nextMonth = month + 1;
  if (nextMonth === 13) {
    nextMonth = 1;
    nextMonthYear += 1;
  }
  const nextMonthStart = formatDateParts({
    year: nextMonthYear,
    month: nextMonth,
    day: 1,
  });
  return { startDate, nextMonthStart, year, month };
}

function formatMonthLabel(year, month, timeZone) {
  const date = new Date(Date.UTC(year, month - 1, 1));
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone,
    month: "long",
    year: "numeric",
  });
  return fmt.format(date);
}

function numberToPlainString(value) {
  if (Number.isInteger(value)) return String(value);
  return String(Number(value));
}

function csvEscape(value) {
  const str = String(value);
  if (/[",\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

async function fetchClientSummaries(pool, monthRange, options = {}) {
  const includeAlerts = options.includeAlerts === true;
  const includeEntries = options.includeEntries === true;
  const isCurrentMonth = options.isCurrentMonth === true;
  const userId = Number(options.userId);
  if (!Number.isInteger(userId)) {
    throw new Error("userId is required to fetch client summaries");
  }
  const result = await pool.query(
    `SELECT c.id, c.name, r.monthly_hour_limit,
            COALESCE(SUM(te.hours), 0) AS hours_used,
            (r.monthly_hour_limit - COALESCE(SUM(te.hours), 0)) AS hours_remaining
     FROM clients c
     JOIN retainers r ON r.client_id = c.id
     LEFT JOIN time_entries te
       ON te.client_id = c.id
      AND te.entry_date >= $1
      AND te.entry_date < $2
     WHERE c.user_id = $3
     GROUP BY c.id, c.name, r.monthly_hour_limit
     ORDER BY c.id ASC`,
    [monthRange.startDate, monthRange.nextMonthStart, userId]
  );
  const summaries = result.rows.map((row) => {
    const limit = Number(row.monthly_hour_limit);
    const used = Number(row.hours_used);
    const remaining = Number(row.hours_remaining);
    const alertStatus = includeAlerts
      ? used >= limit
        ? "critical"
        : used >= limit * 0.8
          ? "warning"
          : null
      : null;
    return {
      id: row.id,
      name: row.name,
      monthly_hour_limit: limit,
      hours_used: used,
      hours_remaining: remaining,
      alertStatus,
      canAddHours: isCurrentMonth,
    };
  });

  if (includeEntries) {
    const entriesResult = await pool.query(
      `SELECT te.client_id, te.entry_date, te.hours
       FROM time_entries te
       JOIN clients c ON c.id = te.client_id
       WHERE c.user_id = $1
         AND te.entry_date >= $2
         AND te.entry_date < $3
       ORDER BY te.entry_date DESC, te.id DESC`,
      [userId, monthRange.startDate, monthRange.nextMonthStart]
    );

    const entriesByClient = new Map();
    for (const row of entriesResult.rows) {
      const dateObj = new Date(row.entry_date);
      const entryDate = formatDateParts({
        year: dateObj.getUTCFullYear(),
        month: dateObj.getUTCMonth() + 1,
        day: dateObj.getUTCDate(),
      });
      const entry = { date: entryDate, hours: Number(row.hours) };
      const list = entriesByClient.get(row.client_id) || [];
      list.push(entry);
      entriesByClient.set(row.client_id, list);
    }

    summaries.forEach((client) => {
      client.entries = entriesByClient.get(client.id) || [];
    });
  }

  return summaries;
}

function renderLandingPage(options = {}) {
  const isAuthenticated = options.isAuthenticated === true;
  const startHref = isAuthenticated ? "/dashboard" : "/signup";
  const signupLink = isAuthenticated
    ? ""
    : '<a class="cta-secondary" href="/signup">SIGN UP</a>';
  const footerAuthLink = isAuthenticated
    ? '<a href="/logout">LOGOUT</a>'
    : '<a href="/login">LOGIN</a>';
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "Hourcrate | RETAINER HOURS. CONTAINED.",
    description:
      "Hourcrate keeps monthly retainer hours contained with simple limits and clear tracking.",
    canonical: "https://hourcrate.com/",
    robots: "index, follow",
  })}
</head>
<body class="landing-body">
  <main class="page landing">
    <header class="hero">
      <h1 class="hero-title">STOP GIVING AWAY HOURS.</h1>
      <p class="hero-subhead">TRACK LIMITS. STOP OVER-SERVICING. GET PAID.</p>
      <div class="cta-row">
        <a class="cta-primary" href="${startHref}">START NOW</a>
        <a class="cta-secondary" href="/login">LOGIN</a>
        ${signupLink}
      </div>
    </header>

    <section class="section">
      <h2>HOW IT WORKS</h2>
      <ul class="plain-list">
        <li>SET LIMITS.</li>
        <li>LOG HOURS.</li>
        <li>WATCH THE CAP.</li>
      </ul>
    </section>

    <section class="section">
      <h2>WHO THIS IS FOR</h2>
      <p>FOR CONSULTANTS AND AGENCIES WHO HATE SCOPE CREEP.</p>
    </section>

    <section class="section pricing">
      <p class="pricing-note">FREE FOR SMALL TEAMS. PRO FOR SCALING.</p>
    </section>
  </main>

  <footer class="footer">
    <div class="footer-links" aria-label="Footer navigation">
      ${footerAuthLink}
      <a href="/pricing">PRICING</a>
      <a href="/privacy">PRIVACY</a>
      <a href="/terms">TERMS</a>
    </div>
    <div class="footer-meta" aria-label="Footer contact">
      <div class="footer-identity">
        <span class="footer-credit">BUILT BY SAYEEM KHAN</span>
        <a class="footer-social" href="https://www.linkedin.com/in/sayeem-khan-7657732b7/" aria-label="LinkedIn">
          <svg class="footer-icon" viewBox="0 0 24 24" role="img" aria-hidden="true">
            <path d="M4.98 3.5C4.98 4.88 3.86 6 2.5 6 1.12 6 0 4.88 0 3.5 0 2.12 1.12 1 2.5 1 3.86 1 4.98 2.12 4.98 3.5zM.24 23.5h4.52V8.5H.24v15zM8.43 8.5h4.33v2.04h.06c.6-1.1 2.05-2.25 4.23-2.25 4.52 0 5.36 2.9 5.36 6.67v8.54h-4.52v-7.57c0-1.8-.03-4.11-2.5-4.11-2.5 0-2.88 1.95-2.88 3.98v7.7H8.43V8.5z"/>
          </svg>
        </a>
        <a class="footer-social" href="https://github.com/KhanSayeem" aria-label="GitHub">
          <svg class="footer-icon" viewBox="0 0 24 24" role="img" aria-hidden="true">
            <path d="M12 .5a11.5 11.5 0 0 0-3.63 22.4c.57.1.78-.24.78-.55v-2.17c-3.19.7-3.87-1.53-3.87-1.53-.52-1.33-1.28-1.68-1.28-1.68-1.06-.74.08-.73.08-.73 1.17.08 1.78 1.2 1.78 1.2 1.04 1.78 2.74 1.27 3.4.97.11-.75.42-1.27.76-1.56-2.54-.29-5.21-1.26-5.21-5.66 0-1.25.45-2.28 1.19-3.09-.12-.3-.51-1.48.11-3.1 0 0 .96-.3 3.14 1.18a11 11 0 0 1 5.72 0c2.18-1.48 3.14-1.18 3.14-1.18.62 1.62.23 2.8.11 3.1.74.8 1.19 1.83 1.19 3.08 0 4.4-2.67 5.37-5.22 5.66.43.37.81 1.09.81 2.2v3.25c0 .31.2.66.78.55A11.5 11.5 0 0 0 12 .5z"/>
          </svg>
        </a>
        <a class="footer-social" href="mailto:sayeem@daywinlabs.com" aria-label="Email">
          <svg class="footer-icon" viewBox="0 0 24 24" role="img" aria-hidden="true">
            <path d="M3 5h18a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1zm0 2v1.1l9 5.1 9-5.1V7l-9 5.1L3 7zm0 3.26v6.74h18v-6.74l-9 5.1-9-5.1z"/>
          </svg>
        </a>
      </div>
      <div class="footer-open">
        <a href="https://github.com/KhanSayeem">OPEN SOURCE ON GITHUB</a>
      </div>
      <div class="footer-copy">© 2025 HOURCRATE | OPERATED BY DAYWIN LABS</div>
    </div>
  </footer>
</body>
</html>`;
}

function renderPricingPage() {
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "Pricing - Hourcrate",
    description:
      "Hourcrate pricing: Free for two clients, Hourcrate Pro at $12/month for unlimited clients, history, exports, and alerts.",
    canonical: "https://hourcrate.com/pricing",
    robots: "index, follow",
  })}
</head>
<body>
  <main class="page pricing-page">
    <h1>PRICING</h1>

    <section class="plan">
      <h2 class="plan-title">FREE</h2>
      <ul class="plain-list">
        <li>2 CLIENTS MAX</li>
        <li>CURRENT MONTH ONLY</li>
        <li>MANUAL ENTRY</li>
        <li>NO EXPORTS</li>
      </ul>
      <p class="plan-note">TRY IT OUT.</p>
    </section>

    <section class="plan">
      <h2 class="plan-title">PRO</h2>
      <ul class="plain-list">
        <li>UNLIMITED CLIENTS</li>
        <li>HISTORY</li>
        <li>EXPORTS</li>
        <li>ALERTS</li>
      </ul>
      <p class="plan-price">$12 / MO</p>
      <p class="plan-note">CANCEL ANYTIME.</p>
    </section>

    <div class="upgrade-action">
      <a class="upgrade-link" href="/upgrade">GO PRO</a>
    </div>
  </main>
</body>
</html>`;
}

function renderSignupPage(errorMessage, values = {}) {
  const errorBlock = errorMessage
    ? `<p role="alert">${errorMessage}</p>`
    : "";
  const emailValue =
    typeof values.email === "string" && values.email
      ? ` value="${escapeHtml(values.email)}"`
      : "";
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "CREATE ACCOUNT - HOURCRATE",
    description: "Create an Hourcrate account to keep retainer hours capped and visible.",
    canonical: "https://hourcrate.com/signup",
  })}
</head>
<body>
  <main class="page auth-page">
    <div class="form-wrapper">
      <h1>CREATE ACCOUNT</h1>
      ${errorBlock}
      <form action="/signup" method="post">
        <div>
          <label for="email">EMAIL</label>
          <input type="email" id="email" name="email"${emailValue} required>
        </div>
        <div>
          <label for="password">PASSWORD</label>
          <input type="password" id="password" name="password" required>
        </div>
        <button type="submit">CREATE ACCOUNT</button>
      </form>
      <p class="oauth-link"><a href="/auth/google?mode=signup">SIGN UP WITH GOOGLE</a></p>
    </div>
  </main>
</body>
</html>`;
}

function renderSignupSuccessPage() {
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "ACCOUNT CREATED",
    description: "Your Hourcrate account is ready.",
  })}
</head>
<body>
  <main class="page text-page">
    <h1>ACCOUNT CREATED</h1>
    <p>YOUR ACCOUNT IS READY.</p>
    <p><a href="/dashboard">GO TO DASHBOARD</a></p>
  </main>
</body>
</html>`;
}

function renderPlainMessagePage(message, options = {}) {
  const includeUpgrade = options.includeUpgrade === true;
  const upgradeLink = includeUpgrade ? ' <a href="/upgrade">UPGRADE</a>' : "";
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({ title: "Hourcrate" })}
</head>
<body>
  <main class="page text-page">
    <p>${escapeHtml(message)}${upgradeLink}</p>
  </main>
</body>
</html>`;
}

function renderInfoPage(title, paragraphs) {
  const body = (Array.isArray(paragraphs) ? paragraphs : [])
    .map((text) => `<p>${escapeHtml(text)}</p>`)
    .join("");
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: `${title} - Hourcrate`,
  })}
</head>
<body>
  <main class="page text-page">
    <h1>${escapeHtml(title)}</h1>
    ${body}
  </main>
</body>
</html>`;
}

function renderPrivacyPage() {
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "Privacy Policy - Hourcrate",
  })}
</head>
<body>
  <main class="page text-page legal">
    <h1>PRIVACY POLICY</h1>
    <p><strong>Effective date:</strong> March 15, 2025</p>

    <section class="legal-section">
      <h2>1. Information We Collect</h2>
      <ul>
        <li><strong>Account data:</strong> your name, email address, workspace details, and billing contact information provided to create and manage your account.</li>
        <li><strong>Authentication data:</strong> encrypted credentials, session tokens, and optional single sign-on identifiers used to authenticate users and protect accounts.</li>
        <li><strong>Usage data:</strong> actions you take in the Service (such as client records, time entries, and settings changes), support communications, and limited technical logs to keep the Service reliable.</li>
        <li><strong>Payment data:</strong> transaction details from our payment providers (Stripe, Paddle, and 2Checkout), such as billing country, transaction amount, and status. We do not receive full payment card numbers.</li>
      </ul>
      <p>The Service is designed to use only the information necessary to operate Hourcrate.</p>
    </section>

    <section class="legal-section">
      <h2>2. How We Use the Information</h2>
      <ul>
        <li>Provide, maintain, and improve the Service and its features.</li>
        <li>Authenticate you, secure accounts, and prevent fraud or misuse.</li>
        <li>Process payments, invoices, and account changes through our payment partners.</li>
        <li>Respond to support requests and send transactional communications about your account or the Service.</li>
        <li>Comply with legal, tax, accounting, and regulatory obligations.</li>
      </ul>
    </section>

    <section class="legal-section">
      <h2>3. Cookies and Session Management</h2>
      <p>We use essential cookies to keep you signed in, protect your session, and remember required settings. No optional or cross-site tracking cookies are set. You can disable cookies in your browser, but the Service may not function correctly without them.</p>
    </section>

    <section class="legal-section">
      <h2>4. Data Storage and Security</h2>
      <p>Data is stored on secure servers with encryption in transit and at rest where applicable. Access is limited to authorized personnel and service providers who need it to operate the Service. We apply reasonable technical and organizational safeguards, but no method of transmission or storage is completely secure.</p>
    </section>

    <section class="legal-section">
      <h2>5. Data Retention</h2>
      <p>We retain account and usage data while your account is active. Backup logs and security records are kept for limited periods. Billing and transaction records may be retained longer as required for tax, accounting, or legal obligations. When you request deletion, we remove or anonymize personal data unless we must keep it for legal reasons.</p>
    </section>

    <section class="legal-section">
      <h2>6. Your Rights</h2>
      <p>Subject to applicable law, you may request access to your personal data, correct inaccurate information, obtain a copy in a portable format, or ask us to delete your personal data. You may also object to or restrict certain processing. California and EU/UK residents may have additional rights to know the categories of data collected and to request deletion; we do not sell personal data. To exercise these rights, contact support@hourcrate.com.</p>
    </section>

    <section class="legal-section">
      <h2>7. Data Sharing</h2>
      <p>We do not sell or rent your personal data. We share information only with service providers who help us operate the Service (including hosting, email delivery, and payment processors such as Stripe, Paddle, and 2Checkout) and with authorities if required by law or to protect rights and safety. These providers are required to protect your information and use it only as instructed.</p>
    </section>

    <section class="legal-section">
      <h2>8. International Users</h2>
      <p>Your data may be transferred to and processed in countries other than where you live so we can provide the Service and support. Where required, we use legal mechanisms such as contractual safeguards to protect these transfers. By using the Service, you consent to these transfers as permitted by applicable law.</p>
    </section>

    <section class="legal-section">
      <h2>9. Changes to This Policy</h2>
      <p>We may update this Privacy Policy from time to time. If we make material changes, we will post the new version on this page with an updated effective date and, when appropriate, provide additional notice.</p>
    </section>

    <section class="legal-section">
      <h2>10. Contact</h2>
      <p>Questions or requests? Email support@hourcrate.com.</p>
    </section>
  </main>
</body>
</html>`;
}

function renderTermsPage() {
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "Terms of Service - Hourcrate",
  })}
</head>
<body>
  <main class="page text-page legal">
    <h1>TERMS OF SERVICE</h1>

    <section class="legal-section">
      <h2>1. Introduction and Acceptance</h2>
      <p>Hourcrate is a web-based service available at https://hourcrate.com. By creating an account, accessing the Service, or paying fees, you agree to these Terms on behalf of yourself or the organization you represent and confirm you are legally permitted to do so. If you do not agree, do not use the Service. We may update these Terms by posting a revised version, and your continued use after the effective date constitutes acceptance.</p>
      <p>Hourcrate is operated by Mohammad Sayeem Khan, founder of <a href="https://www.daywinlabs.com/">Daywin Labs</a>, based in Bangladesh.</p>
    </section>

    <section class="legal-section">
      <h2>2. Description of the Service</h2>
      <p>The Service helps teams set monthly hour limits, log work, and monitor retainers. We provide dashboards and exports to support your internal workflows. Hourcrate does not provide professional advice, and the accuracy of any time or client data you enter is your responsibility.</p>
    </section>

    <section class="legal-section">
      <h2>3. Account Registration and User Responsibilities</h2>
      <ul>
        <li>Provide accurate account and billing information and keep it current.</li>
        <li>Maintain the confidentiality of your login credentials and notify us of any suspected misuse.</li>
        <li>Ensure you have the right to submit all data to the Service and that it complies with applicable laws and your client commitments.</li>
        <li>Do not misuse the Service, interfere with its operation, or attempt unauthorized access.</li>
      </ul>
    </section>

    <section class="legal-section">
      <h2>4. Subscription, Billing, and Payment Terms</h2>
      <ul>
        <li>Paid plans are billed in advance on a recurring basis (for example, monthly or annually) until canceled.</li>
        <li>You authorize Hourcrate and our payment processors (including Stripe, Paddle, and 2Checkout) to store and charge your payment method for all fees, applicable taxes, and currency conversion costs. Their terms and privacy notices apply to your transactions.</li>
        <li>Prices exclude taxes unless stated otherwise; you are responsible for all taxes, duties, and bank or exchange fees.</li>
        <li>Failed, reversed, or disputed payments may result in suspension or termination of access.</li>
        <li>We may change plan features or fees; any price change will apply from your next renewal after notice. Continued use after the change means you accept the new fees.</li>
      </ul>
    </section>

    <section class="legal-section">
      <h2>5. Cancellation and Termination</h2>
      <p>You can cancel at any time in your account settings or by contacting support. Cancellation takes effect at the end of the current billing term, and access continues until then unless we suspend or terminate earlier for breach, risk, or non-payment. We may close inactive or free accounts after notice. After termination, your data may be deleted; export anything you need beforehand.</p>
    </section>

    <section class="legal-section">
      <h2>6. Refund Policy</h2>
      <p>Fees are non-refundable and non-creditable except where required by law. Canceling does not provide refunds for the current billing period. If you believe a charge was made in error or duplicated, contact support promptly and we will review the request.</p>
    </section>

    <section class="legal-section">
      <h2>7. Service Availability and Modifications</h2>
      <p>The Service may change over time, and features may be added, modified, or removed. We may suspend or limit the Service for maintenance, security, or operational reasons. We do not guarantee uninterrupted availability or data preservation; you are responsible for keeping backups or exports.</p>
    </section>

    <section class="legal-section">
      <h2>8. Limitation of Liability</h2>
      <p>To the fullest extent permitted by law, Hourcrate and its affiliates will not be liable for indirect, incidental, special, consequential, or punitive damages, or for lost profits, revenues, data, or goodwill. Our total liability for any claim relating to the Service is limited to the fees you paid for the Service in the three months before the event giving rise to the claim. These limits apply even if we have been advised of the possibility of such damages and regardless of the theory of liability.</p>
    </section>

    <section class="legal-section">
      <h2>9. Disclaimer of Warranties</h2>
      <p>The Service is provided on an "as-is" and "as-available" basis. Hourcrate disclaims all warranties, express or implied, including any warranties of merchantability, fitness for a particular purpose, non-infringement, and accuracy. Your use of the Service is at your own risk.</p>
    </section>

    <section class="legal-section">
      <h2>10. Indemnification</h2>
      <p>You agree to indemnify and hold harmless Hourcrate, its affiliates, and their directors, officers, employees, and agents from any claims, losses, damages, liabilities, and expenses (including legal fees) arising from your use of the Service, your data, or any breach of these Terms or applicable law.</p>
    </section>

    <section class="legal-section">
      <h2>11. Governing Law and Jurisdiction</h2>
      <p>These Terms are governed by the laws of Bangladesh, without regard to conflict-of-law rules. The courts of Dhaka, Bangladesh will have exclusive jurisdiction over disputes relating to the Service, except where applicable law requires a different venue.</p>
    </section>

    <section class="legal-section">
      <h2>12. Contact</h2>
      <p>For questions or notices, contact support@hourcrate.com.</p>
    </section>
  </main>
</body>
</html>`;
}

function renderDashboardPage(clients, options = {}) {
  const monthLabel = options.monthLabel || "";
  const monthText = escapeHtml(monthLabel).toUpperCase();
  const hasClients = clients.length > 0;

  const cards = hasClients
    ? clients
        .map((client) => {
          const limit = formatHours(client.monthly_hour_limit);
          const used = formatHours(client.hours_used);
          const remainingRaw = Number(client.hours_remaining);
          const isOver = remainingRaw < 0;
          const remainingValue = isOver ? Math.abs(remainingRaw) : remainingRaw;
          const remainingLabel = `${formatHours(remainingValue)}H`;
          const remainingTitle = isOver ? "OVER" : "LEFT";
          const remainingClass = isOver ? " is-over" : " is-remaining";
          const denominator =
            client.monthly_hour_limit > 0 ? client.monthly_hour_limit : 1;
          const percent = Math.max(
            0,
            Math.min(100, (client.hours_used / denominator) * 100)
          );
          const progressClass =
            client.alertStatus === "critical"
              ? " is-critical"
              : client.alertStatus === "warning"
                ? " is-warning"
                : "";
          const entries = Array.isArray(client.entries) ? client.entries : [];
          const entriesHtml =
            entries.length > 0
              ? entries
                  .slice(0, 5)
                  .map(
                    (entry) => `<div class="dash-log-row">
              <span>${escapeHtml(entry.date)}</span>
              <span>${formatHours(entry.hours)}H</span>
            </div>`
                  )
                  .join("")
              : '<div class="dash-log-row empty">NO LOGS FOR THIS MONTH</div>';
          const logAction = client.canAddHours
            ? `<a class="dash-log-btn" href="/clients/${client.id}/entries/new">LOG HOURS</a>`
            : '<button class="dash-log-btn disabled" type="button" aria-disabled="true">LOG HOURS</button>';
          const lockNote = client.canAddHours
            ? ""
            : '<p class="dash-note">LOGGING DISABLED FOR THIS MONTH.</p>';
          return `<article class="dash-card${isOver ? " is-over-limit" : ""}" data-client-id="${client.id}">
      <div class="dash-card-header">
        <h2 class="dash-card-title">${escapeHtml(client.name)}</h2>
        <button class="dash-remove" type="button" data-remove-client="${client.id}">REMOVE</button>
      </div>
      <div class="dash-hours">
        <div class="dash-hour-box">
          USED
          <span class="value">${used}H</span>
        </div>
        <div class="dash-hour-box${remainingClass}">
          ${remainingTitle}
          <span class="value">${remainingLabel}</span>
        </div>
      </div>
      <div class="dash-progress">
        <div class="dash-progress-header">
          <span>PROGRESS</span>
          <span>${limit}H LIMIT</span>
        </div>
        <div class="dash-progress-track${progressClass}">
          <div class="dash-progress-fill" style="width: ${percent}%;"></div>
        </div>
      </div>
      ${logAction}
      ${lockNote}
      <div class="dash-logs">
        <div class="dash-logs-title">CURRENT MONTH LOGS</div>
        ${entriesHtml}
      </div>
    </article>`;
        })
        .join("")
    : `<div class="dash-empty">
        <p>NO CLIENTS YET.</p>
        <a class="dash-button" href="/clients/new">+ ADD CLIENT</a>
      </div>`;

  const removalScript = hasClients
    ? `<script>
      (function() {
        const grid = document.querySelector('.dashboard-grid');
        const buttons = document.querySelectorAll('[data-remove-client]');
        const toastContainer =
          document.querySelector('.toast-container') ||
          (() => {
            const el = document.createElement('div');
            el.className = 'toast-container';
            document.body.appendChild(el);
            return el;
          })();

        const showToast = (message, type) => {
          const toast = document.createElement('div');
          toast.className = 'toast' + (type === 'error' ? ' is-error' : ' is-success');
          toast.textContent = message;
          toastContainer.appendChild(toast);
          setTimeout(() => {
            toast.classList.add('is-fade');
            setTimeout(() => toast.remove(), 250);
          }, 2600);
        };

        const confirmRemove = (message) =>
          new Promise((resolve) => {
            const backdrop = document.createElement('div');
            backdrop.className = 'modal-backdrop';

            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.innerHTML = '<h3 class="modal-title">Confirm Removal</h3><p>' +
              message +
              '</p><div class="modal-actions">' +
              '<button type="button" class="cancel">Cancel</button>' +
              '<button type="button" class="confirm">Remove</button>' +
              '</div>';

            const cleanup = (result) => {
              backdrop.remove();
              resolve(result);
            };

            modal.querySelector('.cancel').addEventListener('click', () => cleanup(false));
            modal.querySelector('.confirm').addEventListener('click', () => cleanup(true));
            backdrop.addEventListener('click', (e) => {
              if (e.target === backdrop) cleanup(false);
            });

            backdrop.appendChild(modal);
            document.body.appendChild(backdrop);
          });

        const emptyMarkup =
          '<div class="dash-empty">' +
          '<p>NO CLIENTS YET.</p>' +
          '<a class="dash-button" href="/clients/new">+ ADD CLIENT</a>' +
          '</div>';

        const renderEmpty = () => {
          if (!grid) return;
          if (grid.children.length === 0) {
            grid.innerHTML = emptyMarkup;
          }
        };

        buttons.forEach((button) => {
          button.addEventListener('click', async () => {
            const clientId = button.getAttribute('data-remove-client');
            if (!clientId) return;
            const card = button.closest('[data-client-id]');
            const confirmMessage = 'Remove this client? All time entries will be deleted.';
            const confirmed = await confirmRemove(confirmMessage);
            if (!confirmed) return;
            button.disabled = true;
            button.textContent = 'REMOVING...';
            try {
              const response = await fetch('/clients/' + clientId, { method: 'DELETE' });
              const data = await response.json().catch(() => null);
              if (response.ok) {
                card && card.remove();
                renderEmpty();
                showToast((data && data.message) || 'Client removed.', 'success');
                return;
              }
              showToast((data && data.error) || 'Unable to remove client.', 'error');
            } catch (err) {
              showToast('Unable to remove client.', 'error');
            } finally {
              button.disabled = false;
              button.textContent = 'REMOVE';
            }
          });
        });
      })();
    </script>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "Client Status - Hourcrate",
  })}
</head>
<body class="dashboard-body">
  <main class="page dashboard-page">
    <header class="dash-header">
      <div class="dash-header-left">
        <h1 class="dash-title">CLIENT STATUS</h1>
        <p class="dash-subhead">VIEWING: ${monthText}</p>
      </div>
      <div class="dash-actions">
        <a class="dash-button" href="/clients/new">+ ADD CLIENT</a>
        <a class="dash-button" href="/export/current-month.csv">EXPORT CSV</a>
      </div>
    </header>

    <section class="dashboard-grid" aria-label="Client cards">
      ${cards}
    </section>
  </main>
  <div class="toast-container" aria-live="polite" aria-atomic="true"></div>
  ${removalScript}
</body>
</html>`;
}

function renderLoginPage(errorMessage, options = {}) {
  const showSignupLink = options.showSignupLink === true;
  const link = showSignupLink ? ' <a href="/signup">SIGN UP</a>' : "";
  const errorBlock = errorMessage
    ? `<p role="alert">${escapeHtml(errorMessage)}${link}</p>`
    : "";
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "LOGIN - HOURCRATE",
    description: "Sign in to Hourcrate.",
    canonical: "https://hourcrate.com/login",
    robots: "index, follow",
  })}
</head>
<body>
  <main class="page auth-page">
    <div class="form-wrapper">
      <h1>LOGIN</h1>
      ${errorBlock}
      <form action="/sessions" method="post">
        <div>
          <label for="email">EMAIL</label>
          <input type="email" id="email" name="email" required>
        </div>
        <div>
          <label for="password">PASSWORD</label>
          <input type="password" id="password" name="password" required>
        </div>
        <button type="submit">LOGIN</button>
      </form>
      <p class="oauth-link"><a href="/auth/google">LOGIN WITH GOOGLE</a></p>
    </div>
  </main>
</body>
</html>`;
}

function renderLoginResponse(res, statusCode, message) {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(statusCode).send(renderLoginPage(message));
}

function renderNewClientPage({ errorMessage, errorLink, values }) {
  const errorLinkHtml =
    errorMessage && errorLink?.href && errorLink?.text
      ? ` <a href="${escapeHtml(errorLink.href)}">${escapeHtml(
          errorLink.text
        )}</a>`
      : "";
  const errorBlock = errorMessage
    ? `<p role="alert">${escapeHtml(errorMessage)}${errorLinkHtml}</p>`
    : "";
  const nameValue = values?.name ? escapeHtml(values.name) : "";
  const limitValue = values?.monthly_hour_limit
    ? escapeHtml(values.monthly_hour_limit)
    : "";
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "NEW CLIENT",
  })}
</head>
<body>
  <main class="page">
    <h1>NEW CLIENT</h1>
    ${errorBlock}
    <form action="/clients" method="post">
      <div>
        <label for="name">CLIENT NAME</label>
        <input type="text" id="name" name="name" value="${nameValue}">
      </div>
      <div>
        <label for="monthly_hour_limit">MONTHLY LIMIT (HOURS)</label>
        <input type="number" id="monthly_hour_limit" name="monthly_hour_limit" step="0.25" value="${limitValue}">
      </div>
      <button type="submit">CREATE CLIENT</button>
    </form>
  </main>
</body>
</html>`;
}

function renderNewEntryPage({ client, errorMessage, values }) {
  const errorBlock = errorMessage
    ? `<p role="alert">${escapeHtml(errorMessage)}</p>`
    : "";
  const dateValue = values?.date ? escapeHtml(values.date) : "";
  const hoursValue = values?.hours ? escapeHtml(values.hours) : "";
  const clientName = client?.name ? escapeHtml(client.name) : "CLIENT";
  const clientId = client?.id;
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "ADD HOURS",
  })}
</head>
<body>
  <main class="page">
    <h1>ADD HOURS: ${clientName}</h1>
    ${errorBlock}
    <form action="/clients/${clientId}/entries" method="post">
      <div>
        <label for="date">DATE</label>
        <input type="date" id="date" name="date" value="${dateValue}">
      </div>
      <div>
        <label for="hours">HOURS</label>
        <input type="text" id="hours" name="hours" inputmode="decimal" value="${hoursValue}">
      </div>
      <button type="submit">LOG HOURS</button>
    </form>
  </main>
</body>
</html>`;
}

function renderNotFoundPage(message) {
  return `<!doctype html>
<html lang="en">
<head>
${renderBaseHead({
    title: "NOT FOUND",
  })}
</head>
<body>
  <main class="page text-page">
    <h1>NOT FOUND</h1>
    <p>${escapeHtml(message || "PAGE NOT FOUND")}</p>
  </main>
</body>
</html>`;
}

function formatHours(value) {
  if (Number.isInteger(value)) return String(value);
  return Number(value).toFixed(2).replace(/\.?0+$/, "");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderBaseHead(options = {}) {
  const title =
    typeof options.title === "string" && options.title ? options.title : "Hourcrate";
  const description =
    typeof options.description === "string" && options.description
      ? options.description
      : "";
  const canonical =
    typeof options.canonical === "string" && options.canonical ? options.canonical : "";
  const robots =
    typeof options.robots === "string" && options.robots ? options.robots : "";

  const headTags = [
    '<meta charset="UTF-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
    `<title>${escapeHtml(title)}</title>`,
  ];

  if (description) {
    headTags.push(`<meta name="description" content="${escapeHtml(description)}">`);
  }
  if (robots) {
    headTags.push(`<meta name="robots" content="${escapeHtml(robots)}">`);
  }
  if (canonical) {
    headTags.push(`<link rel="canonical" href="${escapeHtml(canonical)}">`);
  }

  headTags.push(
    '<meta name="application-name" content="Hourcrate">',
    '<meta name="apple-mobile-web-app-title" content="Hourcrate">',
    '<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">',
    '<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">',
    '<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">',
    '<link rel="shortcut icon" href="/favicon.ico">',
    '<link rel="manifest" href="/site.webmanifest">',
    '<link rel="mask-icon" href="/safari-pinned-tab.svg" color="#ccff00">',
    '<meta name="msapplication-TileColor" content="#ccff00">',
    '<meta name="msapplication-config" content="/browserconfig.xml">',
    '<meta name="theme-color" content="#ccff00">',
    '<link rel="stylesheet" href="/styles.css">'
  );

  return headTags.map((tag) => `  ${tag}`).join("\n");
}

function requestExpectsJson(req) {
  const accept = (req.headers.accept || "").toLowerCase();
  if (accept.includes("application/json")) return true;
  return Boolean(req.is && req.is("application/json"));
}

function requestExpectsHtml(req) {
  const accept = (req.headers.accept || "").toLowerCase();
  return accept.includes("text/html");
}

function resolveRedirectUri(baseUrl, redirectPath) {
  if (typeof redirectPath !== "string" || redirectPath.trim() === "") {
    throw new Error("GOOGLE_REDIRECT_PATH is required");
  }
  if (redirectPath.startsWith("http://") || redirectPath.startsWith("https://")) {
    return redirectPath;
  }
  return new URL(redirectPath, baseUrl).toString();
}

function getGoogleConfig(googleOverrides) {
  const clientId = googleOverrides.clientId || process.env.GOOGLE_CLIENT_ID;
  const clientSecret = googleOverrides.clientSecret || process.env.GOOGLE_CLIENT_SECRET;
  const baseUrl = googleOverrides.baseUrl || process.env.BASE_URL;
  const redirectPath =
    googleOverrides.redirectPath || process.env.GOOGLE_REDIRECT_PATH || "/auth/google/callback";
  const stateSecret =
    googleOverrides.stateSecret || process.env.SESSION_SECRET || clientSecret;

  if (!clientId || !clientSecret || !baseUrl || !stateSecret) {
    return null;
  }

  try {
    new URL(baseUrl);
  } catch {
    return null;
  }

  return {
    clientId,
    clientSecret,
    baseUrl,
    redirectPath,
    stateSecret,
    exchangeCodeForTokens: googleOverrides.exchangeCodeForTokens || exchangeCodeForTokens,
    verifyIdToken: googleOverrides.verifyIdToken || verifyIdToken,
  };
}

async function exchangeCodeForTokens({ code, clientId, clientSecret, redirectUri }) {
  const body = new URLSearchParams({
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  }).toString();
  const response = await httpsJsonRequest(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(body),
    },
  }, body);
  if (!response.body || typeof response.body.id_token !== "string") {
    throw new Error("Missing id_token in token response");
  }
  return response.body;
}

let cachedJwks = { keys: [], expiresAt: 0 };

async function getGoogleJwks() {
  const now = Date.now();
  if (cachedJwks.expiresAt > now && cachedJwks.keys.length > 0) {
    return cachedJwks;
  }
  const response = await httpsJsonRequest(GOOGLE_JWKS_URL, { method: "GET" });
  const cacheControl = response.headers["cache-control"] || "";
  const maxAgeMatch = /max-age=(\d+)/i.exec(cacheControl);
  const maxAgeSeconds = maxAgeMatch ? Number(maxAgeMatch[1]) : 300;
  cachedJwks = {
    keys: Array.isArray(response.body.keys) ? response.body.keys : [],
    expiresAt: now + maxAgeSeconds * 1000,
  };
  return cachedJwks;
}

async function verifyIdToken(idToken, clientId) {
  if (typeof idToken !== "string") {
    throw new Error("id_token missing");
  }
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid id_token format");
  }
  const [headerB64, payloadB64, signatureB64] = parts;
  const header = decodeBase64UrlJson(headerB64);
  const payload = decodeBase64UrlJson(payloadB64);
  if (header.alg !== "RS256" || !header.kid) {
    throw new Error("Unsupported id_token");
  }
  const now = Math.floor(Date.now() / 1000);
  if (!GOOGLE_ISSUERS.has(payload.iss)) {
    throw new Error("Invalid issuer");
  }
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(clientId)) {
    throw new Error("Invalid audience");
  }
  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw new Error("Expired id_token");
  }

  const jwks = await getGoogleJwks();
  const jwk = jwks.keys.find((key) => key.kid === header.kid);
  if (!jwk) {
    throw new Error("JWK not found");
  }
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const signedData = Buffer.from(`${headerB64}.${payloadB64}`);
  const signature = base64UrlToBuffer(signatureB64);
  const isValid = crypto.verify("RSA-SHA256", signedData, key, signature);
  if (!isValid) {
    throw new Error("Invalid id_token signature");
  }
  return {
    sub: payload.sub,
    email: payload.email,
    email_verified: payload.email_verified,
  };
}

function httpsJsonRequest(url, options = {}, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, options, (res) => {
      let raw = "";
      res.on("data", (chunk) => {
        raw += chunk;
      });
      res.on("end", () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`HTTP ${res.statusCode}`));
        }
        try {
          const parsed = raw ? JSON.parse(raw) : {};
          return resolve({ body: parsed, headers: res.headers });
        } catch (err) {
          return reject(err);
        }
      });
    });
    req.on("error", reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

let cachedApp;

async function handler(req, res) {
  if (!cachedApp) {
    // Lazy-load dependencies only once
    const { Pool } = require("pg");
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : false,
    });

    cachedApp = createApp(pool);
  }

  return cachedApp(req, res);
}

module.exports = handler;
module.exports.createApp = createApp;
module.exports.handler = handler;
