function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  return header.split(";").reduce((acc, pair) => {
    const [k, v] = pair.split("=").map((s) => s.trim());
    if (k && v) acc[k] = decodeURIComponent(v);
    return acc;
  }, {});
}

function authMiddleware(pool) {
  return async function (req, res, next) {
    const cookies = parseCookies(req);
    const token = cookies["session_token"];
    if (!token) {
      return handleUnauthenticated(req, res);
    }
    const result = await pool.query(
      `SELECT u.id AS user_id, u.is_paid
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.session_token = $1 AND s.expires_at > now()`,
      [token]
    );
    if (result.rowCount === 0) {
      return handleUnauthenticated(req, res);
    }
    req.userId = result.rows[0].user_id;
    req.user = {
      id: result.rows[0].user_id,
      isPaid: result.rows[0].is_paid === true,
    };
    return next();
  };
}

function optionalAuthMiddleware(pool) {
  return async function (req, res, next) {
    const cookies = parseCookies(req);
    const token = cookies["session_token"];
    if (!token) return next();
    const result = await pool.query(
      `SELECT u.id AS user_id, u.is_paid
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.session_token = $1 AND s.expires_at > now()`,
      [token]
    );
    if (result.rowCount > 0) {
      req.userId = result.rows[0].user_id;
      req.user = {
        id: result.rows[0].user_id,
        isPaid: result.rows[0].is_paid === true,
      };
    }
    return next();
  };
}

function handleUnauthenticated(req, res) {
  if (requestExpectsHtml(req)) {
    return res.redirect("/login");
  }
  if (requestExpectsJson(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  return res.status(401).json({ error: "Unauthorized" });
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

module.exports = { authMiddleware, optionalAuthMiddleware };
