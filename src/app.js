const crypto = require("crypto");
const bcrypt = require("bcrypt");
const express = require("express");
const path = require("path");
const { authMiddleware, optionalAuthMiddleware } = require("./auth");

const SESSION_TTL_HOURS = 24 * 7;

function createApp(pool, config = {}) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(express.static(path.join(__dirname, "public")));

  const userTimeZone = config.userTimeZone || process.env.USER_TIMEZONE || "UTC";

  app.get("/", optionalAuthMiddleware(pool), (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res
      .status(200)
      .send(renderLandingPage({ isAuthenticated: Boolean(req.userId) }));
  });

  app.get("/pricing", optionalAuthMiddleware(pool), (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(
      renderInfoPage("Pricing", [
        "Free covers up to 2 clients and the current month view.",
        "Paid unlocks additional clients, past months, alerts, and CSV export.",
        "No payment is collected here yet; upgrade when available.",
      ])
    );
  });

  app.get("/upgrade", optionalAuthMiddleware(pool), (req, res) => {
    // Lemon Squeezy checkout will be integrated here
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(
      renderInfoPage("Upgrade to HourCrate Pro", [
        "Unlock unlimited clients, historical views, CSV exports, and alerts.",
        "Payments are coming soon.",
      ])
    );
  });

  app.get("/privacy", (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(
      renderInfoPage("Privacy", [
        "HourCrate stores account credentials and the retainer records you enter to provide the service.",
        "Session cookies are used only for authentication.",
        "This page loads without third-party trackers or analytics.",
      ])
    );
  });

  app.get("/terms", (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(
      renderInfoPage("Terms", [
        "Use HourCrate to manage retainer limits for clients you are authorized to serve.",
        "You are responsible for the accuracy of hours entered and any exports you share.",
        "The service is provided as-is; keep your credentials secure.",
      ])
    );
  });

  app.get("/login", optionalAuthMiddleware(pool), (req, res) => {
    if (req.userId) {
      return res.redirect("/dashboard");
    }
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(renderLoginPage());
  });

  app.post("/users", optionalAuthMiddleware(pool), async (req, res) => {
    // Single-operator: allow creation only if no users exist.
    const { email, password } = req.body || {};
    if (typeof email !== "string" || !email.trim()) {
      return res.status(400).json({ error: "email is required" });
    }
    if (typeof password !== "string" || password.length < 8) {
      return res
        .status(400)
        .json({ error: "password must be at least 8 characters" });
    }

    const existing = await pool.query("SELECT id FROM users LIMIT 1");
    if (existing.rowCount > 0) {
      return res
        .status(409)
        .json({ error: "User already exists; multi-user is out of scope" });
    }

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
      [email.trim(), hash]
    );
    return res.status(201).json({ id: result.rows[0].id, email: result.rows[0].email });
  });

  app.post("/sessions", async (req, res) => {
    const { email, password } = req.body || {};
    const prefersJson = requestExpectsJson(req);
    const prefersHtml = requestExpectsHtml(req) && !prefersJson;

    if (typeof email !== "string" || typeof password !== "string") {
      if (prefersHtml) {
        return renderLoginResponse(res, 400, "Email and password are required");
      }
      return res.status(400).json({ error: "email and password are required" });
    }
    const userResult = await pool.query(
      "SELECT id, password_hash FROM users WHERE email = $1",
      [email.trim()]
    );
    if (userResult.rowCount === 0) {
      if (prefersHtml) {
        return renderLoginResponse(res, 401, "Invalid credentials");
      }
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const user = userResult.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      if (prefersHtml) {
        return renderLoginResponse(res, 401, "Invalid credentials");
      }
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + SESSION_TTL_HOURS * 3600 * 1000);
    await pool.query(
      "INSERT INTO sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)",
      [user.id, token, expiresAt]
    );
    res.cookie("session_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      expires: expiresAt,
    });
    if (prefersHtml) {
      return res.redirect("/dashboard");
    }
    return res.status(201).json({ ok: true });
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

    const errors = [];
    if (typeof name !== "string" || !name.trim()) {
      errors.push("name is required");
    }
    const parsedLimit = Number(monthly_hour_limit);
    if (Number.isNaN(parsedLimit)) {
      errors.push("monthly_hour_limit must be a number");
    } else if (!Number.isFinite(parsedLimit) || parsedLimit <= 0) {
      errors.push("monthly_hour_limit must be greater than zero");
    } else if (!hasAtMostTwoDecimals(parsedLimit)) {
      errors.push("monthly_hour_limit must have at most two decimal places");
    } else if (parsedLimit > 9999999.99) {
      errors.push("monthly_hour_limit exceeds DECIMAL(9,2) range");
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
      const countResult = await pool.query("SELECT COUNT(*) AS count FROM clients");
      const clientCount = Number(countResult.rows[0].count || 0);
      if (clientCount >= 2) {
        const limitMessage =
          "Free accounts are limited to 2 clients. Upgrade to add more.";
        if (prefersHtml) {
          res.setHeader("Content-Type", "text/html; charset=utf-8");
          return res.status(403).send(
            renderNewClientPage({
              errorMessage: `${limitMessage} <a href="/upgrade">Upgrade</a>`,
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
      "INSERT INTO clients (name) VALUES ($1) RETURNING id, name";
    const retainerInsert =
      "INSERT INTO retainers (client_id, monthly_hour_limit) VALUES ($1, $2)";

    try {
      await pool.query("BEGIN");
      const clientResult = await pool.query(clientInsert, [clientName]);
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
            errorMessage: "Internal error",
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
    if (!Number.isInteger(clientId) || clientId <= 0) {
      return res.status(400).json({ error: "Invalid client id" });
    }

    const clientResult = await pool.query(
      "SELECT id FROM clients WHERE id = $1",
      [clientId]
    );
    if (clientResult.rowCount === 0) {
      return res.status(404).json({ error: "Client not found" });
    }

    const entry = await pool.query(
      "SELECT id FROM time_entries WHERE client_id = $1 LIMIT 1",
      [clientId]
    );
    if (entry.rowCount > 0) {
      return res
        .status(409)
        .json({ error: "Client has time entries and cannot be deleted" });
    }

    try {
      await pool.query("BEGIN");
      await pool.query("DELETE FROM retainers WHERE client_id = $1", [
        clientId,
      ]);
      await pool.query("DELETE FROM clients WHERE id = $1", [clientId]);
      await pool.query("COMMIT");
      return res.status(204).send();
    } catch (err) {
      await pool.query("ROLLBACK");
      console.error(err);
      return res.status(500).json({ error: "Internal error" });
    }
  });

  app.get("/clients", async (req, res) => {
    const today = getTodayParts(userTimeZone);
    const monthRange = getMonthDateRange(today.year, today.month);
    const data = await fetchClientSummaries(pool, monthRange);
    return res.json({ clients: data });
  });

  app.get("/dashboard", async (req, res) => {
    const hasMonthParam =
      typeof req.query.month === "string" && req.query.month !== "";
    const monthParam = parseMonthParam(req.query.month);
    if (hasMonthParam && !monthParam) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(400).send(renderNotFoundPage("Invalid month format"));
    }

    const today = getTodayParts(userTimeZone);
    const targetMonth = monthParam || { year: today.year, month: today.month };
    const isPaidUser = req.user?.isPaid === true;

    const requestedMonthIsCurrent =
      targetMonth.year === today.year && targetMonth.month === today.month;

    if (!isPaidUser && monthParam && !requestedMonthIsCurrent) {
      const message = "Viewing past months requires a paid plan.";
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res
        .status(403)
        .send(renderPlainMessagePage(message, { includeUpgrade: true }));
    }

    const monthRange = getMonthDateRange(targetMonth.year, targetMonth.month);
    const clients = await fetchClientSummaries(pool, monthRange, {
      includeAlerts: isPaidUser && requestedMonthIsCurrent,
      isCurrentMonth: requestedMonthIsCurrent,
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
      const message = "CSV export requires a paid plan.";
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
    const clients = await fetchClientSummaries(pool, monthRange);
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
      return res.status(400).send(renderNotFoundPage("Invalid client id"));
    }

    const clientResult = await pool.query(
      "SELECT id, name FROM clients WHERE id = $1",
      [clientId]
    );
    if (clientResult.rowCount === 0) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(404).send(renderNotFoundPage("Client not found"));
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
      errors.push("date must be YYYY-MM-DD");
    }

    const parsedHours = Number(hours);
    if (Number.isNaN(parsedHours)) {
      errors.push("hours must be a number");
    } else if (!Number.isFinite(parsedHours) || parsedHours <= 0) {
      errors.push("hours must be greater than zero");
    } else if (!hasAtMostTwoDecimals(parsedHours)) {
      errors.push("hours must have at most two decimal places");
    } else if (parsedHours > 9999999.99) {
      errors.push("hours exceeds DECIMAL(9,2) range");
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
        errors.push("date must be within the current month");
      } else if (parsedDate.day > today.day) {
        errors.push("date cannot be in the future");
      } else if (
        parsedDate.day < currentMonthRange.startDay ||
        parsedDate.day > currentMonthRange.endDay
      ) {
        errors.push("invalid day for month");
      }
    }

    if (errors.length > 0) {
      if (prefersHtml) {
        const clientResult = await pool.query(
          "SELECT id, name FROM clients WHERE id = $1",
          [clientId]
        );
        if (clientResult.rowCount === 0) {
          res.setHeader("Content-Type", "text/html; charset=utf-8");
          return res.status(404).send(renderNotFoundPage("Client not found"));
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
      "SELECT id FROM clients WHERE id = $1",
      [clientId]
    );
    if (clientResult.rowCount === 0) {
      if (prefersHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(404).send(renderNotFoundPage("Client not found"));
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
          "SELECT id, name FROM clients WHERE id = $1",
          [clientId]
        );
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.status(500).send(
          renderNewEntryPage({
            errorMessage: "Internal error",
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
  const isCurrentMonth = options.isCurrentMonth === true;
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
     GROUP BY c.id, c.name, r.monthly_hour_limit
     ORDER BY c.id ASC`,
    [monthRange.startDate, monthRange.nextMonthStart]
  );
  return result.rows.map((row) => {
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
}

function renderLandingPage(options = {}) {
  const isAuthenticated = options.isAuthenticated === true;
  const startHref = isAuthenticated ? "/dashboard" : "/login";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HourCrate | Retainer hours, contained</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body class="landing-body">
  <main class="page landing">
    <header class="hero">
      <h1 class="hero-title">Never give away retainer hours again.</h1>
      <p class="hero-subhead">HourCrate shows you-clearly and in real time-when you're approaching or exceeding your monthly client limits.</p>
      <div class="cta-row">
        <a class="cta-primary" href="${startHref}">Start using HourCrate</a>
        <a class="cta-secondary" href="/login">Sign in</a>
      </div>
    </header>

    <section class="section">
      <h2>How it works</h2>
      <ul class="plain-list">
        <li>Set a monthly hour limit per client</li>
        <li>Log hours as you work</li>
        <li>See when you're nearing or over the limit</li>
      </ul>
    </section>

    <section class="section">
      <h2>Who it's for</h2>
      <p>Designed for consultants, freelancers, and small agencies who work on retainers and want a single source of truth for monthly hours.</p>
    </section>

    <section class="section pricing">
      <p class="pricing-note">Free for small setups. Paid plans unlock alerts, exports, and history.</p>
    </section>
  </main>

  <footer class="footer">
    <a href="/login">Sign in</a>
    <span class="separator" aria-hidden="true">/</span>
    <a href="/privacy">Privacy</a>
    <span class="separator" aria-hidden="true">/</span>
    <a href="/terms">Terms</a>
  </footer>
</body>
</html>`;
}

function renderPlainMessagePage(message, options = {}) {
  const includeUpgrade = options.includeUpgrade === true;
  const upgradeLink = includeUpgrade ? ' <a href="/upgrade">Upgrade</a>' : "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HourCrate</title>
  <link rel="stylesheet" href="/styles.css">
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
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - HourCrate</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main class="page text-page">
    <h1>${escapeHtml(title)}</h1>
    ${body}
  </main>
</body>
</html>`;
}

function renderDashboardPage(clients, options = {}) {
  const isCurrentMonth = options.isCurrentMonth === true;
  const monthLabel = options.monthLabel || "";
  const rows = clients
    .map((client) => {
      const limit = formatHours(client.monthly_hour_limit);
      const used = formatHours(client.hours_used);
      const isOver = client.hours_remaining < 0;
      const remainingValue = isOver
        ? formatHours(Math.abs(client.hours_remaining))
        : formatHours(client.hours_remaining);
      const remainingText = isOver
        ? `${remainingValue} hours over`
        : `${remainingValue} hours remaining`;
      const remainingClass = isOver ? ' class="overage"' : "";
      const approaching =
        isCurrentMonth &&
        client.alertStatus === "warning" &&
        client.hours_remaining >= 0;
      const warningText = approaching ? '<div>Approaching limit</div>' : "";
      const hoursCell = `${remainingText}${warningText}`;
      return `<tr>
  <td>${escapeHtml(client.name)}${
        client.canAddHours
          ? ` <a href="/clients/${client.id}/entries/new">Add hours</a>`
          : ""
      }</td>
  <td>${limit}</td>
  <td>${used}</td>
  <td${remainingClass}>${hoursCell}</td>
</tr>`;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HourCrate Dashboard</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main class="page">
    <h1>Monthly Hours (<a href="/clients/new">Add client</a>) (<a href="/export/current-month.csv">Export current month (CSV)</a>)</h1>
    <p>Viewing: ${escapeHtml(monthLabel)}</p>
    <table class="hours-table">
      <thead>
        <tr>
          <th scope="col">Client</th>
          <th scope="col">Monthly limit</th>
          <th scope="col">Hours used</th>
          <th scope="col">Hours remaining</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </main>
</body>
</html>`;
}

function renderLoginPage(errorMessage) {
  const errorBlock = errorMessage
    ? `<p role="alert">${escapeHtml(errorMessage)}</p>`
    : "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HourCrate Login</title>
</head>
<body>
  <main>
    <h1>Sign in</h1>
    ${errorBlock}
    <form action="/sessions" method="post">
      <div>
        <label for="email">Email</label>
        <input type="email" id="email" name="email" required>
      </div>
      <div>
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">Log in</button>
    </form>
  </main>
</body>
</html>`;
}

function renderLoginResponse(res, statusCode, message) {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(statusCode).send(renderLoginPage(message));
}

function renderNewClientPage({ errorMessage, values }) {
  const errorBlock = errorMessage
    ? `<p role="alert">${escapeHtml(errorMessage)}</p>`
    : "";
  const nameValue = values?.name ? escapeHtml(values.name) : "";
  const limitValue = values?.monthly_hour_limit
    ? escapeHtml(values.monthly_hour_limit)
    : "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>New Client</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main class="page">
    <h1>New Client</h1>
    ${errorBlock}
    <form action="/clients" method="post">
      <div>
        <label for="name">Client name</label>
        <input type="text" id="name" name="name" value="${nameValue}">
      </div>
      <div>
        <label for="monthly_hour_limit">Monthly hour limit</label>
        <input type="number" id="monthly_hour_limit" name="monthly_hour_limit" step="0.25" value="${limitValue}">
      </div>
      <button type="submit">Create client</button>
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
  const clientName = client?.name ? escapeHtml(client.name) : "Client";
  const clientId = client?.id;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Add Hours</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main class="page">
    <h1>Add Hours: ${clientName}</h1>
    ${errorBlock}
    <form action="/clients/${clientId}/entries" method="post">
      <div>
        <label for="date">Date</label>
        <input type="date" id="date" name="date" value="${dateValue}">
      </div>
      <div>
        <label for="hours">Hours</label>
        <input type="text" id="hours" name="hours" inputmode="decimal" value="${hoursValue}">
      </div>
      <button type="submit">Add hours</button>
    </form>
  </main>
</body>
</html>`;
}

function renderNotFoundPage(message) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Not found</title>
</head>
<body>
  <main>
    <p>${escapeHtml(message || "Not found")}</p>
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

function requestExpectsJson(req) {
  const accept = (req.headers.accept || "").toLowerCase();
  if (accept.includes("application/json")) return true;
  return Boolean(req.is && req.is("application/json"));
}

function requestExpectsHtml(req) {
  const accept = (req.headers.accept || "").toLowerCase();
  return accept.includes("text/html");
}

module.exports = { createApp };
