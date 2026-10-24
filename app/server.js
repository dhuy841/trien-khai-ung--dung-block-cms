const crypto = require("node:crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");
const promClient = require("prom-client");
const nodemailer = require("nodemailer");
const multer = require("multer");

const required = ["DB_PASSWORD", "SESSION_SECRET", "ADMIN_PASSWORD"];
for (const name of required) {
  if (!process.env[name]) throw new Error(`${name} must be set`);
}
if (Buffer.byteLength(process.env.SESSION_SECRET) < 32) {
  throw new Error("SESSION_SECRET must contain at least 32 bytes");
}
if (process.env.ADMIN_PASSWORD.length < 12) {
  throw new Error("ADMIN_PASSWORD must contain at least 12 characters");
}

const app = express();
const pool = mysql.createPool({
  host: process.env.DB_HOST || "db",
  user: process.env.DB_USER || "blog_app",
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "blog",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });
const httpRequests = new promClient.Counter({
  name: "http_requests_total",
  help: "Total HTTP requests handled by the CMS",
  labelNames: ["method", "route", "status"],
  registers: [register]
});
const passwordResetRequests = new Map();
const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024, files: 1, fields: 20 },
  fileFilter: (req, file, callback) => {
    if (!["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)) {
      return callback(new Error("Only JPEG, PNG, and WebP profile images are allowed"));
    }
    callback(null, true);
  }
});
let mailTransport;

app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
app.use(express.static("public", { maxAge: 0, index: false }));
app.use((req, res, next) => {
  const started = process.hrtime.bigint();
  res.on("finish", () => {
    const route = req.route?.path ? `${req.baseUrl}${req.route.path}` : "unmatched";
    httpRequests.inc({ method: req.method, route, status: String(res.statusCode) });
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      level: "info",
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration_ms: Number(process.hrtime.bigint() - started) / 1e6
    }));
  });
  next();
});

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function avatarMarkup(user, sizeClass = "") {
  const initial = escapeHtml((user.username || "?").slice(0, 1).toUpperCase());
  const image = user.avatar || user.avatar_mime
    ? '<img src="/profile/avatar" alt="" loading="lazy">'
    : initial;
  return `<span class="profile-avatar ${sizeClass}">${image}</span>`;
}

function detectAvatarMime(buffer) {
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return "image/jpeg";
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "image/png";
  if (buffer.length >= 12 && buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP") return "image/webp";
  return null;
}

function sign(value) {
  return crypto.createHmac("sha256", process.env.SESSION_SECRET).update(value).digest("base64url");
}

function readSession(req) {
  const token = req.get("cookie")?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("blog_session="))?.slice("blog_session=".length);
  if (!token) return null;
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return null;
  const expected = sign(payload);
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(actualBuffer, expectedBuffer)) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return session.exp > Date.now() ? session : null;
  } catch (error) {
    console.warn(JSON.stringify({ level: "warn", message: "Invalid session cookie", error: error.message }));
    return null;
  }
}

function setSession(res, user) {
  const payload = Buffer.from(JSON.stringify({
    id: user.id,
    username: user.username,
    role: user.role,
    avatar: Boolean(user.avatar || user.avatar_mime),
    csrf: crypto.randomBytes(24).toString("hex"),
    exp: Date.now() + 8 * 60 * 60 * 1000
  })).toString("base64url");
  const secure = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `blog_session=${payload}.${sign(payload)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
}

function clearSession(res) {
  res.setHeader("Set-Cookie", "blog_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
}

function requireUser(req, res, next) {
  req.user = readSession(req);
  if (!req.user) return res.redirect("/login");
  next();
}

function parseAvatarUpload(req, res, next) {
  avatarUpload.single("avatar")(req, res, (error) => {
    if (!error) return next();
    if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
      return res.status(413).send(page("Ảnh quá lớn", '<p class="error form-alert">Ảnh hồ sơ cần có dung lượng không quá 2 MB.</p><p><a class="button button-outline" href="/profile">Quay lại hồ sơ</a></p>', req.user));
    }
    if (error instanceof multer.MulterError || error.message === "Only JPEG, PNG, and WebP profile images are allowed") {
      return res.status(400).send(page("Ảnh không hợp lệ", '<p class="error form-alert">Chỉ hỗ trợ ảnh JPEG, PNG hoặc WebP, tối đa 2 MB.</p><p><a class="button button-outline" href="/profile">Quay lại hồ sơ</a></p>', req.user));
    }
    next(error);
  });
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).send(page("Không có quyền", "<p>Bạn không có quyền thực hiện thao tác này.</p>"));
  next();
}

function requireCsrf(req, res, next) {
  const session = req.user || readSession(req);
  if (!session || typeof req.body.csrf !== "string" || req.body.csrf !== session.csrf) {
    return res.status(403).send(page("Yêu cầu không hợp lệ", "<p>Token bảo vệ biểu mẫu không hợp lệ. Hãy tải lại trang.</p>"));
  }
  next();
}

function issueFormCsrf(res) {
  const nonce = crypto.randomBytes(24).toString("hex");
  const token = `${nonce}.${sign(`form:${nonce}`)}`;
  const secure = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  res.append("Set-Cookie", `blog_csrf=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900${secure}`);
  return `<input type="hidden" name="csrf" value="${escapeHtml(token)}">`;
}

function requireFormCsrf(req, res, next) {
  const cookie = req.get("cookie")?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("blog_csrf="))?.slice("blog_csrf=".length);
  const token = req.body.csrf;
  if (typeof token !== "string" || token !== cookie) {
    return res.status(403).send(page("Yêu cầu không hợp lệ", '<p class="error form-alert">Biểu mẫu đã hết hạn. Hãy tải lại trang và thử lại.</p>'));
  }
  const [nonce, signature] = token.split(".");
  if (!nonce || !signature) return res.status(403).send(page("Yêu cầu không hợp lệ", "<p>Token biểu mẫu không hợp lệ.</p>"));
  const actual = Buffer.from(signature);
  const expected = Buffer.from(sign(`form:${nonce}`));
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    return res.status(403).send(page("Yêu cầu không hợp lệ", "<p>Token biểu mẫu không hợp lệ.</p>"));
  }
  next();
}

function validEmail(value) {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validBirthDate(value) {
  if (!value) return true;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.valueOf()) &&
    date.toISOString().slice(0, 10) === value &&
    date <= new Date(new Date().toISOString().slice(0, 10));
}

function resetCodeHash(userId, code) {
  return crypto.createHmac("sha256", process.env.SESSION_SECRET)
    .update(`password-reset:${userId}:${code}`)
    .digest("hex");
}

function resetRequestAllowed(req) {
  const address = req.get("x-real-ip") || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const recent = (passwordResetRequests.get(address) || []).filter((time) => now - time < windowMs);
  if (recent.length >= 3) {
    passwordResetRequests.set(address, recent);
    return false;
  }
  recent.push(now);
  passwordResetRequests.set(address, recent);
  if (passwordResetRequests.size > 1000) {
    for (const [key, times] of passwordResetRequests) {
      if (!times.some((time) => now - time < windowMs)) passwordResetRequests.delete(key);
    }
  }
  return true;
}

function getMailTransport() {
  const user = process.env.SMTP_USER;
  const password = process.env.SMTP_PASS;
  if (!user || !password || password.startsWith("REPLACE_")) return null;
  if (!mailTransport) {
    mailTransport = nodemailer.createTransport({
      host: process.env.SMTP_HOST || "smtp.gmail.com",
      port: Number(process.env.SMTP_PORT || 465),
      secure: process.env.SMTP_SECURE !== "false",
      auth: { user, pass: password }
    });
  }
  return mailTransport;
}

function page(title, body, user = null, showRegister = true) {
  const links = user
    ? `<a class="nav-link" href="/">Bài viết</a><a class="nav-link" href="/admin">Quản trị</a>${user.role === "admin" ? '<a class="nav-link" href="/admin/users">Tài khoản</a>' : ""}<details class="profile-menu"><summary class="profile-trigger" aria-label="Tùy chọn tài khoản">${avatarMarkup(user)}<span class="profile-trigger-name">${escapeHtml(user.username)}</span><span class="profile-chevron" aria-hidden="true">⌄</span></summary><div class="profile-dropdown"><p>Đang đăng nhập<br><strong>${escapeHtml(user.username)}</strong></p><a href="/profile">Hồ sơ cá nhân</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="${escapeHtml(user.csrf)}"><button class="button button-outline button-small" type="submit">Đăng xuất</button></form></div></details>`
    : `<a class="nav-link" href="/">Bài viết</a>${showRegister ? '<a class="nav-link" href="/register">Tạo tài khoản</a>' : ""}<a class="button button-primary button-small" href="/login">Đăng nhập <span aria-hidden="true">→</span></a>`;
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#10251f"><meta name="description" content="Blog CMS - góc chia sẻ kiến thức và ý tưởng."><title>${escapeHtml(title)} | Blog CMS</title><link rel="stylesheet" href="/style.css?v=20261024-7"></head><body><header class="site-header"><div class="header-inner"><a class="brand" href="/" aria-label="Blog CMS - trang chủ"><span class="brand-mark">B</span><span>blog<span class="brand-accent">folio</span><small>STORIES & IDEAS</small></span></a><nav class="site-nav" aria-label="Điều hướng chính">${links}</nav></div></header><main class="page-shell"><div class="page-heading"><p class="eyebrow">BLOG CMS <span></span> KHÔNG GIAN CHIA SẺ</p><h1>${escapeHtml(title)}</h1></div>${body}</main><footer class="site-footer"><div class="footer-inner"><a class="brand footer-brand" href="/"><span class="brand-mark">B</span><span>blog<span class="brand-accent">folio</span><small>STORIES & IDEAS</small></span></a><p>Ý tưởng hay xứng đáng được sẻ chia.</p><span>Blog CMS · MySQL · Docker</span></div></footer><script src="/password-strength.js?v=2" defer></script></body></html>`;
}

function formField(label, name, value = "", type = "text", required = true, attributes = "") {
  const passwordRules = type === "password"
    ? name === "current_password" ? ' autocomplete="current-password"' : ' minlength="12" autocomplete="new-password"'
    : "";
  const emailRules = type === "email" ? ' maxlength="254" autocomplete="email" autocapitalize="none"': "";
  const input = `<input type="${type}" name="${escapeHtml(name)}" value="${escapeHtml(value)}"${required ? " required" : ""}${passwordRules}${emailRules}${attributes ? ` ${attributes}` : ""}>`;
  if (type !== "password") return `<label>${escapeHtml(label)}${input}</label>`;
  return `<label>${escapeHtml(label)}<span class="password-input-wrap">${input}<button class="password-toggle" type="button" data-password-toggle aria-label="Hiện mật khẩu" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg></button></span></label>`;
}

function passwordStrengthMeter() {
  return '<div class="password-strength" data-password-strength-meter><div class="password-strength-heading"><span>Độ mạnh mật khẩu</span><span data-strength-value>0%</span></div><div class="password-strength-track" role="progressbar" aria-label="Độ mạnh mật khẩu" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><span data-strength-bar></span></div><ul class="password-strength-rules"><li data-rule="uppercase">Có chữ cái viết hoa</li><li data-rule="length">Có ít nhất 12 ký tự</li><li data-rule="number">Có chữ số</li><li data-rule="special">Có ký tự đặc biệt (@#$&amp;*...)</li></ul></div>';
}

function isStrongPassword(password) {
  return password.length >= 12 &&
    /\p{Lu}/u.test(password) &&
    /\p{N}/u.test(password) &&
    /[\p{P}\p{S}]/u.test(password);
}

function csrfField(user) {
  return `<input type="hidden" name="csrf" value="${escapeHtml(user.csrf)}">`;
}

function slugify(value) {
  return value.normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 180);
}

app.get("/healthz", async (req, res) => {
  await pool.query("SELECT 1");
  res.status(200).send("ok");
});

app.get("/metrics", async (req, res) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

app.get("/", async (req, res) => {
  const [posts] = await pool.execute(
    `SELECT p.id, p.title, p.slug, p.excerpt, p.created_at, u.username, c.name AS category
     FROM posts p JOIN users u ON u.id = p.author_id
     LEFT JOIN categories c ON c.id = p.category_id
     WHERE p.status = 'published' ORDER BY p.created_at DESC`
  );
  const cards = posts.map((post, index) =>
    `<article class="post-card"><div class="post-card-top"><span class="category-chip">${escapeHtml(post.category || "Chưa phân loại")}</span><span class="post-number">${String(index + 1).padStart(2, "0")}</span></div><h2><a href="/posts/${encodeURIComponent(post.slug)}">${escapeHtml(post.title)}</a></h2><p class="post-excerpt">${escapeHtml(post.excerpt || "")}</p><div class="post-card-footer"><span>${escapeHtml(post.username)}</span><time datetime="${new Date(post.created_at).toISOString()}">${new Date(post.created_at).toLocaleDateString("vi-VN")}</time><a class="read-more" href="/posts/${encodeURIComponent(post.slug)}" aria-label="Đọc ${escapeHtml(post.title)}">Đọc bài <span aria-hidden="true">↗</span></a></div></article>`
  ).join("") || '<div class="empty-state"><span class="empty-icon">✦</span><h2>Chưa có bài viết nào</h2><p>Hãy đăng nhập quản trị để chia sẻ bài viết đầu tiên.</p><a class="button button-primary" href="/login">Đăng nhập quản trị <span aria-hidden="true">→</span></a></div>';
  const hero = `<section class="hero"><div class="hero-copy"><p class="hero-kicker"><span class="status-dot"></span> MỘT GÓC NHỎ CHO NHỮNG Ý TƯỞNG LỚN</p><h2>Đọc để khám phá.<br><em>Viết để sẻ chia.</em></h2><p class="hero-description">Những câu chuyện, góc nhìn và kiến thức được chọn lọc — dành cho người luôn tò mò về thế giới.</p><a class="button button-light" href="#bai-viet">Khám phá bài viết <span aria-hidden="true">↓</span></a></div><div class="hero-art" aria-hidden="true"><div class="art-orbit orbit-one"></div><div class="art-orbit orbit-two"></div><div class="art-sun"></div><div class="art-leaf leaf-one"></div><div class="art-leaf leaf-two"></div><div class="art-label">READ<br>MORE<br><span>✳</span></div><div class="art-caption">A little space<br>for big thoughts</div></div><div class="hero-index">01 <span>/ BLOG JOURNAL</span></div></section><section class="posts-section" id="bai-viet"><div class="section-heading"><div><p class="eyebrow">TỪ CỘNG ĐỒNG</p><h2>Mới trên blog <span>✳</span></h2></div><p class="section-note">Góc nhìn mới, ý tưởng mới<br>được cập nhật thường xuyên.</p></div><div class="post-grid">${cards}</div></section>`;
  res.send(page("Góc đọc của bạn", hero, readSession(req)));
});

app.get("/posts/:slug", async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT p.title, p.body, p.created_at, u.username, c.name AS category
     FROM posts p JOIN users u ON u.id = p.author_id
     LEFT JOIN categories c ON c.id = p.category_id
     WHERE p.slug = ? AND p.status = 'published' LIMIT 1`,
    [req.params.slug]
  );
  if (!rows.length) return res.status(404).send(page("Không tìm thấy bài viết", "<p>Bài viết không tồn tại hoặc chưa được xuất bản.</p>", readSession(req)));
  const post = rows[0];
  res.send(page(post.title, `<article class="article-detail"><div class="article-meta"><span class="category-chip">${escapeHtml(post.category || "Chưa phân loại")}</span><span>${escapeHtml(post.username)}</span><time datetime="${new Date(post.created_at).toISOString()}">${new Date(post.created_at).toLocaleDateString("vi-VN")}</time></div><div class="content">${escapeHtml(post.body).replace(/\n/g, "<br>")}</div><a class="back-link" href="/">← Quay lại bài viết</a></article>`, readSession(req)));
});

app.get("/login", (req, res) => {
  const notice = req.query["password-reset"] === "1"
    ? '<p class="success form-alert">Đổi mật khẩu thành công. Hãy đăng nhập bằng mật khẩu mới.</p>'
    : "";
  const body = `<section class="auth-layout"><div class="auth-aside"><span class="auth-aside-mark">✳</span><p class="eyebrow">CHÀO MỪNG TRỞ LẠI</p><h2>Tiếp tục câu chuyện của bạn.</h2><p>Đăng nhập để quản lý bài viết và chia sẻ những ý tưởng mới.</p></div><div class="auth-card"><p class="eyebrow">KHU VỰC QUẢN TRỊ</p><h2>Đăng nhập</h2>${notice}<p class="muted">Nhập thông tin tài khoản để tiếp tục.</p><form method="post" action="/login" class="form-stack">${formField("Tên đăng nhập", "username")} ${formField("Mật khẩu", "password", "", "password")}<button class="button button-primary button-wide" type="submit">Đăng nhập <span aria-hidden="true">→</span></button></form><div class="auth-links"><a href="/forgot-password">Quên mật khẩu?</a><span>Không có liên kết đăng ký trên trang đăng nhập.</span></div></div></section>`;
  res.send(page("Đăng nhập CMS", body, null, false));
});

app.get("/register", (req, res) => {
  const csrf = issueFormCsrf(res);
  const body = `<section class="auth-layout"><div class="auth-aside"><span class="auth-aside-mark">✳</span><p class="eyebrow">BẮT ĐẦU HÀNH TRÌNH</p><h2>Mỗi tài khoản, một góc nhìn mới.</h2><p>Tạo tài khoản để tham gia cộng đồng và bắt đầu chia sẻ câu chuyện của bạn.</p></div><div class="auth-card"><p class="eyebrow">THAM GIA BLOGFOLIO</p><h2>Tạo tài khoản</h2><p class="muted">Email được dùng để khôi phục tài khoản khi cần.</p><form method="post" action="/register" class="form-stack">${csrf}${formField("Tên đăng nhập (3–50 ký tự)", "username")}${formField("Địa chỉ Gmail / email", "email", "", "email")}${formField("Ngày sinh (không bắt buộc)", "birth_date", "", "date", false)}${formField("Mật khẩu mới", "password", "", "password", true, 'data-password-strength')}${passwordStrengthMeter()}${formField("Nhập lại mật khẩu", "password_confirm", "", "password")}<button class="button button-primary button-wide" type="submit">Tạo tài khoản <span aria-hidden="true">→</span></button></form><p class="auth-footnote">Đã có tài khoản? <a href="/login">Đăng nhập</a></p></div></section>`;
  res.send(page("Tạo tài khoản", body));
});

app.post("/register", requireFormCsrf, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const birthDate = String(req.body.birth_date || "");
  const password = String(req.body.password || "");
  const passwordConfirm = String(req.body.password_confirm || "");
  if (!/^[a-zA-Z0-9_.-]{3,50}$/.test(username) || !validEmail(email) ||
      !validBirthDate(birthDate) || !isStrongPassword(password) || password !== passwordConfirm) {
    return res.status(400).send(page("Tạo tài khoản", `<section class="auth-layout"><div class="auth-aside"><span class="auth-aside-mark">✳</span><p class="eyebrow">BẮT ĐẦU HÀNH TRÌNH</p><h2>Mỗi tài khoản, một góc nhìn mới.</h2><p>Tạo tài khoản để tham gia cộng đồng và bắt đầu chia sẻ câu chuyện của bạn.</p></div><div class="auth-card"><p class="eyebrow">THAM GIA BLOGFOLIO</p><h2>Tạo tài khoản</h2><p class="error form-alert">Vui lòng kiểm tra tên đăng nhập, email, ngày sinh và xác nhận mật khẩu. Mật khẩu cần đủ 4 tiêu chí bên dưới.</p><form method="post" action="/register" class="form-stack"><input type="hidden" name="csrf" value="${escapeHtml(req.body.csrf || "")}">${formField("Tên đăng nhập (3–50 ký tự)", "username", username)}${formField("Địa chỉ Gmail / email", "email", email, "email")}${formField("Ngày sinh (không bắt buộc)", "birth_date", birthDate, "date", false)}${formField("Mật khẩu mới", "password", "", "password", true, 'data-password-strength')}${passwordStrengthMeter()}${formField("Nhập lại mật khẩu", "password_confirm", "", "password")}<button class="button button-primary button-wide" type="submit">Tạo tài khoản <span aria-hidden="true">→</span></button></form></div></section>`), null, false);
  }
  const passwordHash = await bcrypt.hash(password, 12);
  try {
    const [result] = await pool.execute(
      "INSERT INTO users (username, email, birth_date, password_hash, role) VALUES (?, ?, ?, ?, 'editor')",
      [username, email, birthDate || null, passwordHash]
    );
    setSession(res, { id: result.insertId, username, role: "editor" });
    res.redirect("/");
  } catch (error) {
    if (error.code !== "ER_DUP_ENTRY") throw error;
    res.status(409).send(page("Tạo tài khoản", `<section class="auth-layout"><div class="auth-aside"><span class="auth-aside-mark">✳</span><p class="eyebrow">BẮT ĐẦU HÀNH TRÌNH</p><h2>Mỗi tài khoản, một góc nhìn mới.</h2><p>Tạo tài khoản để tham gia cộng đồng và bắt đầu chia sẻ câu chuyện của bạn.</p></div><div class="auth-card"><p class="eyebrow">THAM GIA BLOGFOLIO</p><h2>Tạo tài khoản</h2><p class="error form-alert">Tên đăng nhập hoặc email này đã được sử dụng.</p><form method="post" action="/register" class="form-stack"><input type="hidden" name="csrf" value="${escapeHtml(req.body.csrf || "")}">${formField("Tên đăng nhập (3–50 ký tự)", "username", username)}${formField("Địa chỉ Gmail / email", "email", email, "email")}${formField("Ngày sinh (không bắt buộc)", "birth_date", birthDate, "date", false)}${formField("Mật khẩu mới", "password", "", "password", true, 'data-password-strength')}${passwordStrengthMeter()}${formField("Nhập lại mật khẩu", "password_confirm", "", "password")}<button class="button button-primary button-wide" type="submit">Tạo tài khoản <span aria-hidden="true">→</span></button></form></div></section>`), null, false);
  }
});

app.post("/login", async (req, res) => {
  const [rows] = await pool.execute("SELECT id, username, password_hash, role, avatar_mime FROM users WHERE username = ? LIMIT 1", [req.body.username || ""]);
  if (!rows.length || !(await bcrypt.compare(req.body.password || "", rows[0].password_hash))) {
    return res.status(401).send(page("Đăng nhập CMS", `<section class="auth-layout"><div class="auth-aside"><span class="auth-aside-mark">✳</span><p class="eyebrow">CHÀO MỪNG TRỞ LẠI</p><h2>Tiếp tục câu chuyện của bạn.</h2><p>Đăng nhập để quản lý bài viết và chia sẻ những ý tưởng mới.</p></div><div class="auth-card"><p class="eyebrow">KHU VỰC QUẢN TRỊ</p><h2>Đăng nhập</h2><p class="error form-alert">Tên đăng nhập hoặc mật khẩu không đúng. Vui lòng thử lại.</p><form method="post" action="/login" class="form-stack">${formField("Tên đăng nhập", "username")} ${formField("Mật khẩu", "password", "", "password")}<button class="button button-primary button-wide" type="submit">Đăng nhập <span aria-hidden="true">→</span></button></form><div class="auth-links"><a href="/forgot-password">Quên mật khẩu?</a><span>Không có liên kết đăng ký trên trang đăng nhập.</span></div></div></section>`, null, false));
  }
  setSession(res, rows[0]);
  res.redirect("/admin");
});

app.post("/logout", requireUser, requireCsrf, (req, res) => {
  clearSession(res);
  res.redirect("/");
});

app.get("/profile", requireUser, async (req, res) => {
  const [rows] = await pool.execute(
    "SELECT username, email, birth_date, role, created_at, avatar_mime FROM users WHERE id = ? LIMIT 1",
    [req.user.id]
  );
  if (!rows.length) {
    clearSession(res);
    return res.redirect("/login");
  }
  const profile = rows[0];
  const birthDate = profile.birth_date ? new Date(profile.birth_date).toISOString().slice(0, 10) : "";
  const notice = req.query.welcome === "1"
    ? '<p class="success form-alert">Tài khoản đã tạo thành công. Hoàn thiện hồ sơ để dễ khôi phục khi cần.</p>'
    : req.query.saved === "1" ? '<p class="success form-alert">Thông tin cá nhân đã được cập nhật.</p>'
      : req.query.password === "1" ? '<p class="success form-alert">Mật khẩu đã được cập nhật thành công.</p>' : "";
  const body = `<section class="profile-layout"><aside class="profile-summary">${avatarMarkup({ ...profile, avatar: Boolean(profile.avatar_mime) }, "profile-avatar-large")}<p class="eyebrow">TÀI KHOẢN ${profile.role === "admin" ? "QUẢN TRỊ" : "THÀNH VIÊN"}</p><h2>${escapeHtml(profile.username)}</h2><p>${escapeHtml(profile.email || "Chưa thêm email")}</p><span class="role-chip">${profile.role === "admin" ? "Quản trị viên" : "Biên tập viên"}</span></aside><div class="profile-content">${notice}<form method="post" action="/profile" enctype="multipart/form-data" class="form-card"><input type="hidden" name="csrf" value="${escapeHtml(req.user.csrf)}"><div class="form-card-heading"><span class="form-icon">✎</span><div><h2>Thông tin cá nhân</h2><p>Cập nhật ảnh hồ sơ, email và ngày sinh của bạn.</p></div></div><label class="avatar-upload">Ảnh hồ sơ<input type="file" name="avatar" accept="image/jpeg,image/png,image/webp"><small>Chọn ảnh JPEG, PNG hoặc WebP, tối đa 2 MB.</small></label>${profile.avatar_mime ? '<label class="avatar-remove"><input type="checkbox" name="remove_avatar" value="1"> Xóa ảnh hồ sơ hiện tại</label>' : ""}${formField("Tên đăng nhập", "username_display", profile.username)}<small class="field-help">Tên đăng nhập không thể thay đổi.</small>${formField("Địa chỉ Gmail / email", "email", profile.email || "", "email")}${formField("Ngày sinh", "birth_date", birthDate, "date", false)}<p class="profile-security-note">Email được dùng để gửi mã xác minh khi bạn quên mật khẩu.</p><button class="button button-primary" type="submit">Lưu thay đổi <span aria-hidden="true">→</span></button></form><form method="post" action="/profile/password" class="form-card"><input type="hidden" name="csrf" value="${escapeHtml(req.user.csrf)}"><div class="form-card-heading"><span class="form-icon">♧</span><div><h2>Đổi mật khẩu</h2><p>Nhập mật khẩu hiện tại và chọn mật khẩu mới đủ mạnh.</p></div></div>${formField("Mật khẩu hiện tại", "current_password", "", "password", true, 'autocomplete="current-password"')}${formField("Mật khẩu mới", "new_password", "", "password", true, 'data-password-strength')}${passwordStrengthMeter()}${formField("Nhập lại mật khẩu mới", "password_confirm", "", "password")}<button class="button button-primary" type="submit">Cập nhật mật khẩu <span aria-hidden="true">→</span></button></form></div></section>`;
  res.send(page("Hồ sơ cá nhân", body, req.user));
});

app.get("/profile/avatar", requireUser, async (req, res) => {
  const [rows] = await pool.execute("SELECT avatar_mime, avatar_data FROM users WHERE id = ? LIMIT 1", [req.user.id]);
  if (!rows.length || !rows[0].avatar_mime || !rows[0].avatar_data) {
    return res.status(404).send("Profile image not found");
  }
  res.set({
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "X-Content-Type-Options": "nosniff"
  });
  res.type(rows[0].avatar_mime).send(rows[0].avatar_data);
});

app.post("/profile", requireUser, parseAvatarUpload, requireCsrf, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const birthDate = String(req.body.birth_date || "");
  const avatarMime = req.file ? detectAvatarMime(req.file.buffer) : null;
  const removeAvatar = req.body.remove_avatar === "1";
  if (!validEmail(email) || !validBirthDate(birthDate)) {
    return res.status(400).send(page("Hồ sơ cá nhân", '<p class="error form-alert">Vui lòng nhập email hợp lệ và ngày sinh hợp lệ, không ở tương lai.</p><p><a class="button button-outline" href="/profile">Quay lại hồ sơ</a></p>', req.user));
  }
  if ((req.file && !avatarMime) || (req.file && avatarMime !== req.file.mimetype) || (req.file && removeAvatar)) {
    return res.status(400).send(page("Ảnh không hợp lệ", '<p class="error form-alert">Tệp không phải ảnh JPEG, PNG hoặc WebP hợp lệ; hoặc hãy bỏ chọn xóa ảnh khi tải ảnh mới.</p><p><a class="button button-outline" href="/profile">Quay lại hồ sơ</a></p>', req.user));
  }
  try {
    if (req.file) {
      await pool.execute(
        "UPDATE users SET email = ?, birth_date = ?, avatar_mime = ?, avatar_data = ? WHERE id = ?",
        [email, birthDate || null, avatarMime, req.file.buffer, req.user.id]
      );
      setSession(res, { ...req.user, avatar: true });
    } else if (removeAvatar) {
      await pool.execute(
        "UPDATE users SET email = ?, birth_date = ?, avatar_mime = NULL, avatar_data = NULL WHERE id = ?",
        [email, birthDate || null, req.user.id]
      );
      setSession(res, { ...req.user, avatar: false });
    } else {
      await pool.execute("UPDATE users SET email = ?, birth_date = ? WHERE id = ?", [email, birthDate || null, req.user.id]);
    }
    res.redirect("/profile?saved=1");
  } catch (error) {
    if (error.code !== "ER_DUP_ENTRY") throw error;
    res.status(409).send(page("Hồ sơ cá nhân", '<p class="error form-alert">Email này đã được sử dụng cho tài khoản khác.</p><p><a class="button button-outline" href="/profile">Quay lại hồ sơ</a></p>', req.user));
  }
});

app.post("/profile/password", requireUser, requireCsrf, async (req, res) => {
  const currentPassword = String(req.body.current_password || "");
  const newPassword = String(req.body.new_password || "");
  const passwordConfirm = String(req.body.password_confirm || "");
  if (!isStrongPassword(newPassword) || newPassword !== passwordConfirm) {
    return res.status(400).send(page("Không thể đổi mật khẩu", '<p class="error form-alert">Mật khẩu mới cần đạt đủ 4 tiêu chí độ mạnh và hai lần nhập phải khớp nhau.</p><p><a class="button button-outline" href="/profile">Quay lại hồ sơ</a></p>', req.user));
  }
  const [users] = await pool.execute("SELECT password_hash FROM users WHERE id = ? LIMIT 1", [req.user.id]);
  if (!users.length) {
    clearSession(res);
    return res.redirect("/login");
  }
  if (!(await bcrypt.compare(currentPassword, users[0].password_hash))) {
    return res.status(400).send(page("Không thể đổi mật khẩu", '<p class="error form-alert">Mật khẩu hiện tại không chính xác.</p><p><a class="button button-outline" href="/profile">Quay lại hồ sơ</a></p>', req.user));
  }
  const passwordHash = await bcrypt.hash(newPassword, 12);
  await pool.execute("UPDATE users SET password_hash = ? WHERE id = ?", [passwordHash, req.user.id]);
  res.redirect("/profile?password=1");
});

app.get("/forgot-password", (req, res) => {
  const csrf = issueFormCsrf(res);
  const body = `<section class="auth-layout"><div class="auth-aside"><span class="auth-aside-mark">✳</span><p class="eyebrow">KHÔI PHỤC TÀI KHOẢN</p><h2>Quên mật khẩu không có nghĩa là mất câu chuyện.</h2><p>Nhập tên đăng nhập hoặc email đã đăng ký. Chúng tôi sẽ gửi mã xác minh tới email gắn với tài khoản.</p></div><div class="auth-card"><p class="eyebrow">XÁC MINH BẢO MẬT</p><h2>Quên mật khẩu?</h2><p class="muted">Có thể nhập tên đăng nhập hoặc email chính xác đã xác minh.</p><form method="post" action="/forgot-password" class="form-stack">${csrf}${formField("Tên đăng nhập hoặc email", "identifier")}<button class="button button-primary button-wide" type="submit">Gửi mã xác minh <span aria-hidden="true">→</span></button></form><p class="auth-footnote">Mã có hiệu lực trong 10 phút. Kiểm tra cả thư mục Spam.</p><p class="auth-footnote"><a href="/login">← Quay lại đăng nhập</a></p></div></section>`;
  res.send(page("Khôi phục mật khẩu", body));
});

app.post("/forgot-password", requireFormCsrf, async (req, res) => {
  const identifier = String(req.body.identifier || "").trim();
  if (!identifier || identifier.length > 254) {
    return res.status(400).send(page("Khôi phục mật khẩu", '<p class="error form-alert">Vui lòng nhập tên đăng nhập hoặc email hợp lệ.</p><p><a class="button button-outline" href="/forgot-password">Thử lại</a></p>'));
  }
  if (!resetRequestAllowed(req)) {
    return res.status(429).send(page("Khôi phục mật khẩu", '<p class="error form-alert">Đã gửi quá nhiều yêu cầu. Vui lòng đợi 15 phút rồi thử lại.</p><p><a class="button button-outline" href="/forgot-password">Quay lại</a></p>'));
  }
  const mailer = getMailTransport();
  if (!mailer) {
    return res.status(503).send(page("Khôi phục mật khẩu", '<p class="error form-alert">Chức năng gửi mã chưa được cấu hình. Quản trị viên cần điền SMTP_USER, SMTP_PASS và MAIL_FROM trong file .env rồi khởi động lại ứng dụng.</p><p><a class="button button-outline" href="/forgot-password">Quay lại</a></p>'));
  }
  const isEmail = identifier.includes("@");
  const [users] = await pool.execute(
    `SELECT id, username, email FROM users WHERE ${isEmail ? "email = ?" : "username = ?"} LIMIT 1`,
    [isEmail ? identifier.toLowerCase() : identifier]
  );
  if (users.length && users[0].email) {
    const user = users[0];
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString().slice(0, 19).replace("T", " ");
    await pool.execute(
      "INSERT INTO password_resets (user_id, code_hash, expires_at, attempts) VALUES (?, ?, ?, 0) ON DUPLICATE KEY UPDATE code_hash = VALUES(code_hash), expires_at = VALUES(expires_at), attempts = 0, created_at = CURRENT_TIMESTAMP",
      [user.id, resetCodeHash(user.id, code), expires]
    );
    try {
      await mailer.sendMail({
        from: process.env.MAIL_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: "Mã xác minh khôi phục Blogfolio",
        text: `Xin chào ${user.username}, mã xác minh khôi phục mật khẩu của bạn là ${code}. Mã có hiệu lực trong 10 phút. Nếu bạn không yêu cầu, hãy bỏ qua email này.`,
        html: `<p>Xin chào <strong>${escapeHtml(user.username)}</strong>,</p><p>Mã xác minh khôi phục mật khẩu của bạn:</p><p style="font-size:28px;font-weight:bold;letter-spacing:8px">${code}</p><p>Mã có hiệu lực trong 10 phút. Nếu bạn không yêu cầu, hãy bỏ qua email này.</p>`
      });
    } catch (error) {
      await pool.execute("DELETE FROM password_resets WHERE user_id = ?", [user.id]);
      console.error(JSON.stringify({ level: "error", message: "Password reset email delivery failed", code: error.code || "SMTP_ERROR" }));
      return res.status(502).send(page("Khôi phục mật khẩu", '<p class="error form-alert">Không gửi được email. Hãy kiểm tra cấu hình Gmail SMTP/App Password rồi thử lại.</p><p><a class="button button-outline" href="/forgot-password">Thử lại</a></p>'));
    }
  }
  const body = `<section class="auth-layout"><div class="auth-aside"><span class="auth-aside-mark">✳</span><p class="eyebrow">MÃ ĐÃ ĐƯỢC GỬI</p><h2>Kiểm tra hộp thư của bạn.</h2><p>Nếu thông tin khớp với tài khoản đã đăng ký email, mã xác minh sẽ được gửi đến hộp thư đó.</p></div><div class="auth-card"><p class="eyebrow">BƯỚC TIẾP THEO</p><h2>Đặt mật khẩu mới</h2><p class="muted">Nhập mã 6 chữ số trong email cùng mật khẩu mới của bạn.</p><form method="post" action="/reset-password" class="form-stack"><input type="hidden" name="csrf" value="${escapeHtml(req.body.csrf || "")}">${formField("Tên đăng nhập hoặc email", "identifier", identifier)}${formField("Mã xác minh 6 chữ số", "code", "", "text", true, 'inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"')}${formField("Mật khẩu mới", "password", "", "password", true, 'data-password-strength')}${passwordStrengthMeter()}${formField("Nhập lại mật khẩu mới", "password_confirm", "", "password")}<button class="button button-primary button-wide" type="submit">Đổi mật khẩu <span aria-hidden="true">→</span></button></form><p class="auth-footnote"><a href="/login">Quay lại đăng nhập</a></p></div></section>`;
  res.send(page("Nhập mã xác minh", body));
});

app.post("/reset-password", requireFormCsrf, async (req, res) => {
  const identifier = String(req.body.identifier || "").trim();
  const code = String(req.body.code || "").trim();
  const password = String(req.body.password || "");
  const passwordConfirm = String(req.body.password_confirm || "");
  if (!identifier || !/^\d{6}$/.test(code) || !isStrongPassword(password) || password !== passwordConfirm) {
    return res.status(400).send(page("Mã xác minh không hợp lệ", '<p class="error form-alert">Kiểm tra mã 6 chữ số và nhập hai mật khẩu giống nhau. Mật khẩu cần đạt đủ 4 tiêu chí độ mạnh.</p><p><a class="button button-outline" href="/forgot-password">Yêu cầu mã mới</a></p>'));
  }
  const isEmail = identifier.includes("@");
  const [users] = await pool.execute(
    `SELECT id FROM users WHERE ${isEmail ? "email = ?" : "username = ?"} LIMIT 1`,
    [isEmail ? identifier.toLowerCase() : identifier]
  );
  if (!users.length) return res.status(400).send(page("Mã xác minh không hợp lệ", '<p class="error form-alert">Mã không đúng, đã hết hạn hoặc tài khoản không hợp lệ. Hãy yêu cầu mã mới.</p><p><a class="button button-outline" href="/forgot-password">Yêu cầu mã mới</a></p>'));

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [resets] = await connection.execute(
      "SELECT code_hash, expires_at, attempts FROM password_resets WHERE user_id = ? FOR UPDATE",
      [users[0].id]
    );
    if (!resets.length || resets[0].attempts >= 5 || new Date(resets[0].expires_at).getTime() <= Date.now()) {
      await connection.execute("DELETE FROM password_resets WHERE user_id = ?", [users[0].id]);
      await connection.commit();
      return res.status(400).send(page("Mã xác minh không hợp lệ", '<p class="error form-alert">Mã không đúng, đã hết hạn hoặc đã vượt quá số lần thử. Hãy yêu cầu mã mới.</p><p><a class="button button-outline" href="/forgot-password">Yêu cầu mã mới</a></p>'));
    }
    const expected = Buffer.from(resets[0].code_hash, "hex");
    const actual = Buffer.from(resetCodeHash(users[0].id, code), "hex");
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
      await connection.execute("UPDATE password_resets SET attempts = attempts + 1 WHERE user_id = ?", [users[0].id]);
      await connection.commit();
      return res.status(400).send(page("Mã xác minh không hợp lệ", '<p class="error form-alert">Mã không đúng. Mã sẽ bị vô hiệu sau 5 lần thử.</p><p><a class="button button-outline" href="/forgot-password">Yêu cầu mã mới</a></p>'));
    }
    const passwordHash = await bcrypt.hash(password, 12);
    await connection.execute("UPDATE users SET password_hash = ? WHERE id = ?", [passwordHash, users[0].id]);
    await connection.execute("DELETE FROM password_resets WHERE user_id = ?", [users[0].id]);
    await connection.commit();
    res.redirect("/login?password-reset=1");
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
});

app.get("/admin", requireUser, async (req, res) => {
  const [posts] = await pool.execute(
    `SELECT p.id, p.title, p.status, p.slug, c.name AS category
     FROM posts p LEFT JOIN categories c ON c.id = p.category_id ORDER BY p.updated_at DESC`
  );
  const rows = posts.map((post) =>
    `<tr><td>${escapeHtml(post.title)}</td><td>${escapeHtml(post.category || "-")}</td><td>${escapeHtml(post.status)}</td><td><a href="/admin/posts/${post.id}/edit">Sửa</a>${post.status === "published" ? ` · <a href="/posts/${encodeURIComponent(post.slug)}">Xem</a>` : ""}<form class="inline" method="post" action="/admin/posts/${post.id}/delete">${csrfField(req.user)}<button class="link danger" type="submit">Xóa</button></form></td></tr>`
  ).join("");
  let body = `<p><a class="button" href="/admin/posts/new">Tạo bài viết</a> <a class="button secondary" href="/admin/categories">Danh mục</a>${req.user.role === "admin" ? ' <a class="button secondary" href="/admin/users">Người dùng</a>' : ""}</p><div class="table-wrap"><table><thead><tr><th>Tiêu đề</th><th>Danh mục</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>${rows || '<tr><td colspan="4">Chưa có bài viết.</td></tr>'}</tbody></table></div>`;
  res.send(page("Quản trị bài viết", body, req.user));
});

async function postForm(user, post = {}) {
  const [categories] = await pool.execute("SELECT id, name FROM categories ORDER BY name");
  const categoryOptions = categories.map((category) =>
    `<option value="${category.id}"${String(category.id) === String(post.category_id) ? " selected" : ""}>${escapeHtml(category.name)}</option>`
  ).join("");
  const action = post.id ? `/admin/posts/${post.id}/edit` : "/admin/posts/new";
  const body = `<form method="post" action="${action}" class="panel">${csrfField(user)}${formField("Tiêu đề", "title", post.title || "")}${formField("Tóm tắt", "excerpt", post.excerpt || "", "text", false)}<label>Danh mục<select name="category_id"><option value="">Không có</option>${categoryOptions}</select></label><label>Nội dung<textarea name="body" rows="12" required>${escapeHtml(post.body || "")}</textarea></label><label>Trạng thái<select name="status"><option value="draft"${post.status !== "published" ? " selected" : ""}>Bản nháp</option><option value="published"${post.status === "published" ? " selected" : ""}>Xuất bản</option></select></label><button type="submit">Lưu bài viết</button></form>`;
  return page(post.id ? "Sửa bài viết" : "Tạo bài viết", body, user);
}

app.get("/admin/posts/new", requireUser, async (req, res) => res.send(await postForm(req.user)));
app.post("/admin/posts/new", requireUser, requireCsrf, async (req, res) => {
  const title = String(req.body.title || "").trim();
  const body = String(req.body.body || "").trim();
  if (!title || !body) return res.status(400).send(page("Dữ liệu không hợp lệ", "<p>Tiêu đề và nội dung là bắt buộc.</p>", req.user));
  const slug = `${slugify(title) || "bai-viet"}-${crypto.randomBytes(3).toString("hex")}`;
  const categoryId = req.body.category_id ? Number(req.body.category_id) : null;
  await pool.execute(
    "INSERT INTO posts (title, slug, excerpt, body, status, author_id, category_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [title, slug, String(req.body.excerpt || "").trim(), body, req.body.status === "published" ? "published" : "draft", req.user.id, categoryId]
  );
  res.redirect("/admin");
});

app.get("/admin/posts/:id/edit", requireUser, async (req, res) => {
  const [rows] = await pool.execute("SELECT * FROM posts WHERE id = ? LIMIT 1", [Number(req.params.id)]);
  if (!rows.length) return res.status(404).send(page("Không tìm thấy bài viết", "<p>Bài viết không tồn tại.</p>", req.user));
  res.send(await postForm(req.user, rows[0]));
});

app.post("/admin/posts/:id/edit", requireUser, requireCsrf, async (req, res) => {
  const postId = Number(req.params.id);
  const title = String(req.body.title || "").trim();
  const body = String(req.body.body || "").trim();
  if (!Number.isInteger(postId) || postId < 1 || !title || !body) return res.status(400).send(page("Dữ liệu không hợp lệ", "<p>Vui lòng nhập tiêu đề và nội dung hợp lệ.</p>", req.user));
  const categoryId = req.body.category_id ? Number(req.body.category_id) : null;
  const [result] = await pool.execute(
    "UPDATE posts SET title = ?, excerpt = ?, body = ?, status = ?, category_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    [title, String(req.body.excerpt || "").trim(), body, req.body.status === "published" ? "published" : "draft", categoryId, postId]
  );
  if (!result.affectedRows) return res.status(404).send(page("Không tìm thấy bài viết", "<p>Bài viết không tồn tại.</p>", req.user));
  res.redirect("/admin");
});

app.post("/admin/posts/:id/delete", requireUser, requireCsrf, async (req, res) => {
  const postId = Number(req.params.id);
  if (!Number.isInteger(postId) || postId < 1) return res.status(400).send(page("Dữ liệu không hợp lệ", "<p>Mã bài viết không hợp lệ.</p>", req.user));
  await pool.execute("DELETE FROM posts WHERE id = ?", [postId]);
  res.redirect("/admin");
});

app.get("/admin/categories", requireUser, requireAdmin, async (req, res) => {
  const [categories] = await pool.execute("SELECT id, name FROM categories ORDER BY name");
  const rows = categories.map((category) =>
    `<tr><td>${escapeHtml(category.name)}</td><td><form method="post" action="/admin/categories/${category.id}/delete">${csrfField(req.user)}<button class="link danger" type="submit">Xóa</button></form></td></tr>`
  ).join("");
  const body = `<form method="post" action="/admin/categories" class="panel">${csrfField(req.user)}${formField("Tên danh mục", "name")}<button type="submit">Thêm danh mục</button></form><div class="table-wrap"><table><thead><tr><th>Tên</th><th>Thao tác</th></tr></thead><tbody>${rows || '<tr><td colspan="2">Chưa có danh mục.</td></tr>'}</tbody></table></div>`;
  res.send(page("Quản lý danh mục", body, req.user));
});

app.post("/admin/categories", requireUser, requireAdmin, requireCsrf, async (req, res) => {
  const name = String(req.body.name || "").trim();
  if (!name || name.length > 100) return res.status(400).send(page("Dữ liệu không hợp lệ", "<p>Tên danh mục phải từ 1 đến 100 ký tự.</p>", req.user));
  await pool.execute("INSERT INTO categories (name) VALUES (?)", [name]);
  res.redirect("/admin/categories");
});

app.post("/admin/categories/:id/delete", requireUser, requireAdmin, requireCsrf, async (req, res) => {
  await pool.execute("DELETE FROM categories WHERE id = ?", [Number(req.params.id)]);
  res.redirect("/admin/categories");
});

app.get("/admin/users", requireUser, requireAdmin, async (req, res) => {
  const [users] = await pool.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id");
  const rows = users.map((user) =>
    `<tr><td>${escapeHtml(user.username)}</td><td>${escapeHtml(user.email || "Chưa cập nhật")}</td><td><span class="role-chip">${user.role === "admin" ? "Quản trị viên" : "Biên tập viên"}</span></td><td>${new Date(user.created_at).toLocaleDateString("vi-VN")}</td></tr>`
  ).join("");
  const body = `<section class="management-layout"><div class="management-intro"><p class="eyebrow">QUẢN TRỊ VIÊN</p><h2>Cộng đồng Blogfolio.</h2><p>Thành viên tự đăng ký từ trang chủ. Trang này giúp quản trị viên xem tài khoản và email đã khai báo.</p><div class="management-count"><strong>${users.length.toString().padStart(2, "0")}</strong><span>TÀI KHOẢN<br>TRONG HỆ THỐNG</span></div></div><div class="management-content"><section class="users-card"><div class="section-heading compact-heading"><div><p class="eyebrow">THÀNH VIÊN</p><h2>Tài khoản hiện có</h2></div><span class="count-pill">${users.length}</span></div><div class="table-wrap"><table><thead><tr><th>Tài khoản</th><th>Email</th><th>Vai trò</th><th>Ngày tham gia</th></tr></thead><tbody>${rows}</tbody></table></div></section></div></section>`;
  res.send(page("Quản lý người dùng", body, req.user));
});

app.use((req, res) => res.status(404).send(page("Không tìm thấy trang", "<p>Đường dẫn không tồn tại.</p>", readSession(req))));
app.use((error, req, res, next) => {
  console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: "error", message: error.message, path: req.path }));
  if (res.headersSent) return next(error);
  res.status(500).send(page("Lỗi máy chủ", "<p>Đã xảy ra lỗi. Quản trị viên có thể xem chi tiết trong log tập trung.</p>", readSession(req)));
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      email VARCHAR(254) NULL,
      birth_date DATE NULL,
      password_hash VARCHAR(100) NOT NULL,
      role ENUM('admin', 'editor') NOT NULL DEFAULT 'editor',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `);
  const [userColumns] = await pool.execute(
    "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'"
  );
  const existingColumns = new Set(userColumns.map((column) => column.COLUMN_NAME));
  if (!existingColumns.has("email")) {
    await pool.query("ALTER TABLE users ADD COLUMN email VARCHAR(254) NULL");
  }
  if (!existingColumns.has("birth_date")) {
    await pool.query("ALTER TABLE users ADD COLUMN birth_date DATE NULL");
  }
  if (!existingColumns.has("avatar_mime")) {
    await pool.query("ALTER TABLE users ADD COLUMN avatar_mime VARCHAR(32) NULL");
  }
  if (!existingColumns.has("avatar_data")) {
    await pool.query("ALTER TABLE users ADD COLUMN avatar_data MEDIUMBLOB NULL");
  }
  const [emailIndexes] = await pool.execute(
    "SELECT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND INDEX_NAME = 'uq_users_email'"
  );
  if (!emailIndexes.length) {
    await pool.query("CREATE UNIQUE INDEX uq_users_email ON users (email)");
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      user_id INT UNSIGNED NOT NULL PRIMARY KEY,
      code_hash CHAR(64) NOT NULL,
      expires_at DATETIME NOT NULL,
      attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS categories (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL UNIQUE,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      slug VARCHAR(200) NOT NULL UNIQUE,
      excerpt VARCHAR(500) NOT NULL DEFAULT '',
      body TEXT NOT NULL,
      status ENUM('draft', 'published') NOT NULL DEFAULT 'draft',
      author_id INT UNSIGNED NOT NULL,
      category_id INT UNSIGNED NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_posts_author FOREIGN KEY (author_id) REFERENCES users(id),
      CONSTRAINT fk_posts_category FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
    ) ENGINE=InnoDB
  `);

  const username = process.env.ADMIN_USERNAME || "admin";
  const [admins] = await pool.execute("SELECT id FROM users WHERE username = ? LIMIT 1", [username]);
  if (!admins.length) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", [username, hash]);
  }
  await pool.execute("INSERT IGNORE INTO categories (name) VALUES ('Công nghệ'), ('Hướng dẫn')");
  const [sample] = await pool.execute("SELECT id FROM posts WHERE slug = 'chao-mung-den-blog-cms' LIMIT 1");
  if (!sample.length) {
    const [author] = await pool.execute("SELECT id FROM users WHERE username = ? LIMIT 1", [username]);
    await pool.execute(
      "INSERT INTO posts (title, slug, excerpt, body, status, author_id) VALUES (?, ?, ?, ?, 'published', ?)",
      ["Chào mừng đến Blog CMS", "chao-mung-den-blog-cms", "Bài viết mẫu để kiểm tra ứng dụng.", "Đây là bài viết mẫu. Hãy đăng nhập để tạo, chỉnh sửa và xuất bản nội dung mới.", author[0].id]
    );
  }
}

async function start() {
  await initializeDatabase();
  const port = Number(process.env.PORT || 3000);
  app.listen(port, "0.0.0.0", () => console.log(JSON.stringify({ level: "info", message: `CMS listening on ${port}` })));
}

start().catch((error) => {
  console.error(JSON.stringify({ level: "fatal", message: "CMS startup failed", error: error.message }));
  process.exit(1);
});
