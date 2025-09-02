const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

// 从 Authorization Header 里取 Bearer token
function extractBearer(req) {
  const h = req.headers["authorization"];
  if (!h) return null;
  const [scheme, token] = h.split(" ");
  return scheme === "Bearer" && token ? token : null;
}

/**
 * 严格鉴权：必须登录
 * - 成功：req.user = 用户对象（已去掉 password）
 * - 失败：401
 */
async function requireAuth(req, res, next) {
  const token = extractBearer(req);
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // 自动校验 exp
    const user = await User.findById(decoded.id).select("-password");
    if (!user) return res.status(401).json({ message: "User not found" });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

/**
 * 可选鉴权：有 token 就解析到 req.user；无 token 也放行
 * - 适合 /api/telemetry/visit 这类“匿名亦可”的接口
 */
async function attachUserIfPresent(req, res, next) {
  const token = extractBearer(req);
  if (!token) return next(); // 没 token，直接放行（req.user 保持 undefined）

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");
    if (user) req.user = user;
  } catch {
    // token 无效就当匿名，不阻塞请求
  }
  next();
}

/**
 * 角色保护：只有管理员可访问
 * - 依赖 requireAuth 先跑
 */
function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ message: "Unauthorized" });
  if (!req.user.isAdmin) return res.status(403).json({ message: "Forbidden" });
  next();
}

module.exports = { requireAuth, attachUserIfPresent, requireAdmin };
