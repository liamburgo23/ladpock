function requireLogin(req, res, next) {
  if (process.env.SKIP_AUTH === "true") return next();
  return check(req, res, next);
}
module.exports = { requireLogin };
