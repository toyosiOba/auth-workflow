const crypto = require("crypto");

// hash password reset token
module.exports = (string) =>
  crypto.createHash("md5").update(string).digest("hex");
