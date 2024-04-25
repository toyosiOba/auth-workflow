const sendEmail = require("./sendEmail");

module.exports = async ({ name, email, origin, passwordToken }) => {
  const resetURL = `${origin}/user/reset-password?token=${passwordToken}&email=${email}`;
  const message = `
  <h4>Hello ${name}</h4>
  <p>You requested for a password reset, click the link to reset your password : <a href="${resetURL}">reset password</a></p>
  <p>Ignore if this is not you.</p>
  `;

  return sendEmail({ to: email, subject: "Reset Password", html: message });
};
