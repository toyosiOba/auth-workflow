const sendEmail = require("./sendEmail");

module.exports = async ({ name, email, origin, verificationToken }) => {
  const message = `
  <h4>Hello ${name}</h4>
  <p>Please click on the link to verify your email: <a href="${origin}/user/verify-email?token=${verificationToken}&email=${email}">verify email</a> </p>
`;

  return sendEmail({ to: email, subject: "Email Confirmation", html: message });
};
