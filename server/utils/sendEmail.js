const nodemailer = require("nodemailer");
const nodemailerConfig = require("./nodemailerConfig");

const transporter = nodemailer.createTransport(nodemailerConfig);

module.exports = function sendEmail({ to, subject, html }) {
  return transporter.sendMail({
    from: '"Auth Workflow" <auth-workflow@email.com>',
    to,
    subject,
    html,
  });
};
