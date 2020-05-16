const nodemailer = require("nodemailer");

exports.transport = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: process.env.MAIL_PORT,
  auth: {
    user: process.env.MAIL_USERNAME,
    pass: process.env.MAIL_PASS
  }
});

exports.makeANiceMail = (text, name) => `
<div className="email" style="
border: 1px solid black;
padding: 20px;
font-family: sans-serif;
line-height: 2;
font-size: 20px;
">
<h2>Hello ${name.split(" ")[0]}!</h2>
<p>${text}</p>
</div>
`;
