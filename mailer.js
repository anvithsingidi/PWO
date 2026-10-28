'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Sends through SMTP when SMTP_HOST is set and nodemailer is installed.
// Otherwise every email is appended to data/outbox.log so the app can be demonstrated
// without a mail account.
function createMailer(config, logger = console) {
  let transport = null;
  if (config.smtp) {
    try {
      const nodemailer = require('nodemailer');
      transport = nodemailer.createTransport({
        host: config.smtp.host,
        port: config.smtp.port,
        secure: config.smtp.secure,
        auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined
      });
    } catch (e) {
      logger.warn('SMTP is configured but nodemailer is not installed. Run "npm install". Emails will go to the outbox log instead.');
    }
  }

  return {
    usingSmtp: !!transport,
    async send({ to, subject, text }) {
      if (transport) {
        await transport.sendMail({ from: config.mailFrom, to, subject, text });
        return { delivered: true };
      }
      fs.mkdirSync(config.dataDir, { recursive: true });
      const entry = `--- ${new Date().toISOString()}\nTo: ${to}\nSubject: ${subject}\n\n${text}\n\n`;
      fs.appendFileSync(path.join(config.dataDir, 'outbox.log'), entry);
      logger.log(`[mail] written to outbox for ${to}: ${subject}`);
      return { delivered: false };
    }
  };
}

module.exports = { createMailer };
