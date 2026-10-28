'use strict';
const path = require('node:path');

function loadConfig(env = process.env) {
  const port = Number(env.PORT) || 3000;
  const baseUrl = (env.BASE_URL || `http://localhost:${port}`).replace(/\/+$/, '');
  return {
    port,
    baseUrl,
    dataDir: path.resolve(env.DATA_DIR || './data'),
    secureCookies: baseUrl.startsWith('https://'),
    trustProxy: env.TRUST_PROXY === '1',
    reminderIntervalMinutes: Math.max(1, Number(env.REMINDER_INTERVAL_MINUTES) || 60),
    smtp: env.SMTP_HOST
      ? {
          host: env.SMTP_HOST,
          port: Number(env.SMTP_PORT) || 587,
          secure: env.SMTP_SECURE === 'true',
          user: env.SMTP_USER || '',
          pass: env.SMTP_PASS || ''
        }
      : null,
    mailFrom: env.MAIL_FROM || 'Document Expiry Reminder <no-reply@localhost>'
  };
}

module.exports = { loadConfig };
