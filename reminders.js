'use strict';

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function formatDate(s) {
  const [y, m, d] = s.split('-').map(Number);
  return `${d} ${MONTHS[m - 1]} ${y}`;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

// Whole days from today until the date, using the server's local calendar day.
function daysUntil(dateStr, now) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const target = new Date(y, m - 1, d);
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  return Math.round((target - today) / 864e5);
}

// A document that is already expired when it is saved should not trigger an email.
function stageForNewDoc(dateStr, now) {
  return daysUntil(dateStr, now) < 0 ? 'expired' : '';
}

function buildEmail(items, baseUrl) {
  const expired = items.filter((i) => i.kind === 'expired');
  const due = items.filter((i) => i.kind === 'due');
  const lines = ['Hello,', '', 'These documents need your attention.', ''];
  if (expired.length) {
    lines.push('Expired');
    expired.forEach((i) => lines.push(`  - ${i.name}: expired on ${formatDate(i.date)} (${plural(-i.dl, 'day')} ago)`));
    lines.push('');
  }
  if (due.length) {
    lines.push('Due soon');
    due.forEach((i) => lines.push(`  - ${i.name}: expires on ${formatDate(i.date)} (${i.dl === 0 ? 'today' : plural(i.dl, 'day') + ' left'})`));
    lines.push('');
  }
  lines.push(`Review and renew them here: ${baseUrl}`, '');
  lines.push('You receive this email because email reminders are turned on for your account. You can turn them off in the tracker under Account.');
  return {
    subject: `Document Expiry Reminder: ${plural(items.length, 'document')} need${items.length === 1 ? 's' : ''} attention`,
    text: lines.join('\n')
  };
}

// Sends one email per user listing every document that newly needs attention,
// then records that it was sent so the same reminder is never sent twice.
async function runReminders({ db, mailer, now = new Date(), baseUrl, logger = console }) {
  const rows = db.prepare(`
    SELECT d.id, d.user_id AS userId, d.name, d.expiry_date AS date, d.remind_days AS remind,
           d.notified_stage AS stage, u.email
    FROM documents d JOIN users u ON u.id = d.user_id
    WHERE u.email_reminders = 1
    ORDER BY d.user_id, d.expiry_date`).all();

  const byUser = new Map();
  for (const row of rows) {
    const dl = daysUntil(row.date, now);
    let kind = null;
    if (dl < 0 && row.stage !== 'expired') kind = 'expired';
    else if (dl >= 0 && dl <= row.remind && row.stage === '') kind = 'due';
    if (!kind) continue;
    if (!byUser.has(row.userId)) byUser.set(row.userId, { email: row.email, items: [] });
    byUser.get(row.userId).items.push({ id: row.id, name: row.name, date: row.date, dl, kind });
  }

  let emails = 0, documents = 0;
  const mark = db.prepare('UPDATE documents SET notified_stage = ? WHERE id = ? AND user_id = ?');
  for (const [userId, { email, items }] of byUser) {
    try {
      const msg = buildEmail(items, baseUrl);
      await mailer.send({ to: email, subject: msg.subject, text: msg.text });
      for (const i of items) mark.run(i.kind, i.id, userId);
      emails++;
      documents += items.length;
    } catch (err) {
      logger.error(`Could not send reminder to user ${userId}:`, err && err.message ? err.message : err);
    }
  }
  return { emails, documents };
}

module.exports = { runReminders, stageForNewDoc, daysUntil, buildEmail, formatDate };
