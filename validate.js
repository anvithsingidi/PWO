'use strict';

const REMINDER_CHOICES = [7, 14, 30, 60, 90, 180];
const MAX_DOCS_PER_USER = 500;

function isValidDate(v) {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  const y = +v.slice(0, 4), m = +v.slice(5, 7), d = +v.slice(8, 10);
  if (y < 2000 || y > 2100) return false;
  const t = new Date(Date.UTC(y, m - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d;
}

function validateDocument(input) {
  if (!input || typeof input !== 'object') return { error: 'Invalid document.' };
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  if (!name) return { error: 'Enter a document name.' };
  if (name.length > 80) return { error: 'The document name must be 80 characters or fewer.' };
  if (/[\u0000-\u001f\u007f]/.test(name)) return { error: 'The document name contains invalid characters.' };
  if (!isValidDate(input.date)) return { error: 'Choose a valid expiry date between 2000 and 2100.' };
  const remind = Number(input.remind);
  if (!REMINDER_CHOICES.includes(remind)) return { error: 'Choose a valid warning period.' };
  return { value: { name, date: input.date, remind } };
}

function validateEmail(v) {
  if (typeof v !== 'string') return null;
  const e = v.trim().toLowerCase();
  if (e.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) return null;
  return e;
}

function validatePassword(p) {
  if (typeof p !== 'string' || p.length < 8 || p.length > 128) {
    return 'Your password must be 8 to 128 characters.';
  }
  if (!/[A-Za-z]/.test(p) || !/[0-9]/.test(p)) {
    return 'Your password must contain a letter and a number.';
  }
  return null;
}

module.exports = { REMINDER_CHOICES, MAX_DOCS_PER_USER, isValidDate, validateDocument, validateEmail, validatePassword };
