'use strict';
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);

const N = 16384, R = 8, P = 1, KEYLEN = 64;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const RESET_TTL_MS = 60 * 60 * 1000;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, KEYLEN, { N, r: R, p: P });
  return ['scrypt', N, R, P, salt.toString('hex'), key.toString('hex')].join('$');
}

async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const expected = Buffer.from(parts[5], 'hex');
  const key = await scrypt(password, Buffer.from(parts[4], 'hex'), expected.length, {
    N: Number(parts[1]), r: Number(parts[2]), p: Number(parts[3])
  });
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}

// Used so that logging in with an unknown email takes about as long as a real check.
let dummy = null;
async function dummyHash() {
  if (!dummy) dummy = await hashPassword('not-a-real-password-1');
  return dummy;
}

function newToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

module.exports = { hashPassword, verifyPassword, dummyHash, newToken, hashToken, SESSION_TTL_MS, RESET_TTL_MS };
