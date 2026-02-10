#!/usr/bin/env node
/**
 * Encrypt HTML content for use in password-protected pages.
 *
 * Usage:
 *   node tools/encrypt.js <password> <input-file>
 *   node tools/encrypt.js <password> --text "<h2>Hello</h2>"
 *
 * The output is the encrypted payload string. Paste it into the
 * data-encrypted attribute of your protected-content div.
 *
 * Example:
 *   node tools/encrypt.js "mypassword" content/school.html
 *   node tools/encrypt.js "mypassword" --text "<h2>My Page</h2><p>Secret stuff.</p>"
 */

const crypto = require('crypto');
const fs = require('fs');

const password = process.argv[2];
const source = process.argv[3];
const extra = process.argv[4];

if (!password || !source) {
  console.error('Usage: node tools/encrypt.js <password> <input-file>');
  console.error('       node tools/encrypt.js <password> --text "<html>"');
  process.exit(1);
}

let plaintext;
if (source === '--text') {
  plaintext = extra;
} else {
  plaintext = fs.readFileSync(source, 'utf8');
}

const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);

crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, derivedKey) => {
  if (err) throw err;
  const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();
  const ctWithTag = Buffer.concat([encrypted, tag]);
  const payload =
    salt.toString('base64') + ':' +
    Buffer.from(iv).toString('base64') + ':' +
    ctWithTag.toString('base64');
  console.log(payload);
});
