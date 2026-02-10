/**
 * Client-side page protection for static sites (GitHub Pages).
 *
 * How it works:
 * 1. Page content is encrypted with AES-GCM using a key derived from the password (PBKDF2).
 * 2. The encrypted blob, salt, and IV are stored in a data attribute on the page.
 * 3. When a visitor enters the correct password, the content is decrypted and injected.
 * 4. The password hash is cached in sessionStorage so you only enter it once per session.
 *
 * To encrypt content for a new page, open the browser console on any protected page
 * and run:  encryptContent('your-password', '<h2>Your HTML here</h2>')
 * Then paste the output into the data-encrypted attribute of your page's protected div.
 */

(function () {
  'use strict';

  const STORAGE_KEY = 'caudle_family_auth';

  // --- Crypto helpers ---

  function utf8Encode(str) {
    return new TextEncoder().encode(str);
  }

  function utf8Decode(buf) {
    return new TextDecoder().decode(buf);
  }

  function bufToBase64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  function base64ToBuf(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  }

  async function deriveKey(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw', utf8Encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(password, plaintext) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      utf8Encode(plaintext)
    );
    return bufToBase64(salt) + ':' + bufToBase64(iv) + ':' + bufToBase64(ciphertext);
  }

  async function decrypt(password, payload) {
    const [saltB64, ivB64, ctB64] = payload.split(':');
    const salt = base64ToBuf(saltB64);
    const iv = base64ToBuf(ivB64);
    const ciphertext = base64ToBuf(ctB64);
    const key = await deriveKey(password, salt);
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    return utf8Decode(plainBuf);
  }

  // --- UI Logic ---

  const gate = document.getElementById('password-gate');
  const content = document.getElementById('protected-content');
  const form = document.getElementById('password-form');
  const input = document.getElementById('password-input');
  const errorMsg = document.getElementById('password-error');

  if (!gate || !content || !form) return; // not a protected page

  const encryptedPayload = content.getAttribute('data-encrypted');
  if (!encryptedPayload) return;

  async function unlock(password) {
    try {
      const html = await decrypt(password, encryptedPayload);
      content.innerHTML = html;
      content.classList.add('unlocked');
      gate.style.display = 'none';
      // Cache for this session
      sessionStorage.setItem(STORAGE_KEY, password);
    } catch (e) {
      throw new Error('Wrong password');
    }
  }

  // Check session cache
  const cached = sessionStorage.getItem(STORAGE_KEY);
  if (cached) {
    unlock(cached).catch(function () {
      sessionStorage.removeItem(STORAGE_KEY);
    });
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    errorMsg.classList.remove('visible');
    const pw = input.value;
    if (!pw) return;

    try {
      await unlock(pw);
    } catch (err) {
      errorMsg.classList.add('visible');
      input.value = '';
      input.focus();
    }
  });

  // --- Helper: expose encryption function to console for content authoring ---
  window.encryptContent = async function (password, htmlString) {
    const result = await encrypt(password, htmlString);
    console.log('Encrypted payload (copy this into data-encrypted):');
    console.log(result);
    return result;
  };
})();
