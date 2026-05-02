/**
 * Auth helpers - PBKDF2 password hashing + HMAC token verification
 * All operations use the Web Crypto API (available in Cloudflare Workers)
 */

export async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 200000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function verifyPassword(password, salt, storedHash) {
  const hash = await hashPassword(password, salt);
  // Constant-time comparison
  if (hash.length !== storedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ storedHash.charCodeAt(i);
  return diff === 0;
}

export async function requireAuth(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return { ok: false };
  try {
    const decoded = atob(token);
    const parts = decoded.split(':');
    if (parts.length < 4) return { ok: false };
    const sigHex = parts.pop();
    const payload = parts.join(':');
    // Verify timestamp (24h expiry)
    const ts = parseInt(parts[1]);
    if (Date.now() - ts > 86400000) return { ok: false };
    // Verify HMAC
    const secret = env.JWT_SECRET || 'elementa-secret-change-me';
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = new Uint8Array(sigHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(payload));
    return { ok: valid, userId: parseInt(parts[0]) };
  } catch {
    return { ok: false };
  }
}

export { handleAuth };
function handleAuth() {} // placeholder export
