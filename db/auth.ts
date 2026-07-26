import { env } from "cloudflare:workers";

function bytesToBase64Url(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export async function hashSecret(value: string) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function hashMasterPassword(value: string) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(value),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: new TextEncoder().encode("yuemi-master-v1"),
      iterations: 210_000,
    },
    keyMaterial,
    256,
  );
  return Array.from(new Uint8Array(derived))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function createOpaqueToken() {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function createVaultSession(deviceId: string) {
  const token = createOpaqueToken();
  const tokenHash = await hashSecret(token);
  const expiresAt = new Date(Date.now() + 30 * 60_000).toISOString();

  await env.DB.prepare(
    "INSERT INTO vault_sessions (token_hash, device_id, expires_at) VALUES (?, ?, ?)",
  )
    .bind(tokenHash, deviceId, expiresAt)
    .run();

  return token;
}

export async function getVaultSession(request: Request) {
  const authorization = request.headers.get("authorization") ?? "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7).trim()
    : "";
  if (!token) return null;

  const tokenHash = await hashSecret(token);
  const session = await env.DB.prepare(
    "SELECT device_id AS deviceId, expires_at AS expiresAt FROM vault_sessions WHERE token_hash = ?",
  )
    .bind(tokenHash)
    .first<{ deviceId: string; expiresAt: string }>();

  if (!session || Date.parse(session.expiresAt) <= Date.now()) {
    if (session) {
      await env.DB.prepare(
        "DELETE FROM vault_sessions WHERE token_hash = ?",
      )
        .bind(tokenHash)
        .run();
    }
    return null;
  }

  return { deviceId: session.deviceId, tokenHash };
}
