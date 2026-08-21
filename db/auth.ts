import { env } from "@/runtime/database";
import { timingSafeEqual } from "node:crypto";
import {
  CURRENT_MASTER_PASSWORD_ITERATIONS,
  LEGACY_MASTER_PASSWORD_ITERATIONS,
  LEGACY_MASTER_PASSWORD_SALT,
} from "./security-constants";

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

export async function hashMasterPassword(
  value: string,
  salt = LEGACY_MASTER_PASSWORD_SALT,
  iterations = LEGACY_MASTER_PASSWORD_ITERATIONS,
) {
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
      salt: new TextEncoder().encode(salt),
      iterations,
    },
    keyMaterial,
    256,
  );
  return Array.from(new Uint8Array(derived))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function createMasterPasswordSalt() {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(24)));
}

export function currentMasterPasswordIterations() {
  return CURRENT_MASTER_PASSWORD_ITERATIONS;
}

export function safeEqual(left: string, right: string) {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  return (
    leftBytes.byteLength === rightBytes.byteLength &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

export async function verifyMasterPassword(
  value: string,
  expectedHash: string,
  salt: string,
  iterations: number,
) {
  const providedHash = await hashMasterPassword(value, salt, iterations);
  return safeEqual(providedHash, expectedHash);
}

export function createSixDigitCode() {
  const values = crypto.getRandomValues(new Uint32Array(1));
  return String(values[0] % 1_000_000).padStart(6, "0");
}

export function createOpaqueToken() {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function createVaultSession(deviceId: string) {
  const token = createOpaqueToken();
  const tokenHash = await hashSecret(token);
  const expiresAt = new Date(Date.now() + 2 * 60 * 60_000).toISOString();

  await env.DB.batch([
    env.DB.prepare("DELETE FROM vault_sessions WHERE expires_at <= ?").bind(
      new Date().toISOString(),
    ),
    env.DB.prepare(
      "INSERT INTO vault_sessions (token_hash, device_id, expires_at) VALUES (?, ?, ?)",
    ).bind(tokenHash, deviceId, expiresAt),
  ]);

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
