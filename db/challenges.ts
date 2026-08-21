import { env } from "@/runtime/database";
import {
  createOpaqueToken,
  createSixDigitCode,
  hashSecret,
  safeEqual,
} from "./auth";

type ChallengeRow = {
  deviceId: string;
  purpose: string;
  codeHash: string;
  failedCount: number;
  expiresAt: string;
};

export async function createCodeChallenge(
  deviceId: string,
  purpose: "device" | "recovery-code",
  lifetimeMinutes = 10,
) {
  const token = createOpaqueToken();
  const code = createSixDigitCode();
  const tokenHash = await hashSecret(token);
  const codeHash = await hashSecret(`${token}:${code}`);
  const expiresAt = new Date(
    Date.now() + lifetimeMinutes * 60_000,
  ).toISOString();
  await env.DB.batch([
    env.DB.prepare(
      "DELETE FROM verification_challenges WHERE expires_at <= ? OR (device_id = ? AND purpose = ?)",
    ).bind(new Date().toISOString(), deviceId, purpose),
    env.DB.prepare(
      `INSERT INTO verification_challenges
        (token_hash, device_id, purpose, code_hash, failed_count, expires_at)
       VALUES (?, ?, ?, ?, 0, ?)`,
    ).bind(tokenHash, deviceId, purpose, codeHash, expiresAt),
  ]);
  return { token, code, tokenHash, expiresAt };
}

export async function consumeCodeChallenge(input: {
  token: string;
  code: string;
  purpose: "device" | "recovery-code";
  deviceId?: string;
}) {
  const tokenHash = await hashSecret(input.token);
  const challenge = await env.DB.prepare(
    `SELECT device_id AS deviceId, purpose, code_hash AS codeHash,
            failed_count AS failedCount, expires_at AS expiresAt
     FROM verification_challenges WHERE token_hash = ?`,
  )
    .bind(tokenHash)
    .first<ChallengeRow>();

  if (
    !challenge ||
    challenge.purpose !== input.purpose ||
    (input.deviceId && challenge.deviceId !== input.deviceId) ||
    Date.parse(challenge.expiresAt) <= Date.now()
  ) {
    if (challenge) {
      await env.DB.prepare(
        "DELETE FROM verification_challenges WHERE token_hash = ?",
      )
        .bind(tokenHash)
        .run();
    }
    return { ok: false as const, reason: "expired" as const };
  }

  const providedHash = await hashSecret(`${input.token}:${input.code}`);
  if (!safeEqual(providedHash, challenge.codeHash)) {
    const nextCount = challenge.failedCount + 1;
    if (nextCount >= 5) {
      await env.DB.prepare(
        "DELETE FROM verification_challenges WHERE token_hash = ?",
      )
        .bind(tokenHash)
        .run();
    } else {
      await env.DB.prepare(
        "UPDATE verification_challenges SET failed_count = ? WHERE token_hash = ?",
      )
        .bind(nextCount, tokenHash)
        .run();
    }
    return {
      ok: false as const,
      reason: "invalid" as const,
      attemptsRemaining: Math.max(0, 5 - nextCount),
    };
  }

  const consumed = await env.DB.prepare(
    "DELETE FROM verification_challenges WHERE token_hash = ? RETURNING device_id AS deviceId",
  )
    .bind(tokenHash)
    .first<{ deviceId: string }>();
  return consumed
    ? { ok: true as const, deviceId: consumed.deviceId }
    : { ok: false as const, reason: "expired" as const };
}

export async function createAccessChallenge(
  deviceId: string,
  purpose: "recovery-access",
  lifetimeMinutes = 10,
) {
  const token = createOpaqueToken();
  const tokenHash = await hashSecret(token);
  const expiresAt = new Date(
    Date.now() + lifetimeMinutes * 60_000,
  ).toISOString();
  await env.DB.prepare(
    `INSERT INTO verification_challenges
      (token_hash, device_id, purpose, code_hash, failed_count, expires_at)
     VALUES (?, ?, ?, '', 0, ?)`,
  )
    .bind(tokenHash, deviceId, purpose, expiresAt)
    .run();
  return token;
}

export async function consumeAccessChallenge(
  token: string,
  purpose: "recovery-access",
) {
  const tokenHash = await hashSecret(token);
  return env.DB.prepare(
    `DELETE FROM verification_challenges
     WHERE token_hash = ? AND purpose = ? AND expires_at > ?
     RETURNING device_id AS deviceId`,
  )
    .bind(tokenHash, purpose, new Date().toISOString())
    .first<{ deviceId: string }>();
}
