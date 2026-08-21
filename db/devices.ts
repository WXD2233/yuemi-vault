import { env } from "@/runtime/database";
import { createOpaqueToken, hashSecret, safeEqual } from "./auth";

export async function hasTrustedDeviceCredential(
  deviceId: string,
  credential: string,
) {
  if (!credential || credential.length > 128) return false;
  const row = await env.DB.prepare(
    "SELECT credential_hash AS credentialHash FROM trusted_devices WHERE id = ?",
  )
    .bind(deviceId)
    .first<{ credentialHash: string }>();
  if (!row?.credentialHash) return false;
  const providedHash = await hashSecret(credential);
  return safeEqual(providedHash, row.credentialHash);
}

export async function registerTrustedDevice(input: {
  deviceId: string;
  deviceName: string;
  browser: string;
  location: string;
}) {
  const credential = createOpaqueToken();
  const credentialHash = await hashSecret(credential);
  await env.DB.prepare(
    `INSERT INTO trusted_devices
      (id, credential_hash, device_name, browser, location, last_active, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       credential_hash = excluded.credential_hash,
       device_name = excluded.device_name,
       browser = excluded.browser,
       location = excluded.location,
       last_active = excluded.last_active`,
  )
    .bind(
      input.deviceId,
      credentialHash,
      input.deviceName,
      input.browser,
      input.location,
      "刚刚",
      new Date().toISOString().slice(0, 10),
    )
    .run();
  return credential;
}

export async function touchTrustedDevice(deviceId: string) {
  await env.DB.prepare(
    "UPDATE trusted_devices SET last_active = ? WHERE id = ?",
  )
    .bind("刚刚", deviceId)
    .run();
}
