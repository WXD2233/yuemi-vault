import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("builds the complete responsive Chinese vault interface", async () => {
  const [page, layout, styles] = await Promise.all([
    read("../app/page.tsx"),
    read("../app/layout.tsx"),
    read("../app/globals.css"),
    access(new URL("../dist/server/index.js", import.meta.url)),
  ]);
  assert.match(layout, /钥密 · 安全密码管理器/);
  assert.match(layout, /theme-init\.js/);
  assert.doesNotMatch(layout, /dangerouslySetInnerHTML/);
  assert.match(page, /解锁钥密/);
  assert.match(page, /type=\{showMasterPassword \? "text" : "password"\}/);
  assert.match(page, /密码记录/);
  assert.match(page, /修改主密码/);
  assert.match(page, /自动锁定/);
  assert.match(page, /"violet"/);
  assert.match(page, /"glacier"/);
  assert.match(page, /"amber"/);
  assert.match(styles, /@media \(max-width: 760px\)/);
  assert.match(styles, /@media \(max-width: 480px\)/);
});

test("uses random one-time codes and credential-bound trusted devices", async () => {
  const [unlock, verify, challenges, devices, schema] = await Promise.all([
    read("../app/api/auth/unlock/route.ts"),
    read("../app/api/auth/verify/route.ts"),
    read("../db/challenges.ts"),
    read("../db/devices.ts"),
    read("../db/schema.ts"),
  ]);
  const combined = `${unlock}\n${verify}\n${challenges}`;
  assert.doesNotMatch(combined, /246810|FIXED_VERIFICATION_CODE|DEMO_CODE/);
  assert.match(challenges, /createSixDigitCode/);
  assert.match(challenges, /codeHash/);
  assert.match(challenges, /DELETE FROM verification_challenges[\s\S]*RETURNING/);
  assert.match(challenges, /failedCount/);
  assert.match(devices, /credential_hash/);
  assert.match(devices, /safeEqual/);
  assert.match(schema, /credentialHash/);
  assert.match(unlock, /deviceCredential/);
  assert.match(unlock, /enforceRateLimit/);
  assert.match(unlock, /attemptKey/);
});

test("recovers locally without resetting or emailing a master password", async () => {
  const [page, recovery, vault, schema] = await Promise.all([
    read("../app/page.tsx"),
    read("../app/api/auth/recovery/route.ts"),
    read("../app/api/vault/route.ts"),
    read("../db/schema.ts"),
  ]);
  assert.match(page, /createRecoveryMaterial/);
  assert.match(page, /decryptRecoveryMaterial/);
  assert.match(page, /离线恢复密钥/);
  assert.match(recovery, /action === "request-code"/);
  assert.match(recovery, /action === "verify-code"/);
  assert.match(recovery, /action === "get-material"/);
  assert.doesNotMatch(recovery, /send-password|新的主密码|master_password_hash/);
  assert.match(vault, /action === "set-recovery-material"/);
  assert.match(schema, /recoveryCipher/);
  assert.match(schema, /recoverySalt/);
});

test("uses current password KDF parameters and encrypted migration", async () => {
  const [page, auth, ensure, vault] = await Promise.all([
    read("../app/page.tsx"),
    read("../db/auth.ts"),
    read("../db/ensure.ts"),
    read("../app/api/vault/route.ts"),
  ]);
  assert.match(auth, /CURRENT_MASTER_PASSWORD_ITERATIONS/);
  assert.match(auth, /timingSafeEqual/);
  assert.match(ensure, /YUEMI_INITIAL_PASSWORD/);
  assert.match(ensure, /NODE_ENV === "production"/);
  assert.match(page, /yv3\.600000/);
  assert.match(page, /LEGACY_ENCRYPTED_RECORD_PREFIX/);
  assert.match(page, /BACKUP_KDF_ITERATIONS = 600_000/);
  assert.match(vault, /master_password_salt/);
  assert.match(vault, /requires_password_change = 0/);
});

test("hardens SMTP, request bodies, sessions and browser responses", async () => {
  const [smtpConfig, smtp, sockets, httpSecurity, proxy, vault] =
    await Promise.all([
      read("../db/smtp-config.ts"),
      read("../db/smtp.ts"),
      read("../runtime/sockets.ts"),
      read("../db/http-security.ts"),
      read("../proxy.ts"),
      read("../app/api/vault/route.ts"),
    ]);
  assert.match(smtpConfig, /process\.env\.SMTP_CONFIG_KEY/);
  assert.match(smtpConfig, /resolvePublicSmtpAddress/);
  assert.match(smtpConfig, /不能解析到本机、内网或保留地址/);
  assert.match(smtp, /endpoint\.address/);
  assert.match(sockets, /servername/);
  assert.match(httpSecurity, /maxBytes/);
  assert.match(httpSecurity, /请求内容过大/);
  assert.match(proxy, /Content-Security-Policy/);
  assert.match(proxy, /Strict-Transport-Security/);
  assert.match(vault, /action === "logout"/);
});

test("keeps browser import and encrypted backup inside settings", async () => {
  const [page, styles] = await Promise.all([
    read("../app/page.tsx"),
    read("../app/globals.css"),
  ]);
  assert.match(page, /parseBrowserPasswordCsv/);
  assert.match(page, /Chrome \/ Edge/);
  assert.match(page, /yuemi-encrypted-vault-backup/);
  assert.match(page, /downloadEncryptedBackup/);
  assert.match(page, /decryptEncryptedBackup/);
  const vaultView = page.slice(
    page.indexOf("function VaultView"),
    page.indexOf("function SettingsView"),
  );
  const settingsView = page.slice(page.indexOf("function SettingsView"));
  assert.doesNotMatch(vaultView, /vault-transfer-title/);
  assert.match(settingsView, /vault-transfer-title/);
  assert.match(styles, /\.transfer-actions/);
});
