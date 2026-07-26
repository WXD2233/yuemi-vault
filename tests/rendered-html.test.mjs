import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

test("builds the 钥密 unlock experience", async () => {
  const [page, layout] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    access(new URL("../dist/server/index.js", import.meta.url)),
  ]);

  assert.match(layout, /钥密 · 安全密码管理器/);
  assert.match(page, /解锁钥密/);
  assert.match(page, /请输入主密码进入你的加密密码库/);
  assert.match(page, /KeySafe2026!/);
  assert.doesNotMatch(
    `${page}\n${layout}`,
    /codex-preview|SkeletonPreview|react-loading-skeleton/,
  );
});

test("includes the requested security and device-management flows", async () => {
  const [page, layout, schema, unlockRoute, vaultRoute] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/auth/unlock/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/vault/route.ts", import.meta.url), "utf8"),
  ]);

  assert.match(page, /验证新设备/);
  assert.match(page, /新设备二次验证/);
  assert.match(page, /删除已加入的设备/);
  assert.match(page, /confirmDeviceDeletion/);
  assert.match(page, /AES-GCM/);
  assert.match(layout, /钥密 · 安全密码管理器/);
  assert.match(schema, /trustedDevices/);
  assert.match(schema, /vaultEntries/);
  assert.match(schema, /loginAttempts/);
  assert.match(schema, /vaultSessions/);
  assert.match(unlockRoute, /maxFailedAttempts/);
  assert.match(unlockRoute, /lockedUntil/);
  assert.match(unlockRoute, /createVaultSession/);
  assert.match(vaultRoute, /getVaultSession/);
  assert.match(page, /密码错误锁定策略/);
});
