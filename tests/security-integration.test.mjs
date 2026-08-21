import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

async function waitForServer(url, child) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`测试服务器提前退出，代码 ${child.exitCode}`);
    }
    try {
      const response = await fetch(`${url}/api/auth/recovery`);
      if (response.ok) return;
    } catch {
      // The server is still starting.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
  }
  throw new Error("等待测试服务器启动超时");
}

async function requestJson(base, path, init = {}) {
  const response = await fetch(`${base}${path}`, init);
  return {
    response,
    body: await response.json().catch(() => ({})),
  };
}

test("enforces the production authentication lifecycle", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "yuemi-security-"));
  const port = 44_000 + Math.floor(Math.random() * 8_000);
  const base = `http://127.0.0.1:${port}`;
  const child = spawn(
    process.execPath,
    [join(projectRoot, "node_modules", "vinext", "dist", "cli.js"), "start"],
    {
      cwd: projectRoot,
      env: {
        ...process.env,
        NODE_ENV: "production",
        HOSTNAME: "127.0.0.1",
        PORT: String(port),
        YUEMI_DATA_DIR: dataDirectory,
        YUEMI_INITIAL_PASSWORD: "AuditInitial-A1!",
        SMTP_CONFIG_KEY:
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      },
      stdio: "ignore",
    },
  );

  try {
    await waitForServer(base, child);

    const page = await fetch(`${base}/`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-security-policy") ?? "", /default-src 'self'/);
    assert.equal(page.headers.get("x-frame-options"), "DENY");

    const oversized = await requestJson(base, "/api/auth/unlock", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(20_000) }),
    });
    assert.equal(oversized.response.status, 413);

    const first = await requestJson(base, "/api/auth/unlock", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "198.51.100.10",
      },
      body: JSON.stringify({
        deviceId: "audit-device-0001",
        masterPassword: "AuditInitial-A1!",
        deviceName: "安全测试设备",
        browser: "测试浏览器",
        location: "测试网络",
      }),
    });
    assert.equal(first.response.status, 200);
    assert.ok(first.body.sessionToken);
    assert.ok(first.body.deviceCredential);

    const firstHeaders = {
      authorization: `Bearer ${first.body.sessionToken}`,
      "content-type": "application/json",
    };
    const firstVault = await requestJson(base, "/api/vault", {
      headers: firstHeaders,
    });
    assert.equal(firstVault.response.status, 200);
    assert.equal(firstVault.body.settings.requiresPasswordChange, true);
    assert.equal("credentialHash" in firstVault.body.devices[0], false);

    const forbiddenSetting = await requestJson(base, "/api/vault", {
      method: "POST",
      headers: firstHeaders,
      body: JSON.stringify({
        action: "set-lockout-policy",
        maxFailedAttempts: 3,
        lockoutMinutes: 5,
      }),
    });
    assert.equal(forbiddenSetting.response.status, 428);

    const changed = await requestJson(base, "/api/vault", {
      method: "POST",
      headers: firstHeaders,
      body: JSON.stringify({
        action: "change-master-password",
        currentPassword: "AuditInitial-A1!",
        newPassword: "AuditNew-Password2!",
        entries: [],
      }),
    });
    assert.equal(changed.response.status, 200);

    const revoked = await requestJson(base, "/api/vault", {
      headers: firstHeaders,
    });
    assert.equal(revoked.response.status, 401);

    const oldPassword = await requestJson(base, "/api/auth/unlock", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "198.51.100.11",
      },
      body: JSON.stringify({
        deviceId: "audit-device-0001",
        deviceCredential: first.body.deviceCredential,
        masterPassword: "AuditInitial-A1!",
      }),
    });
    assert.equal(oldPassword.response.status, 401);

    const second = await requestJson(base, "/api/auth/unlock", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "198.51.100.12",
      },
      body: JSON.stringify({
        deviceId: "audit-device-0001",
        deviceCredential: first.body.deviceCredential,
        masterPassword: "AuditNew-Password2!",
      }),
    });
    assert.equal(second.response.status, 200);
    assert.ok(second.body.sessionToken);

    const secondHeaders = {
      authorization: `Bearer ${second.body.sessionToken}`,
      "content-type": "application/json",
    };
    const secondVault = await requestJson(base, "/api/vault", {
      headers: secondHeaders,
    });
    assert.equal(secondVault.body.settings.requiresPasswordChange, false);

    const logout = await requestJson(base, "/api/vault", {
      method: "POST",
      headers: secondHeaders,
      body: JSON.stringify({ action: "logout" }),
    });
    assert.equal(logout.response.status, 200);
    const loggedOut = await requestJson(base, "/api/vault", {
      headers: secondHeaders,
    });
    assert.equal(loggedOut.response.status, 401);
  } finally {
    child.kill("SIGTERM");
    await new Promise((resolveExit) => {
      if (child.exitCode !== null) return resolveExit();
      child.once("exit", resolveExit);
      setTimeout(resolveExit, 2_000).unref();
    });
    await rm(dataDirectory, { recursive: true, force: true });
  }
});
