import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("ships a loopback-first VPS deployment with optional standalone HTTPS", async () => {
  const [
    installer,
    dockerStarter,
    compose,
    dockerfile,
    caddyfile,
    nextConfig,
    healthRoute,
    dockerWorkflow,
    readme,
    packageJson,
  ] =
    await Promise.all([
      readFile(new URL("../install-vps.sh", import.meta.url), "utf8"),
      readFile(new URL("../docker-start.sh", import.meta.url), "utf8"),
      readFile(new URL("../compose.yaml", import.meta.url), "utf8"),
      readFile(new URL("../Dockerfile", import.meta.url), "utf8"),
      readFile(new URL("../Caddyfile", import.meta.url), "utf8"),
      readFile(new URL("../next.config.ts", import.meta.url), "utf8"),
      readFile(new URL("../app/api/health/route.ts", import.meta.url), "utf8"),
      readFile(
        new URL("../.github/workflows/docker-image.yml", import.meta.url),
        "utf8",
      ),
      readFile(new URL("../README.md", import.meta.url), "utf8"),
      readFile(new URL("../package.json", import.meta.url), "utf8"),
    ]);

  assert.match(installer, /^#!\/usr\/bin\/env bash/);
  assert.match(installer, /openssl rand -hex/);
  assert.match(installer, /SMTP_CONFIG_KEY/);
  assert.match(installer, /YUEMI_INITIAL_PASSWORD/);
  assert.match(installer, /BIND_ADDRESS=127\.0\.0\.1/);
  assert.match(installer, /--profile standalone-https/);
  assert.doesNotMatch(installer, /首次默认主密码：12345678/);
  assert.match(dockerStarter, /up -d --build --remove-orphans app/);
  assert.match(dockerStarter, /BIND_ADDRESS=127\.0\.0\.1/);
  assert.doesNotMatch(dockerStarter, /standalone-https/);
  assert.match(compose, /127\.0\.0\.1/);
  assert.match(compose, /\$\{HTTP_PORT:-51213\}:3000/);
  assert.match(compose, /profiles:[\s\S]*standalone-https/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /pids_limit: 256/);
  assert.match(compose, /api\/health/);
  assert.match(dockerfile, /node:24-bookworm-slim/);
  assert.match(dockerfile, /USER node/);
  assert.match(dockerfile, /dist\/standalone/);
  assert.doesNotMatch(dockerfile, /COPY --from=builder --chown=node:node \/app \/app/);
  assert.match(nextConfig, /output: "standalone"/);
  assert.match(healthRoute, /SELECT 1 AS healthy/);
  assert.match(dockerWorkflow, /ghcr\.io\/\$\{\{ github\.repository \}\}/);
  assert.match(dockerWorkflow, /linux\/amd64,linux\/arm64/);
  assert.match(caddyfile, /reverse_proxy app:3000/);
  assert.match(caddyfile, /Content-Security-Policy/);
  assert.match(readme, /默认只监听 `127\.0\.0\.1:51213`/);
  assert.match(readme, /不要把 51213 端口直接开放到公网/);
  assert.match(readme, /随机初始主密码/);
  assert.match(packageJson, /"security:audit"/);
});

test("uses local SQLite and pinned TLS server names", async () => {
  const [viteConfig, databaseAdapter, socketsAdapter] = await Promise.all([
    readFile(new URL("../vite.config.ts", import.meta.url), "utf8"),
    readFile(new URL("../runtime/database.ts", import.meta.url), "utf8"),
    readFile(new URL("../runtime/sockets.ts", import.meta.url), "utf8"),
  ]);
  assert.match(viteConfig, /plugins: \[vinext\(\)\]/);
  assert.doesNotMatch(viteConfig, /cloudflare|sites\(/i);
  assert.match(databaseAdapter, /DatabaseSync/);
  assert.match(databaseAdapter, /PRAGMA journal_mode=WAL/);
  assert.match(databaseAdapter, /BEGIN IMMEDIATE/);
  assert.match(socketsAdapter, /tls\.connect/);
  assert.match(socketsAdapter, /servername/);
});
