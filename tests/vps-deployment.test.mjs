import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("ships an independent VPS deployment", async () => {
  const [installer, compose, dockerfile, caddyfile, readme, packageJson] =
    await Promise.all([
      readFile(new URL("../install-vps.sh", import.meta.url), "utf8"),
      readFile(new URL("../compose.yaml", import.meta.url), "utf8"),
      readFile(new URL("../Dockerfile", import.meta.url), "utf8"),
      readFile(new URL("../Caddyfile", import.meta.url), "utf8"),
      readFile(new URL("../README.md", import.meta.url), "utf8"),
      readFile(new URL("../package.json", import.meta.url), "utf8"),
    ]);

  assert.match(installer, /^#!\/usr\/bin\/env bash/);
  assert.match(installer, /download\.docker\.com\/linux\/\$\{ID\}/);
  assert.match(installer, /docker-compose-plugin/);
  assert.match(installer, /docker compose[\s\S]*up -d --build/);
  assert.match(compose, /vault_data:\/data/);
  assert.match(compose, /caddy:2\.10-alpine/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(dockerfile, /node:24-bookworm-slim/);
  assert.match(dockerfile, /USER node/);
  assert.match(caddyfile, /reverse_proxy app:3000/);
  assert.match(readme, /VPS 一键安装/);
  assert.match(readme, /12345678/);
  assert.match(packageJson, /"start": "vinext start"/);
  assert.doesNotMatch(packageJson, /start:vps|build:vps/);
});

test("uses only local SQLite and Node socket adapters", async () => {
  const [viteConfig, databaseAdapter, socketsAdapter] = await Promise.all([
    readFile(new URL("../vite.config.ts", import.meta.url), "utf8"),
    readFile(
      new URL("../runtime/database.ts", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../runtime/sockets.ts", import.meta.url),
      "utf8",
    ),
  ]);

  assert.match(viteConfig, /plugins: \[vinext\(\)\]/);
  assert.doesNotMatch(viteConfig, /cloudflare|sites\(/i);
  assert.match(databaseAdapter, /DatabaseSync/);
  assert.match(databaseAdapter, /PRAGMA journal_mode=WAL/);
  assert.match(databaseAdapter, /BEGIN IMMEDIATE/);
  assert.match(socketsAdapter, /tls\.connect/);
  assert.match(socketsAdapter, /startTls\(\)/);
});
