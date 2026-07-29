import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("ships a Windows one-click installer and launcher", async () => {
  const [installerEntry, installer, launcher, readme, packageJson] =
    await Promise.all([
      readFile(new URL("../install.cmd", import.meta.url), "utf8"),
      readFile(new URL("../install.ps1", import.meta.url), "utf8"),
      readFile(new URL("../start.cmd", import.meta.url), "utf8"),
      readFile(new URL("../README.md", import.meta.url), "utf8"),
      readFile(new URL("../package.json", import.meta.url), "utf8"),
    ]);

  assert.match(installerEntry, /ExecutionPolicy Bypass/);
  assert.match(installerEntry, /install\.ps1/);
  assert.match(installer, /22\.13\.0/);
  assert.match(installer, /OpenJS\.NodeJS\.LTS/);
  assert.match(installer, /"ci", "--no-audit", "--no-fund"/);
  assert.match(installer, /"run", "build"/);
  assert.match(launcher, /npm\.cmd run dev/);
  assert.match(readme, /Windows 一键安装/);
  assert.match(readme, /双击 `install\.cmd`/);
  assert.match(packageJson, /node --test tests\/\*\.test\.mjs/);
});
