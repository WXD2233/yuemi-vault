import { env } from "cloudflare:workers";

export async function ensureVaultSchema() {
  if (!env.DB) {
    throw new Error("Cloudflare D1 binding `DB` is unavailable.");
  }

  await env.DB.batch([
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS vault_entries (
        id TEXT PRIMARY KEY NOT NULL,
        project_name TEXT NOT NULL,
        account TEXT NOT NULL,
        category TEXT NOT NULL,
        security_status TEXT NOT NULL DEFAULT '安全',
        password_cipher TEXT NOT NULL,
        password_iv TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS trusted_devices (
        id TEXT PRIMARY KEY NOT NULL,
        device_name TEXT NOT NULL,
        browser TEXT NOT NULL,
        location TEXT NOT NULL,
        last_active TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS security_settings (
        id INTEGER PRIMARY KEY NOT NULL,
        two_factor_enabled INTEGER NOT NULL DEFAULT 1,
        email TEXT NOT NULL DEFAULT 'w***@example.com'
      )
    `),
  ]);

  const entryCount = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM vault_entries",
  ).first<{ total: number }>();
  const deviceCount = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM trusted_devices",
  ).first<{ total: number }>();
  const settingsCount = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM security_settings",
  ).first<{ total: number }>();

  const seedStatements: D1PreparedStatement[] = [];

  if (!entryCount?.total) {
    seedStatements.push(
      env.DB.prepare(
        "INSERT INTO vault_entries (id, project_name, account, category, security_status, password_cipher, password_iv, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).bind(
        "entry-github",
        "GitHub",
        "dev***@example.com",
        "开发工具",
        "安全",
        "encrypted-demo-value",
        "demo-iv",
        "2026-07-26 14:30",
      ),
      env.DB.prepare(
        "INSERT INTO vault_entries (id, project_name, account, category, security_status, password_cipher, password_iv, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).bind(
        "entry-email",
        "工作邮箱",
        "w***@example.com",
        "电子邮件",
        "安全",
        "encrypted-demo-value",
        "demo-iv",
        "2026-07-26 10:15",
      ),
      env.DB.prepare(
        "INSERT INTO vault_entries (id, project_name, account, category, security_status, password_cipher, password_iv, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).bind(
        "entry-cloud",
        "云服务器",
        "root-admin",
        "服务器",
        "一般",
        "encrypted-demo-value",
        "demo-iv",
        "2026-07-25 09:42",
      ),
      env.DB.prepare(
        "INSERT INTO vault_entries (id, project_name, account, category, security_status, password_cipher, password_iv, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).bind(
        "entry-bank",
        "网上银行",
        "6222 **** 8831",
        "金融",
        "安全",
        "encrypted-demo-value",
        "demo-iv",
        "2026-07-24 16:08",
      ),
    );
  }

  if (!deviceCount?.total) {
    seedStatements.push(
      env.DB.prepare(
        "INSERT INTO trusted_devices (id, device_name, browser, location, last_active, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      ).bind(
        "trusted-macbook",
        "MacBook Pro",
        "Safari 18",
        "香港",
        "今天 09:42",
        "2026-07-18",
      ),
      env.DB.prepare(
        "INSERT INTO trusted_devices (id, device_name, browser, location, last_active, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      ).bind(
        "trusted-iphone",
        "iPhone 16",
        "钥密移动端",
        "香港",
        "昨天 22:16",
        "2026-07-20",
      ),
    );
  }

  if (!settingsCount?.total) {
    seedStatements.push(
      env.DB.prepare(
        "INSERT INTO security_settings (id, two_factor_enabled, email) VALUES (1, 1, ?)",
      ).bind("w***@example.com"),
    );
  }

  if (seedStatements.length) {
    await env.DB.batch(seedStatements);
  }
}
