import { env, type SqlitePreparedStatement } from "@/runtime/database";
import {
  DEFAULT_MASTER_PASSWORD_HASH,
  LEGACY_DEFAULT_MASTER_PASSWORD_HASH,
} from "./security-constants";

const OLDER_MASTER_PASSWORD_HASH =
  "3651389d80ea709f76a95ec93ca42343eb35a31525020cc9b7a58100159a139c";
const LEGACY_MASTER_PASSWORD_HASH =
  "c079208ec8d20c1aab38ffdc12de7252735ba1ab334e19b56bc1c237f89aaced";

export async function ensureVaultSchema() {
  if (!env.DB) {
    throw new Error("The local SQLite database is unavailable.");
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
        notes TEXT NOT NULL DEFAULT '',
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
        email TEXT NOT NULL DEFAULT 'w***@example.com',
        master_password_hash TEXT NOT NULL DEFAULT '${DEFAULT_MASTER_PASSWORD_HASH}',
        max_failed_attempts INTEGER NOT NULL DEFAULT 5,
        lockout_minutes INTEGER NOT NULL DEFAULT 15,
        smtp_provider TEXT NOT NULL DEFAULT '',
        smtp_host TEXT NOT NULL DEFAULT '',
        smtp_port INTEGER NOT NULL DEFAULT 465,
        smtp_security TEXT NOT NULL DEFAULT 'tls',
        smtp_username TEXT NOT NULL DEFAULT '',
        smtp_secret_cipher TEXT NOT NULL DEFAULT '',
        smtp_secret_iv TEXT NOT NULL DEFAULT '',
        smtp_from_name TEXT NOT NULL DEFAULT '钥密',
        smtp_enabled INTEGER NOT NULL DEFAULT 0,
        smtp_feature_enabled INTEGER NOT NULL DEFAULT 0,
        smtp_verified_at TEXT
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS login_attempts (
        device_id TEXT PRIMARY KEY NOT NULL,
        failed_count INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS vault_sessions (
        token_hash TEXT PRIMARY KEY NOT NULL,
        device_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS verification_challenges (
        token_hash TEXT PRIMARY KEY NOT NULL,
        device_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),
  ]);

  const entryColumns = await env.DB.prepare(
    "PRAGMA table_info(vault_entries)",
  ).all<{ name: string }>();
  const existingEntryColumns = new Set(
    entryColumns.results.map((column) => column.name),
  );
  if (!existingEntryColumns.has("notes")) {
    await env.DB.prepare(
      "ALTER TABLE vault_entries ADD COLUMN notes TEXT NOT NULL DEFAULT ''",
    ).run();
  }

  const settingsColumns = await env.DB.prepare(
    "PRAGMA table_info(security_settings)",
  ).all<{ name: string }>();
  const existingColumns = new Set(
    settingsColumns.results.map((column) => column.name),
  );

  if (!existingColumns.has("master_password_hash")) {
    await env.DB.prepare(
      `ALTER TABLE security_settings ADD COLUMN master_password_hash TEXT NOT NULL DEFAULT '${DEFAULT_MASTER_PASSWORD_HASH}'`,
    ).run();
  }
  if (!existingColumns.has("max_failed_attempts")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN max_failed_attempts INTEGER NOT NULL DEFAULT 5",
    ).run();
  }
  if (!existingColumns.has("lockout_minutes")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN lockout_minutes INTEGER NOT NULL DEFAULT 15",
    ).run();
  }
  if (!existingColumns.has("smtp_provider")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_provider TEXT NOT NULL DEFAULT ''",
    ).run();
  }
  if (!existingColumns.has("smtp_host")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_host TEXT NOT NULL DEFAULT ''",
    ).run();
  }
  if (!existingColumns.has("smtp_port")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_port INTEGER NOT NULL DEFAULT 465",
    ).run();
  }
  if (!existingColumns.has("smtp_security")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_security TEXT NOT NULL DEFAULT 'tls'",
    ).run();
  }
  if (!existingColumns.has("smtp_username")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_username TEXT NOT NULL DEFAULT ''",
    ).run();
  }
  if (!existingColumns.has("smtp_secret_cipher")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_secret_cipher TEXT NOT NULL DEFAULT ''",
    ).run();
  }
  if (!existingColumns.has("smtp_secret_iv")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_secret_iv TEXT NOT NULL DEFAULT ''",
    ).run();
  }
  if (!existingColumns.has("smtp_from_name")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_from_name TEXT NOT NULL DEFAULT '钥密'",
    ).run();
  }
  if (!existingColumns.has("smtp_enabled")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_enabled INTEGER NOT NULL DEFAULT 0",
    ).run();
  }
  if (!existingColumns.has("smtp_feature_enabled")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_feature_enabled INTEGER NOT NULL DEFAULT 0",
    ).run();
  }
  if (!existingColumns.has("smtp_verified_at")) {
    await env.DB.prepare(
      "ALTER TABLE security_settings ADD COLUMN smtp_verified_at TEXT",
    ).run();
  }

  await env.DB.prepare(
    "UPDATE security_settings SET master_password_hash = ? WHERE id = 1 AND master_password_hash IN (?, ?)",
  )
    .bind(
      DEFAULT_MASTER_PASSWORD_HASH,
      OLDER_MASTER_PASSWORD_HASH,
      LEGACY_MASTER_PASSWORD_HASH,
    )
    .run();

  await env.DB.prepare(
    "UPDATE security_settings SET master_password_hash = ? WHERE id = 1 AND master_password_hash = ? AND NOT EXISTS (SELECT 1 FROM vault_entries WHERE password_cipher != 'encrypted-demo-value' AND password_iv != 'demo-iv')",
  )
    .bind(
      DEFAULT_MASTER_PASSWORD_HASH,
      LEGACY_DEFAULT_MASTER_PASSWORD_HASH,
    )
    .run();

  await env.DB.prepare(
    "UPDATE security_settings SET two_factor_enabled = 0 WHERE email = '' OR email LIKE '%*%'",
  ).run();

  const entryCount = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM vault_entries",
  ).first<{ total: number }>();
  const deviceCount = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM trusted_devices",
  ).first<{ total: number }>();
  const settingsCount = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM security_settings",
  ).first<{ total: number }>();

  const seedStatements: SqlitePreparedStatement[] = [];

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
        "INSERT INTO security_settings (id, two_factor_enabled, email, master_password_hash, max_failed_attempts, lockout_minutes) VALUES (1, 1, ?, ?, 5, 15)",
      ).bind("w***@example.com", DEFAULT_MASTER_PASSWORD_HASH),
    );
  }

  if (seedStatements.length) {
    await env.DB.batch(seedStatements);
  }
}
