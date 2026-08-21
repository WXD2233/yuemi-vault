import { env, type SqlitePreparedStatement } from "@/runtime/database";
import {
  createMasterPasswordSalt,
  currentMasterPasswordIterations,
  hashMasterPassword,
} from "./auth";
import {
  DEFAULT_MASTER_PASSWORD,
  DEFAULT_MASTER_PASSWORD_HASH,
  LEGACY_DEFAULT_MASTER_PASSWORD_HASH,
} from "./security-constants";

const OLDER_MASTER_PASSWORD_HASH =
  "3651389d80ea709f76a95ec93ca42343eb35a31525020cc9b7a58100159a139c";
const LEGACY_MASTER_PASSWORD_HASH =
  "c079208ec8d20c1aab38ffdc12de7252735ba1ab334e19b56bc1c237f89aaced";

async function columnNames(table: string) {
  const columns = await env.DB.prepare(`PRAGMA table_info(${table})`).all<{
    name: string;
  }>();
  return new Set(columns.results.map((column) => column.name));
}

async function addColumn(
  columns: Set<string>,
  table: string,
  name: string,
  declaration: string,
) {
  if (!columns.has(name)) {
    await env.DB.prepare(
      `ALTER TABLE ${table} ADD COLUMN ${name} ${declaration}`,
    ).run();
    columns.add(name);
  }
}

let schemaReady: Promise<void> | null = null;

async function initializeVaultSchema() {
  if (!env.DB) throw new Error("本地 SQLite 数据库不可用");

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
        credential_hash TEXT NOT NULL DEFAULT '',
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
        two_factor_enabled INTEGER NOT NULL DEFAULT 0,
        email TEXT NOT NULL DEFAULT '',
        master_password_hash TEXT NOT NULL DEFAULT '${DEFAULT_MASTER_PASSWORD_HASH}',
        master_password_salt TEXT NOT NULL DEFAULT 'yuemi-master-v1',
        master_password_iterations INTEGER NOT NULL DEFAULT 100000,
        requires_password_change INTEGER NOT NULL DEFAULT 1,
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
        smtp_verified_at TEXT,
        recovery_cipher TEXT NOT NULL DEFAULT '',
        recovery_iv TEXT NOT NULL DEFAULT '',
        recovery_salt TEXT NOT NULL DEFAULT '',
        recovery_iterations INTEGER NOT NULL DEFAULT 600000
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
        purpose TEXT NOT NULL DEFAULT 'device',
        code_hash TEXT NOT NULL DEFAULT '',
        failed_count INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),
  ]);

  const entryColumns = await columnNames("vault_entries");
  await addColumn(entryColumns, "vault_entries", "notes", "TEXT NOT NULL DEFAULT ''");

  const deviceColumns = await columnNames("trusted_devices");
  await addColumn(
    deviceColumns,
    "trusted_devices",
    "credential_hash",
    "TEXT NOT NULL DEFAULT ''",
  );

  const settingsColumns = await columnNames("security_settings");
  await addColumn(
    settingsColumns,
    "security_settings",
    "master_password_hash",
    `TEXT NOT NULL DEFAULT '${DEFAULT_MASTER_PASSWORD_HASH}'`,
  );
  await addColumn(
    settingsColumns,
    "security_settings",
    "master_password_salt",
    "TEXT NOT NULL DEFAULT 'yuemi-master-v1'",
  );
  await addColumn(
    settingsColumns,
    "security_settings",
    "master_password_iterations",
    "INTEGER NOT NULL DEFAULT 100000",
  );
  const hadRequiresPasswordChange = settingsColumns.has("requires_password_change");
  await addColumn(
    settingsColumns,
    "security_settings",
    "requires_password_change",
    "INTEGER NOT NULL DEFAULT 0",
  );

  const settingsMigrations: Array<[string, string]> = [
    ["max_failed_attempts", "INTEGER NOT NULL DEFAULT 5"],
    ["lockout_minutes", "INTEGER NOT NULL DEFAULT 15"],
    ["smtp_provider", "TEXT NOT NULL DEFAULT ''"],
    ["smtp_host", "TEXT NOT NULL DEFAULT ''"],
    ["smtp_port", "INTEGER NOT NULL DEFAULT 465"],
    ["smtp_security", "TEXT NOT NULL DEFAULT 'tls'"],
    ["smtp_username", "TEXT NOT NULL DEFAULT ''"],
    ["smtp_secret_cipher", "TEXT NOT NULL DEFAULT ''"],
    ["smtp_secret_iv", "TEXT NOT NULL DEFAULT ''"],
    ["smtp_from_name", "TEXT NOT NULL DEFAULT '钥密'"],
    ["smtp_enabled", "INTEGER NOT NULL DEFAULT 0"],
    ["smtp_feature_enabled", "INTEGER NOT NULL DEFAULT 0"],
    ["smtp_verified_at", "TEXT"],
    ["recovery_cipher", "TEXT NOT NULL DEFAULT ''"],
    ["recovery_iv", "TEXT NOT NULL DEFAULT ''"],
    ["recovery_salt", "TEXT NOT NULL DEFAULT ''"],
    ["recovery_iterations", "INTEGER NOT NULL DEFAULT 600000"],
  ];
  for (const [name, declaration] of settingsMigrations) {
    await addColumn(settingsColumns, "security_settings", name, declaration);
  }

  const challengeColumns = await columnNames("verification_challenges");
  await addColumn(
    challengeColumns,
    "verification_challenges",
    "purpose",
    "TEXT NOT NULL DEFAULT 'device'",
  );
  await addColumn(
    challengeColumns,
    "verification_challenges",
    "code_hash",
    "TEXT NOT NULL DEFAULT ''",
  );
  await addColumn(
    challengeColumns,
    "verification_challenges",
    "failed_count",
    "INTEGER NOT NULL DEFAULT 0",
  );

  await env.DB.prepare(
    "UPDATE security_settings SET master_password_hash = ? WHERE id = 1 AND master_password_hash IN (?, ?)",
  )
    .bind(DEFAULT_MASTER_PASSWORD_HASH, OLDER_MASTER_PASSWORD_HASH, LEGACY_MASTER_PASSWORD_HASH)
    .run();

  await env.DB.prepare(
    "UPDATE security_settings SET master_password_hash = ? WHERE id = 1 AND master_password_hash = ? AND NOT EXISTS (SELECT 1 FROM vault_entries WHERE password_cipher != 'encrypted-demo-value' AND password_iv != 'demo-iv')",
  )
    .bind(DEFAULT_MASTER_PASSWORD_HASH, LEGACY_DEFAULT_MASTER_PASSWORD_HASH)
    .run();

  if (!hadRequiresPasswordChange) {
    await env.DB.prepare(
      "UPDATE security_settings SET requires_password_change = CASE WHEN master_password_hash IN (?, ?) THEN 1 ELSE 0 END WHERE id = 1",
    )
      .bind(DEFAULT_MASTER_PASSWORD_HASH, LEGACY_DEFAULT_MASTER_PASSWORD_HASH)
      .run();
  }

  await env.DB.prepare(
    "UPDATE security_settings SET two_factor_enabled = 0 WHERE email = '' OR email LIKE '%*%'",
  ).run();

  const settingsCount = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM security_settings",
  ).first<{ total: number }>();
  const firstInstall = !settingsCount?.total;
  const seedStatements: SqlitePreparedStatement[] = [];

  if (firstInstall) {
    const initialPassword =
      process.env.YUEMI_INITIAL_PASSWORD?.trim() ||
      (process.env.NODE_ENV === "production" ? "" : DEFAULT_MASTER_PASSWORD);
    if (!initialPassword) {
      throw new Error("生产环境首次启动必须设置 YUEMI_INITIAL_PASSWORD");
    }
    if (initialPassword.length < 8 || initialPassword.length > 128) {
      throw new Error("YUEMI_INITIAL_PASSWORD 长度必须为 8–128 位");
    }
    const salt = createMasterPasswordSalt();
    const iterations = currentMasterPasswordIterations();
    const passwordHash = await hashMasterPassword(initialPassword, salt, iterations);
    seedStatements.push(
      env.DB.prepare(
        `INSERT INTO security_settings
          (id, two_factor_enabled, email, master_password_hash,
           master_password_salt, master_password_iterations,
           requires_password_change, max_failed_attempts, lockout_minutes)
         VALUES (1, 0, '', ?, ?, ?, 1, 5, 15)`,
      ).bind(passwordHash, salt, iterations),
    );

    const demoEntries = [
      ["entry-github", "GitHub", "dev***@example.com", "开发工具", "安全", "2026-07-26 14:30"],
      ["entry-email", "工作邮箱", "w***@example.com", "电子邮件", "安全", "2026-07-26 10:15"],
      ["entry-cloud", "云服务器", "root-admin", "服务器", "一般", "2026-07-25 09:42"],
      ["entry-bank", "网上银行", "6222 **** 8831", "金融", "安全", "2026-07-24 16:08"],
    ];
    for (const [id, project, account, category, status, updatedAt] of demoEntries) {
      seedStatements.push(
        env.DB.prepare(
          `INSERT INTO vault_entries
            (id, project_name, account, category, security_status,
             password_cipher, password_iv, updated_at)
           VALUES (?, ?, ?, ?, ?, 'encrypted-demo-value', 'demo-iv', ?)`,
        ).bind(id, project, account, category, status, updatedAt),
      );
    }
  }

  if (seedStatements.length) await env.DB.batch(seedStatements);

  await env.DB.exec(`
    CREATE INDEX IF NOT EXISTS vault_sessions_expires_idx ON vault_sessions(expires_at);
    CREATE INDEX IF NOT EXISTS verification_challenges_expires_idx ON verification_challenges(expires_at);
    CREATE INDEX IF NOT EXISTS login_attempts_updated_idx ON login_attempts(updated_at);
  `);
}

export async function ensureVaultSchema() {
  schemaReady ??= initializeVaultSchema();
  try {
    await schemaReady;
  } catch (error) {
    schemaReady = null;
    throw error;
  }
}
