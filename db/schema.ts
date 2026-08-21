import { sql } from "drizzle-orm";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { DEFAULT_MASTER_PASSWORD_HASH } from "./security-constants";

export const vaultEntries = sqliteTable("vault_entries", {
  id: text("id").primaryKey(),
  projectName: text("project_name").notNull(),
  account: text("account").notNull(),
  category: text("category").notNull(),
  securityStatus: text("security_status").notNull().default("安全"),
  passwordCipher: text("password_cipher").notNull(),
  passwordIv: text("password_iv").notNull(),
  notes: text("notes").notNull().default(""),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const trustedDevices = sqliteTable("trusted_devices", {
  id: text("id").primaryKey(),
  credentialHash: text("credential_hash").notNull().default(""),
  deviceName: text("device_name").notNull(),
  browser: text("browser").notNull(),
  location: text("location").notNull(),
  lastActive: text("last_active").notNull().default(sql`CURRENT_TIMESTAMP`),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const securitySettings = sqliteTable("security_settings", {
  id: integer("id").primaryKey(),
  twoFactorEnabled: integer("two_factor_enabled", { mode: "boolean" })
    .notNull()
    .default(true),
  email: text("email").notNull().default("w***@example.com"),
  masterPasswordHash: text("master_password_hash")
    .notNull()
    .default(DEFAULT_MASTER_PASSWORD_HASH),
  masterPasswordSalt: text("master_password_salt")
    .notNull()
    .default("yuemi-master-v1"),
  masterPasswordIterations: integer("master_password_iterations")
    .notNull()
    .default(100000),
  requiresPasswordChange: integer("requires_password_change", {
    mode: "boolean",
  })
    .notNull()
    .default(true),
  maxFailedAttempts: integer("max_failed_attempts").notNull().default(5),
  lockoutMinutes: integer("lockout_minutes").notNull().default(15),
  smtpProvider: text("smtp_provider").notNull().default(""),
  smtpHost: text("smtp_host").notNull().default(""),
  smtpPort: integer("smtp_port").notNull().default(465),
  smtpSecurity: text("smtp_security").notNull().default("tls"),
  smtpUsername: text("smtp_username").notNull().default(""),
  smtpSecretCipher: text("smtp_secret_cipher").notNull().default(""),
  smtpSecretIv: text("smtp_secret_iv").notNull().default(""),
  smtpFromName: text("smtp_from_name").notNull().default("钥密"),
  smtpEnabled: integer("smtp_enabled", { mode: "boolean" })
    .notNull()
    .default(false),
  smtpFeatureEnabled: integer("smtp_feature_enabled", { mode: "boolean" })
    .notNull()
    .default(false),
  smtpVerifiedAt: text("smtp_verified_at"),
  recoveryCipher: text("recovery_cipher").notNull().default(""),
  recoveryIv: text("recovery_iv").notNull().default(""),
  recoverySalt: text("recovery_salt").notNull().default(""),
  recoveryIterations: integer("recovery_iterations").notNull().default(600000),
});

export const loginAttempts = sqliteTable("login_attempts", {
  deviceId: text("device_id").primaryKey(),
  failedCount: integer("failed_count").notNull().default(0),
  lockedUntil: text("locked_until"),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const vaultSessions = sqliteTable("vault_sessions", {
  tokenHash: text("token_hash").primaryKey(),
  deviceId: text("device_id").notNull(),
  expiresAt: text("expires_at").notNull(),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const verificationChallenges = sqliteTable("verification_challenges", {
  tokenHash: text("token_hash").primaryKey(),
  deviceId: text("device_id").notNull(),
  purpose: text("purpose").notNull().default("device"),
  codeHash: text("code_hash").notNull().default(""),
  failedCount: integer("failed_count").notNull().default(0),
  expiresAt: text("expires_at").notNull(),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});
