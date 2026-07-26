import { sql } from "drizzle-orm";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const vaultEntries = sqliteTable("vault_entries", {
  id: text("id").primaryKey(),
  projectName: text("project_name").notNull(),
  account: text("account").notNull(),
  category: text("category").notNull(),
  securityStatus: text("security_status").notNull().default("安全"),
  passwordCipher: text("password_cipher").notNull(),
  passwordIv: text("password_iv").notNull(),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const trustedDevices = sqliteTable("trusted_devices", {
  id: text("id").primaryKey(),
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
});
