CREATE TABLE `security_settings` (
	`id` integer PRIMARY KEY NOT NULL,
	`two_factor_enabled` integer DEFAULT true NOT NULL,
	`email` text DEFAULT 'w***@example.com' NOT NULL
);
--> statement-breakpoint
CREATE TABLE `trusted_devices` (
	`id` text PRIMARY KEY NOT NULL,
	`device_name` text NOT NULL,
	`browser` text NOT NULL,
	`location` text NOT NULL,
	`last_active` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE `vault_entries` (
	`id` text PRIMARY KEY NOT NULL,
	`project_name` text NOT NULL,
	`account` text NOT NULL,
	`category` text NOT NULL,
	`security_status` text DEFAULT '安全' NOT NULL,
	`password_cipher` text NOT NULL,
	`password_iv` text NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
