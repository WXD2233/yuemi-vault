CREATE TABLE `login_attempts` (
	`device_id` text PRIMARY KEY NOT NULL,
	`failed_count` integer DEFAULT 0 NOT NULL,
	`locked_until` text,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE `vault_sessions` (
	`token_hash` text PRIMARY KEY NOT NULL,
	`device_id` text NOT NULL,
	`expires_at` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE `verification_challenges` (
	`token_hash` text PRIMARY KEY NOT NULL,
	`device_id` text NOT NULL,
	`expires_at` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
ALTER TABLE `security_settings` ADD `master_password_hash` text DEFAULT '3651389d80ea709f76a95ec93ca42343eb35a31525020cc9b7a58100159a139c' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `max_failed_attempts` integer DEFAULT 5 NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `lockout_minutes` integer DEFAULT 15 NOT NULL;
