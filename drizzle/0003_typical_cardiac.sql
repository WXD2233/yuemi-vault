PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_security_settings` (
	`id` integer PRIMARY KEY NOT NULL,
	`two_factor_enabled` integer DEFAULT true NOT NULL,
	`email` text DEFAULT 'w***@example.com' NOT NULL,
	`master_password_hash` text DEFAULT '8feb66c7949b28c70e3e2782a43b08cdec387a3f9fb24ac3877980084ac7f14c' NOT NULL,
	`max_failed_attempts` integer DEFAULT 5 NOT NULL,
	`lockout_minutes` integer DEFAULT 15 NOT NULL
);
--> statement-breakpoint
INSERT INTO `__new_security_settings`("id", "two_factor_enabled", "email", "master_password_hash", "max_failed_attempts", "lockout_minutes") SELECT "id", "two_factor_enabled", "email", "master_password_hash", "max_failed_attempts", "lockout_minutes" FROM `security_settings`;--> statement-breakpoint
DROP TABLE `security_settings`;--> statement-breakpoint
ALTER TABLE `__new_security_settings` RENAME TO `security_settings`;--> statement-breakpoint
PRAGMA foreign_keys=ON;