ALTER TABLE `security_settings` ADD `smtp_provider` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `smtp_host` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `smtp_port` integer DEFAULT 465 NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `smtp_username` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `smtp_secret_cipher` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `smtp_secret_iv` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `smtp_from_name` text DEFAULT '钥密' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `smtp_enabled` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `smtp_verified_at` text;