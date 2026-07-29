ALTER TABLE `security_settings` ADD `smtp_security` text DEFAULT 'tls' NOT NULL;--> statement-breakpoint
ALTER TABLE `security_settings` ADD `smtp_feature_enabled` integer DEFAULT false NOT NULL;