import vinext from "vinext";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import hostingConfig from "./.openai/hosting.json";
import { sites } from "./build/sites-vite-plugin";

const SITE_CREATOR_PLACEHOLDER_DATABASE_ID =
  "00000000-0000-4000-8000-000000000000";

const { d1, r2 } = hostingConfig;

// macOS Seatbelt blocks FSEvents, so Codex previews need polling for HMR.
const isCodexSeatbeltSandbox = process.env.CODEX_SANDBOX === "seatbelt";

const localBindingConfig = {
  main: "./worker/index.ts",
  compatibility_flags: ["nodejs_compat"],
  d1_databases: d1
    ? [
        {
          binding: d1,
          database_name: "site-creator-d1",
          database_id: SITE_CREATOR_PLACEHOLDER_DATABASE_ID,
        },
      ]
    : [],
  r2_buckets: r2
    ? [
        {
          binding: r2,
          bucket_name: "site-creator-r2",
        },
      ]
    : [],
};

export default defineConfig(async () => {
  const isVpsRuntime = process.env.YUEMI_RUNTIME === "vps";

  // Keep Wrangler and Miniflare state project-local. These are non-secret tool
  // settings; application environment belongs in ignored `.env*` files.
  process.env.WRANGLER_WRITE_LOGS ??= "false";
  process.env.WRANGLER_LOG_PATH ??= ".wrangler/logs";
  process.env.MINIFLARE_REGISTRY_PATH ??= ".wrangler/registry";

  // The VPS build uses Node-native SQLite and sockets. Cloudflare remains the
  // default so the existing Sites deployment keeps its D1 binding unchanged.
  const cloudflarePlugin = isVpsRuntime
    ? null
    : (await import("@cloudflare/vite-plugin")).cloudflare({
        viteEnvironment: { name: "rsc", childEnvironments: ["ssr"] },
        config: localBindingConfig,
      });

  return {
    resolve: isVpsRuntime
      ? {
          alias: {
            "cloudflare:workers": fileURLToPath(
              new URL("./runtime/vps/cloudflare-workers.ts", import.meta.url),
            ),
            "cloudflare:sockets": fileURLToPath(
              new URL("./runtime/vps/cloudflare-sockets.ts", import.meta.url),
            ),
          },
        }
      : undefined,
    server: isCodexSeatbeltSandbox
      ? { watch: { useFsEvents: false, usePolling: true } }
      : undefined,
    plugins: [vinext(), ...(isVpsRuntime ? [] : [sites(), cloudflarePlugin!])],
  };
});
