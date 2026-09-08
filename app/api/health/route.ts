import { ensureVaultSchema } from "@/db/ensure";
import { env } from "@/runtime/database";

export const dynamic = "force-dynamic";

const responseHeaders = {
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
};

export async function GET() {
  try {
    await ensureVaultSchema();
    const result = await env.DB.prepare("SELECT 1 AS healthy").first<{
      healthy: number;
    }>();
    if (result?.healthy !== 1) throw new Error("database check failed");

    return Response.json(
      { status: "ok" },
      { status: 200, headers: responseHeaders },
    );
  } catch {
    return Response.json(
      { status: "unavailable" },
      { status: 503, headers: responseHeaders },
    );
  }
}
