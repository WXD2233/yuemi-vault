import { desc, eq } from "drizzle-orm";
import { getDb } from "../../../db";
import { ensureVaultSchema } from "../../../db/ensure";
import {
  securitySettings,
  trustedDevices,
  vaultEntries,
} from "../../../db/schema";

export const dynamic = "force-dynamic";

function errorResponse(error: unknown) {
  const message = error instanceof Error ? error.message : "Unexpected error";
  return Response.json({ error: message }, { status: 500 });
}

export async function GET() {
  try {
    await ensureVaultSchema();
    const db = getDb();
    const [entries, devices, settingsRows] = await Promise.all([
      db
        .select({
          id: vaultEntries.id,
          projectName: vaultEntries.projectName,
          account: vaultEntries.account,
          category: vaultEntries.category,
          securityStatus: vaultEntries.securityStatus,
          updatedAt: vaultEntries.updatedAt,
        })
        .from(vaultEntries)
        .orderBy(desc(vaultEntries.updatedAt)),
      db
        .select()
        .from(trustedDevices)
        .orderBy(desc(trustedDevices.lastActive)),
      db
        .select()
        .from(securitySettings)
        .where(eq(securitySettings.id, 1))
        .limit(1),
    ]);

    return Response.json({
      entries,
      devices,
      settings: settingsRows[0] ?? {
        twoFactorEnabled: true,
        email: "w***@example.com",
      },
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request) {
  try {
    await ensureVaultSchema();
    const payload = (await request.json()) as Record<string, unknown>;
    const action = String(payload.action ?? "");
    const db = getDb();

    if (action === "add-entry") {
      const projectName = String(payload.projectName ?? "").trim();
      const account = String(payload.account ?? "").trim();
      const category = String(payload.category ?? "").trim();
      const passwordCipher = String(payload.passwordCipher ?? "");
      const passwordIv = String(payload.passwordIv ?? "");

      if (
        !projectName ||
        !account ||
        !category ||
        !passwordCipher ||
        !passwordIv
      ) {
        return Response.json({ error: "缺少密码记录字段" }, { status: 400 });
      }

      await db.insert(vaultEntries).values({
        id: crypto.randomUUID(),
        projectName,
        account,
        category,
        passwordCipher,
        passwordIv,
        securityStatus: "安全",
        updatedAt: new Date().toISOString().slice(0, 16).replace("T", " "),
      });
      return Response.json({ ok: true }, { status: 201 });
    }

    if (action === "add-device") {
      const id = String(payload.id ?? "");
      if (!id) {
        return Response.json({ error: "设备 ID 不能为空" }, { status: 400 });
      }

      await db
        .insert(trustedDevices)
        .values({
          id,
          deviceName: String(payload.deviceName ?? "新设备"),
          browser: String(payload.browser ?? "浏览器"),
          location: String(payload.location ?? "未知位置"),
          lastActive: "刚刚",
          createdAt: new Date().toISOString().slice(0, 10),
        })
        .onConflictDoUpdate({
          target: trustedDevices.id,
          set: {
            deviceName: String(payload.deviceName ?? "新设备"),
            browser: String(payload.browser ?? "浏览器"),
            location: String(payload.location ?? "未知位置"),
            lastActive: "刚刚",
          },
        });
      return Response.json({ ok: true }, { status: 201 });
    }

    if (action === "set-two-factor") {
      await db
        .update(securitySettings)
        .set({ twoFactorEnabled: Boolean(payload.enabled) })
        .where(eq(securitySettings.id, 1));
      return Response.json({ ok: true });
    }

    if (action === "delete-device") {
      const id = String(payload.id ?? "");
      if (!id) {
        return Response.json({ error: "设备 ID 不能为空" }, { status: 400 });
      }
      await db.delete(trustedDevices).where(eq(trustedDevices.id, id));
      return Response.json({ ok: true });
    }

    return Response.json({ error: "未知操作" }, { status: 400 });
  } catch (error) {
    return errorResponse(error);
  }
}
