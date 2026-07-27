import { env } from "cloudflare:workers";
import { desc, eq } from "drizzle-orm";
import { getDb } from "../../../db";
import { getVaultSession } from "../../../db/auth";
import { ensureVaultSchema } from "../../../db/ensure";
import {
  securitySettings,
  trustedDevices,
  vaultEntries,
} from "../../../db/schema";

export const dynamic = "force-dynamic";

const ENCRYPTED_RECORD_PREFIX = "yv2.";
const encryptedStorageFields = {
  projectName: "加密记录",
  account: "••••••••",
  category: "已加密",
  notes: "",
};

function errorResponse(error: unknown) {
  const message = error instanceof Error ? error.message : "Unexpected error";
  return Response.json({ error: message }, { status: 500 });
}

async function authorize(request: Request) {
  const session = await getVaultSession(request);
  if (!session) {
    return {
      session: null,
      response: Response.json(
        { error: "本次访问尚未通过服务端校验" },
        { status: 401 },
      ),
    };
  }
  return { session, response: null };
}

export async function GET(request: Request) {
  try {
    await ensureVaultSchema();
    const authorization = await authorize(request);
    if (authorization.response) return authorization.response;

    const db = getDb();
    const [entries, devices, settingsRows] = await Promise.all([
      db
        .select({
          id: vaultEntries.id,
          projectName: vaultEntries.projectName,
          account: vaultEntries.account,
          category: vaultEntries.category,
          securityStatus: vaultEntries.securityStatus,
          passwordCipher: vaultEntries.passwordCipher,
          passwordIv: vaultEntries.passwordIv,
          notes: vaultEntries.notes,
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

    const settings = settingsRows[0];
    return Response.json({
      entries,
      devices,
      settings: settings
        ? {
            twoFactorEnabled: settings.twoFactorEnabled,
            email: settings.email,
            maxFailedAttempts: settings.maxFailedAttempts,
            lockoutMinutes: settings.lockoutMinutes,
          }
        : {
            twoFactorEnabled: true,
            email: "w***@example.com",
            maxFailedAttempts: 5,
            lockoutMinutes: 15,
          },
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request) {
  try {
    await ensureVaultSchema();
    const authorization = await authorize(request);
    if (authorization.response || !authorization.session) {
      return authorization.response;
    }

    const payload = (await request.json()) as Record<string, unknown>;
    const action = String(payload.action ?? "");
    const db = getDb();

    if (action === "add-entry") {
      const projectName = String(payload.projectName ?? "").trim();
      const account = String(payload.account ?? "").trim();
      const category = String(payload.category ?? "").trim();
      const passwordCipher = String(payload.passwordCipher ?? "");
      const passwordIv = String(payload.passwordIv ?? "");
      const notes = String(payload.notes ?? "").trim();

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
        ...(passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX)
          ? encryptedStorageFields
          : { projectName, account, category, notes }),
        passwordCipher,
        passwordIv,
        securityStatus: "安全",
        updatedAt: new Date().toISOString().slice(0, 16).replace("T", " "),
      });
      return Response.json({ ok: true }, { status: 201 });
    }

    if (action === "update-entry") {
      const id = String(payload.id ?? "").trim();
      const projectName = String(payload.projectName ?? "").trim();
      const account = String(payload.account ?? "").trim();
      const category = String(payload.category ?? "").trim();
      const passwordCipher = String(payload.passwordCipher ?? "");
      const passwordIv = String(payload.passwordIv ?? "");
      const notes = String(payload.notes ?? "").trim();

      if (!id || !projectName || !account || !category) {
        return Response.json({ error: "缺少密码记录字段" }, { status: 400 });
      }
      if (
        (passwordCipher && !passwordIv) ||
        (!passwordCipher && passwordIv)
      ) {
        return Response.json({ error: "新密码密文不完整" }, { status: 400 });
      }

      await db
        .update(vaultEntries)
        .set({
          ...(passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX)
            ? encryptedStorageFields
            : { projectName, account, category, notes }),
          updatedAt: new Date().toISOString().slice(0, 16).replace("T", " "),
          ...(passwordCipher && passwordIv
            ? { passwordCipher, passwordIv, securityStatus: "安全" }
            : {}),
        })
        .where(eq(vaultEntries.id, id));
      return Response.json({ ok: true });
    }

    if (action === "set-two-factor") {
      await db
        .update(securitySettings)
        .set({ twoFactorEnabled: Boolean(payload.enabled) })
        .where(eq(securitySettings.id, 1));
      return Response.json({ ok: true });
    }

    if (action === "set-lockout-policy") {
      const maxFailedAttempts = Number(payload.maxFailedAttempts);
      const lockoutMinutes = Number(payload.lockoutMinutes);
      if (
        !Number.isInteger(maxFailedAttempts) ||
        maxFailedAttempts < 2 ||
        maxFailedAttempts > 10 ||
        !Number.isInteger(lockoutMinutes) ||
        lockoutMinutes < 1 ||
        lockoutMinutes > 1440
      ) {
        return Response.json({ error: "锁定策略参数无效" }, { status: 400 });
      }

      await db
        .update(securitySettings)
        .set({ maxFailedAttempts, lockoutMinutes })
        .where(eq(securitySettings.id, 1));
      return Response.json({ ok: true });
    }

    if (action === "delete-device") {
      const id = String(payload.id ?? "");
      if (!id) {
        return Response.json({ error: "设备 ID 不能为空" }, { status: 400 });
      }

      await env.DB.batch([
        env.DB.prepare("DELETE FROM trusted_devices WHERE id = ?").bind(id),
        env.DB.prepare("DELETE FROM vault_sessions WHERE device_id = ?").bind(
          id,
        ),
        env.DB.prepare("DELETE FROM login_attempts WHERE device_id = ?").bind(
          id,
        ),
      ]);
      return Response.json({
        ok: true,
        removedCurrentDevice: id === authorization.session.deviceId,
      });
    }

    return Response.json({ error: "未知操作" }, { status: 400 });
  } catch (error) {
    return errorResponse(error);
  }
}
