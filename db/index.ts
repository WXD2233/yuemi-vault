import { env } from "@/runtime/database";
import { drizzle } from "drizzle-orm/sqlite-proxy";
import * as schema from "./schema";

export function getDb() {
  if (!env.DB) {
    throw new Error(
      "The local SQLite database is unavailable. Check YUEMI_DATA_DIR and directory permissions."
    );
  }

  return drizzle(env.DB.query.bind(env.DB), { schema });
}
