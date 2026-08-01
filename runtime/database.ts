import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  DatabaseSync,
  type SQLInputValue,
  type StatementSync,
} from "node:sqlite";

type Row = Record<string, unknown>;
type QueryMethod = "run" | "all" | "values" | "get";

type SqliteResult<T = Row> = {
  success: true;
  results: T[];
  meta: {
    changes: number;
    duration: number;
    last_row_id: number;
  };
};

function normalizeValue(value: unknown): SQLInputValue {
  if (value === undefined) return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value instanceof Date) return value.toISOString();
  return value as SQLInputValue;
}

function asNumber(value: number | bigint) {
  return typeof value === "bigint" ? Number(value) : value;
}

function result<T>(
  startedAt: number,
  results: T[] = [],
  changes = 0,
  lastRowId = 0,
): SqliteResult<T> {
  return {
    success: true,
    results,
    meta: {
      changes,
      duration: performance.now() - startedAt,
      last_row_id: lastRowId,
    },
  };
}

export class SqlitePreparedStatement {
  private parameters: SQLInputValue[] = [];

  constructor(
    private database: DatabaseSync,
    private sql: string,
  ) {}

  bind(...values: unknown[]) {
    const statement = new SqlitePreparedStatement(this.database, this.sql);
    statement.parameters = values.map(normalizeValue);
    return statement;
  }

  private prepare(returnArrays = false): StatementSync {
    const statement = this.database.prepare(this.sql);
    if (returnArrays) statement.setReturnArrays(true);
    return statement;
  }

  async run(): Promise<SqliteResult> {
    const startedAt = performance.now();
    const info = this.prepare().run(...this.parameters);
    return result(
      startedAt,
      [],
      asNumber(info.changes),
      asNumber(info.lastInsertRowid),
    );
  }

  async all<T = Row>(): Promise<SqliteResult<T>> {
    const startedAt = performance.now();
    const rows = this.prepare().all(...this.parameters) as T[];
    return result(startedAt, rows);
  }

  async first<T = Row>(column?: string): Promise<T | unknown | null> {
    const row = this.prepare().get(...this.parameters) as T | undefined;
    if (!row) return null;
    return column ? (row as Row)[column] : row;
  }

  async raw<T extends unknown[] = unknown[]>(): Promise<T[]> {
    return this.prepare(true).all(...this.parameters) as unknown as T[];
  }
}

export class SqliteDatabase {
  constructor(private database: DatabaseSync) {}

  prepare(sql: string) {
    return new SqlitePreparedStatement(this.database, sql);
  }

  async query(sql: string, parameters: unknown[], method: QueryMethod) {
    const statement = this.database.prepare(sql);
    const values = parameters.map(normalizeValue);

    if (method === "run") {
      statement.run(...values);
      return { rows: [] };
    }

    statement.setReturnArrays(true);
    if (method === "get") {
      return { rows: statement.get(...values) ?? [] };
    }
    return { rows: statement.all(...values) };
  }

  async batch(statements: SqlitePreparedStatement[]) {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const output = [];
      for (const statement of statements) output.push(await statement.run());
      this.database.exec("COMMIT");
      return output;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  async exec(sql: string) {
    const startedAt = performance.now();
    this.database.exec(sql);
    return {
      count: 1,
      duration: performance.now() - startedAt,
    };
  }
}

function createDatabase() {
  const dataDirectory = resolve(
    process.env.YUEMI_DATA_DIR || join(process.cwd(), "data"),
  );
  const databasePath = resolve(
    process.env.YUEMI_DATABASE_PATH || join(dataDirectory, "yuemi-vault.sqlite"),
  );

  mkdirSync(dirname(databasePath), { recursive: true });
  const database = new DatabaseSync(databasePath, {
    timeout: 5_000,
    enableForeignKeyConstraints: true,
  });
  database.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
  return new SqliteDatabase(database);
}

const globalDatabase = globalThis as typeof globalThis & {
  __yuemiDatabase?: SqliteDatabase;
};

globalDatabase.__yuemiDatabase ??= createDatabase();

export const env = {
  DB: globalDatabase.__yuemiDatabase,
};
