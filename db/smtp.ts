import { connect } from "@/runtime/sockets";
import { resolvePublicSmtpAddress } from "./smtp-config";

type SmtpReply = {
  code: number;
  lines: string[];
};

async function withSmtpTimeout<T>(promise: Promise<T>, milliseconds = 15_000) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("SMTP 服务器响应超时")),
          milliseconds,
        );
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

class SmtpConnection {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private buffer = "";
  private decoder = new TextDecoder();
  private encoder = new TextEncoder();

  constructor(
    private socket: ReturnType<typeof connect>,
  ) {
    this.reader = socket.readable.getReader();
    this.writer = socket.writable.getWriter();
  }

  async close() {
    try {
      this.reader.releaseLock();
      this.writer.releaseLock();
      await this.socket.close();
    } catch {
      // The remote SMTP server may close immediately after QUIT.
    }
  }

  async startTls() {
    this.reader.releaseLock();
    this.writer.releaseLock();
    this.socket = this.socket.startTls();
    await withSmtpTimeout(this.socket.opened);
    this.reader = this.socket.readable.getReader();
    this.writer = this.socket.writable.getWriter();
    this.buffer = "";
  }

  private async readLine() {
    while (!this.buffer.includes("\r\n")) {
      const result = await withSmtpTimeout(this.reader.read());
      if (result.done) throw new Error("SMTP 服务器提前断开连接");
      this.buffer += this.decoder.decode(result.value, { stream: true });
    }
    const lineEnd = this.buffer.indexOf("\r\n");
    const line = this.buffer.slice(0, lineEnd);
    this.buffer = this.buffer.slice(lineEnd + 2);
    return line;
  }

  async readReply(): Promise<SmtpReply> {
    const first = await this.readLine();
    const match = first.match(/^(\d{3})([ -])(.*)$/);
    if (!match) throw new Error(`SMTP 返回格式异常：${first}`);

    const code = Number(match[1]);
    const lines = [first];
    if (match[2] === "-") {
      while (true) {
        const line = await this.readLine();
        lines.push(line);
        if (line.startsWith(`${code} `)) break;
      }
    }
    return { code, lines };
  }

  async write(value: string) {
    await withSmtpTimeout(this.writer.write(this.encoder.encode(value)));
  }

  async command(value: string, expectedCodes: number[]) {
    await this.write(`${value}\r\n`);
    const reply = await this.readReply();
    if (!expectedCodes.includes(reply.code)) {
      const detail = reply.lines.join(" | ").replace(/\s+/g, " ").slice(0, 240);
      throw new Error(`SMTP 命令失败（${reply.code}）：${detail}`);
    }
    return reply;
  }
}

function utf8ToBase64(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function encodeHeader(value: string) {
  const safe = value.replace(/[\r\n]+/g, " ").trim();
  return `=?UTF-8?B?${utf8ToBase64(safe)}?=`;
}

function assertEmail(value: string) {
  if (
    value.includes("\r") ||
    value.includes("\n") ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
  ) {
    throw new Error("邮件地址格式不正确");
  }
}

function wrapBase64(value: string) {
  return value.match(/.{1,76}/g)?.join("\r\n") ?? "";
}

export async function sendSmtpMail(input: {
  host: string;
  port: number;
  username: string;
  secret: string;
  security: "tls" | "starttls";
  fromName: string;
  to: string;
  subject: string;
  text: string;
}) {
  assertEmail(input.username);
  assertEmail(input.to);
  if (
    !Number.isInteger(input.port) ||
    input.port < 1 ||
    input.port > 65535 ||
    input.port === 25
  ) {
    throw new Error("SMTP 端口无效；当前环境不支持端口 25");
  }

  const endpoint = await resolvePublicSmtpAddress(input.host);
  const socket = connect(
    {
      hostname: endpoint.address,
      servername: endpoint.servername,
      port: input.port,
    },
    {
      secureTransport: input.security === "tls" ? "on" : "starttls",
      allowHalfOpen: false,
    },
  );
  const smtp = new SmtpConnection(socket);

  try {
    await withSmtpTimeout(socket.opened);
    const greeting = await smtp.readReply();
    if (greeting.code !== 220) {
      throw new Error(`SMTP 服务器拒绝连接（${greeting.code}）`);
    }

    let ehlo = await smtp.command("EHLO yuemi-vault.local", [250]);
    if (input.security === "starttls") {
      await smtp.command("STARTTLS", [220]);
      await smtp.startTls();
      ehlo = await smtp.command("EHLO yuemi-vault.local", [250]);
    }
    const capabilities = ehlo.lines.join(" ").toUpperCase();
    if (/\bAUTH\b[^\r\n]*\bLOGIN\b/.test(capabilities)) {
      await smtp.command("AUTH LOGIN", [334]);
      await smtp.command(utf8ToBase64(input.username), [334]);
      await smtp.command(utf8ToBase64(input.secret), [235]);
    } else if (/\bAUTH\b[^\r\n]*\bPLAIN\b/.test(capabilities)) {
      await smtp.command(
        `AUTH PLAIN ${utf8ToBase64(
          `\u0000${input.username}\u0000${input.secret}`,
        )}`,
        [235],
      );
    } else {
      throw new Error("SMTP 服务器不支持 AUTH LOGIN 或 AUTH PLAIN");
    }
    await smtp.command(`MAIL FROM:<${input.username}>`, [250]);
    await smtp.command(`RCPT TO:<${input.to}>`, [250, 251]);
    await smtp.command("DATA", [354]);

    const message = [
      `From: ${encodeHeader(input.fromName || "钥密")} <${input.username}>`,
      `To: <${input.to}>`,
      `Subject: ${encodeHeader(input.subject)}`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${crypto.randomUUID()}@yuemi-vault.local>`,
      "MIME-Version: 1.0",
      'Content-Type: text/plain; charset="UTF-8"',
      "Content-Transfer-Encoding: base64",
      "",
      wrapBase64(utf8ToBase64(input.text)),
    ].join("\r\n");

    await smtp.write(`${message}\r\n.\r\n`);
    const accepted = await smtp.readReply();
    if (accepted.code !== 250) {
      throw new Error(`SMTP 邮件提交失败（${accepted.code}）`);
    }
    await smtp.command("QUIT", [221]);
  } finally {
    await smtp.close();
  }
}
