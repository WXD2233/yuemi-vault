import net, { type Socket as NetSocket } from "node:net";
import tls, { type TLSSocket } from "node:tls";

type Address = { hostname: string; port: number };
type SocketOptions = {
  secureTransport?: "off" | "on" | "starttls";
  allowHalfOpen?: boolean;
};

type NodeSocket = NetSocket | TLSSocket;

function openedPromise(socket: NodeSocket, secure: boolean) {
  return new Promise<void>((resolve, reject) => {
    const successEvent = secure ? "secureConnect" : "connect";
    const onSuccess = () => {
      socket.off("error", onError);
      resolve();
    };
    const onError = (error: Error) => {
      socket.off(successEvent, onSuccess);
      reject(error);
    };
    socket.once(successEvent, onSuccess);
    socket.once("error", onError);
  });
}

class VpsSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<void>;

  private detachReadable: () => void = () => undefined;

  constructor(
    private socket: NodeSocket,
    private address: Address,
    secure = false,
  ) {
    this.opened = openedPromise(socket, secure);

    this.readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        const onData = (chunk: Buffer) => {
          controller.enqueue(
            new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength),
          );
        };
        const onEnd = () => controller.close();
        const onError = (error: Error) => controller.error(error);
        socket.on("data", onData);
        socket.once("end", onEnd);
        socket.once("error", onError);
        this.detachReadable = () => {
          socket.off("data", onData);
          socket.off("end", onEnd);
          socket.off("error", onError);
        };
      },
      cancel: () => {
        this.detachReadable();
        socket.destroy();
      },
    });

    this.writable = new WritableStream<Uint8Array>({
      write: (chunk) =>
        new Promise<void>((resolve, reject) => {
          socket.write(chunk, (error) => (error ? reject(error) : resolve()));
        }),
      close: () => {
        socket.end();
      },
      abort: (reason) => {
        socket.destroy(reason as Error);
      },
    });
  }

  startTls() {
    this.detachReadable();
    const socket = tls.connect({
      socket: this.socket as NetSocket,
      servername: this.address.hostname,
    });
    return new VpsSocket(socket, this.address, true);
  }

  async close() {
    this.detachReadable();
    if (this.socket.destroyed) return;
    await new Promise<void>((resolve) => {
      this.socket.once("close", () => resolve());
      this.socket.end();
      setTimeout(() => {
        this.socket.destroy();
        resolve();
      }, 1_000).unref();
    });
  }
}

export function connect(address: Address, options: SocketOptions = {}) {
  const secure = options.secureTransport === "on";
  const socket = secure
    ? tls.connect({
        host: address.hostname,
        port: address.port,
        servername: address.hostname,
      })
    : net.connect({
        host: address.hostname,
        port: address.port,
        allowHalfOpen: options.allowHalfOpen,
      });

  return new VpsSocket(socket, address, secure);
}
