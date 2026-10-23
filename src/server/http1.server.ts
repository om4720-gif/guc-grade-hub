// Tiny HTTP/1.1 client over ONE persistent TLS socket.
// NTLM authenticates the TCP connection, so every handshake step must reuse it.
import { connect, type TLSSocket } from "node:tls";

export type RawResponse = { status: number; headers: Record<string, string[]>; body: string };

export class KeepAliveConnection {
  private sock: TLSSocket | null = null;
  private buf = Buffer.alloc(0);
  private waiters: (() => void)[] = [];
  private closed = false;

  constructor(private host: string) {}

  private async open() {
    if (this.sock && !this.closed) return;
    this.buf = Buffer.alloc(0);
    this.closed = false;
    await new Promise<void>((resolve, reject) => {
      const s = connect({ host: this.host, port: 443, servername: this.host }, () => resolve());
      s.once("error", reject);
      s.on("data", (d: Buffer) => {
        this.buf = Buffer.concat([this.buf, d]);
        this.wake();
      });
      s.on("close", () => {
        this.closed = true;
        this.wake();
      });
      s.on("error", () => {
        this.closed = true;
        this.wake();
      });
      this.sock = s;
    });
  }

  private wake() {
    const w = this.waiters;
    this.waiters = [];
    w.forEach((f) => f());
  }

  private async waitFor<T>(take: () => T | null, timeoutMs = 25000): Promise<T> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const v = take();
      if (v !== null) return v;
      if (this.closed) throw new Error("Connection closed by GUC portal");
      if (Date.now() > deadline) throw new Error("GUC portal timed out");
      await new Promise<void>((r) => {
        this.waiters.push(r);
        setTimeout(r, 1000);
      });
    }
  }

  async request(
    method: string,
    path: string,
    headers: Record<string, string>,
    body?: string,
  ): Promise<RawResponse> {
    await this.open();
    const h: Record<string, string> = {
      Host: this.host,
      Connection: "keep-alive",
      "User-Agent": "Mozilla/5.0 GradeWatch",
      Accept: "text/html,*/*",
      ...headers,
    };
    if (body !== undefined) h["Content-Length"] = String(Buffer.byteLength(body));
    let req = `${method} ${path} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(h)) req += `${k}: ${v}\r\n`;
    req += "\r\n" + (body ?? "");
    this.sock!.write(req);

    const headEnd = await this.waitFor(() => {
      const i = this.buf.indexOf("\r\n\r\n");
      return i >= 0 ? i : null;
    });
    const headText = this.buf.subarray(0, headEnd).toString("latin1");
    this.buf = this.buf.subarray(headEnd + 4);
    const [statusLine, ...lines] = headText.split("\r\n");
    const status = Number(/^HTTP\/1\.\d (\d{3})/.exec(statusLine ?? "")?.[1] ?? 0);
    const headersOut: Record<string, string[]> = {};
    for (const l of lines) {
      const c = l.indexOf(":");
      if (c < 0) continue;
      const k = l.slice(0, c).trim().toLowerCase();
      (headersOut[k] ??= []).push(l.slice(c + 1).trim());
    }

    let bodyBuf: Buffer;
    const te = headersOut["transfer-encoding"]?.join(",").toLowerCase() ?? "";
    if (te.includes("chunked")) {
      const parts: Buffer[] = [];
      for (;;) {
        const lineEnd = await this.waitFor(() => {
          const i = this.buf.indexOf("\r\n");
          return i >= 0 ? i : null;
        });
        const size = parseInt(this.buf.subarray(0, lineEnd).toString("latin1"), 16);
        this.buf = this.buf.subarray(lineEnd + 2);
        if (!size) {
          await this.waitFor(() => (this.buf.indexOf("\r\n") >= 0 ? true : null));
          this.buf = this.buf.subarray(this.buf.indexOf("\r\n") + 2);
          break;
        }
        await this.waitFor(() => (this.buf.length >= size + 2 ? true : null));
        parts.push(this.buf.subarray(0, size));
        this.buf = this.buf.subarray(size + 2);
      }
      bodyBuf = Buffer.concat(parts);
    } else {
      const len = Number(headersOut["content-length"]?.[0] ?? 0);
      await this.waitFor(() => (this.buf.length >= len ? true : null));
      bodyBuf = this.buf.subarray(0, len);
      this.buf = this.buf.subarray(len);
    }
    if ((headersOut["connection"]?.[0] ?? "").toLowerCase() === "close") this.close();
    return { status, headers: headersOut, body: bodyBuf.toString("utf8") };
  }

  close() {
    this.sock?.destroy();
    this.sock = null;
    this.closed = true;
  }
}
