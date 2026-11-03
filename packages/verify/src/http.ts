import { request } from "node:http";

export interface Response {
  status: number;
  body: string;
  headers: Record<string, string | string[] | undefined>;
}

export interface Requester {
  /** Sends a request to the target address with an explicit Host header, the way a browser on a tenant hostname would. */
  (host: string, method: string, path: string, opts?: { body?: string; headers?: Record<string, string> }): Promise<Response>;
}

/** Idle-socket timeout per request. Targets hash passwords (PBKDF2) and a loaded machine runs the gate's workers in parallel, so 5 s was close enough to flake; a hung target still fails, 30 s later. */
export const REQUEST_TIMEOUT_MS = 30_000;

export function makeRequester(target: URL): Requester {
  return (host, method, path, opts = {}) =>
    new Promise((resolve, reject) => {
      const req = request(
        { host: target.hostname, port: target.port, method, path, headers: { host, ...(opts.body ? { "content-length": String(Buffer.byteLength(opts.body)), "content-type": "application/json" } : {}), ...opts.headers }, timeout: REQUEST_TIMEOUT_MS },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8"), headers: res.headers }));
        },
      );
      req.on("timeout", () => req.destroy(new Error("request timed out")));
      req.on("error", reject);
      req.end(opts.body);
    });
}
