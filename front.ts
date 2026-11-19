// The front door: a raw node:net HTTP/1.1 server that replaces node:http on the entry's one
// port. The suite's hot paths are dominated by fixed per-request cost (object allocation,
// promise hops and header machinery in node:http), so this server parses just the request
// line + the headers it needs, hands hot requests to synchronous buffer responders, and
// falls back to the existing app handler (through a minimal req/res shim) for everything
// else. One process, one listening socket: main.ts's lifecycle is untouched.

import { createServer, type Server, type Socket } from 'node:net';
import { Readable } from 'node:stream';

/** One fully-read HTTP request, as the front door parsed it. */
export interface ParsedRequest {
  readonly method: string;
  /** The raw request target (path + query, exactly as sent). */
  readonly target: string;
  /** The target before '?'. */
  readonly path: string;
  /** The target after '?' ('' when absent). */
  readonly query: string;
  /**
   * The headers the dispatch itself reads (authorization, git-protocol, content-length,
   * transfer-encoding, connection, expect, host), lower-cased name -> value, duplicates
   * joined with ', '. The full header block stays in headText; the cold path's shim
   * parses all of it, so cold semantics are unchanged.
   */
  readonly headers: ReadonlyMap<string, string>;
  /** The raw header block (request line + headers), for the shim's full parse. */
  readonly headText: string;
  readonly body: Buffer;
  readonly httpVersion: string;
}

/** The header names the front door and the hot dispatch read; everything else is shim-only. */
const KNOWN_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'git-protocol',
  'content-length',
  'transfer-encoding',
  'connection',
  'expect',
  'host',
]);

/** A complete response the front door can write in one flush. */
export interface FrontResponse {
  readonly status: number;
  readonly headers: readonly (readonly [string, string])[];
  readonly body: Buffer;
}

/** Synchronous hot dispatch: a response, or null to fall through to the cold handler. */
export type HotHandler = (req: ParsedRequest) => FrontResponse | null;

/** The cold handler: the existing app handler, driven through the shim below. */
export type ColdHandler = (req: ShimRequest, res: ShimResponse) => Promise<void>;

const EMPTY = Buffer.alloc(0);
const HEADER_CAP = 64 * 1024;
const BODY_CAP = 256 * 1024 * 1024;

const REASONS: Readonly<Record<number, string>> = {
  200: 'OK',
  201: 'Created',
  204: 'No Content',
  400: 'Bad Request',
  401: 'Unauthorized',
  404: 'Not Found',
  405: 'Method Not Allowed',
  409: 'Conflict',
  422: 'Unprocessable Entity',
  500: 'Internal Server Error',
};

/** A Readable standing in for IncomingMessage: the cold handler reads method/url/headers
 *  as properties and the body through the usual 'data'/'end' events. */
export class ShimRequest extends Readable {
  readonly method: string;
  readonly url: string;
  readonly headers: Record<string, string>;
  readonly httpVersion = '1.1';
  private readonly bodyBuf: Buffer;
  private sent = false;

  constructor(req: ParsedRequest) {
    super();
    this.method = req.method;
    this.url = req.target;
    this.bodyBuf = req.body;
    // The full header parse happens only here, on the cold path: every header the app
    // might read, lower-cased name -> value, duplicates joined with ', ' (as node:http).
    const headers: Record<string, string> = {};
    const lines = req.headText.split('\r\n');
    for (let i = 1; i < lines.length; i += 1) {
      const line = lines[i] as string;
      const colon = line.indexOf(':');
      if (colon < 0) continue;
      const name = line.slice(0, colon).trim().toLowerCase();
      const value = line.slice(colon + 1).trim();
      const prior = headers[name];
      headers[name] = prior === undefined ? value : `${prior}, ${value}`;
    }
    this.headers = headers;
  }

  override _read(): void {
    if (this.sent) return;
    this.sent = true;
    if (this.bodyBuf.length > 0) this.push(this.bodyBuf);
    this.push(null);
  }
}

/** A ServerResponse stand-in: collects writeHead + end into one FrontResponse. The cold
 *  handler only ever uses writeHead/end/headersSent (verified across app.ts + gitserver.ts). */
export class ShimResponse {
  headersSent = false;
  private status = 200;
  private readonly headerList: [string, string][] = [];
  private readonly chunks: Buffer[] = [];
  private finished = false;
  readonly done: Promise<FrontResponse>;
  private resolveDone!: (response: FrontResponse) => void;

  constructor() {
    this.done = new Promise<FrontResponse>((resolve) => {
      this.resolveDone = resolve;
    });
  }

  writeHead(status: number, headers?: Record<string, string>): this {
    this.status = status;
    if (headers !== undefined) {
      for (const [name, value] of Object.entries(headers)) this.headerList.push([name, value]);
    }
    this.headersSent = true;
    return this;
  }

  end(chunk?: string | Buffer): this {
    if (chunk !== undefined && chunk !== '') {
      this.chunks.push(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
    }
    if (!this.finished) {
      this.finished = true;
      this.resolveDone({
        status: this.status,
        headers: this.headerList,
        body: this.chunks.length === 1 ? (this.chunks[0] as Buffer) : Buffer.concat(this.chunks),
      });
    }
    return this;
  }
}

/** Serialize and write one response; returns false when the connection should close. */
function writeResponse(socket: Socket, response: FrontResponse, keepAlive: boolean): void {
  const { status, headers, body } = response;
  let head = `HTTP/1.1 ${status} ${REASONS[status] ?? ''}\r\n`;
  let hasLength = false;
  for (const [name, value] of headers) {
    if (name.toLowerCase() === 'content-length') hasLength = true;
    head += `${name}: ${value}\r\n`;
  }
  if (!hasLength && status !== 204) head += `content-length: ${body.length}\r\n`;
  if (!keepAlive) head += 'connection: close\r\n';
  head += '\r\n';
  const headBuf = Buffer.from(head, 'latin1');
  if (body.length === 0) {
    socket.write(headBuf);
  } else if (body.length < 32 * 1024) {
    socket.write(Buffer.concat([headBuf, body]));
  } else {
    socket.cork();
    socket.write(headBuf);
    socket.write(body);
    socket.uncork();
  }
}

type ParseResult =
  | { readonly kind: 'request'; readonly req: ParsedRequest; readonly consumed: number }
  | { readonly kind: 'incomplete'; readonly wantContinue: boolean }
  | { readonly kind: 'bad' };

const HEAD_END = Buffer.from('\r\n\r\n', 'latin1');

/**
 * Match a header name span in `text` against the known set, case-insensitively, without
 * allocating: returns the canonical (lower-case) name or null. Header names are short
 * ASCII tokens; folding A-Z by char code is exact for them.
 */
function knownHeaderName(text: string, start: number, end: number): string | null {
  const length = end - start;
  outer: for (const known of KNOWN_HEADERS) {
    if (known.length !== length) continue;
    for (let i = 0; i < length; i += 1) {
      let code = text.charCodeAt(start + i);
      if (code >= 65 && code <= 90) code += 32;
      if (code !== known.charCodeAt(i)) continue outer;
    }
    return known;
  }
  return null;
}

/** Parse one request from the front of `buf` (headers + a fully framed body). */
function tryParse(buf: Buffer): ParseResult {
  const headerEnd = buf.indexOf(HEAD_END);
  if (headerEnd < 0) return buf.length > HEADER_CAP ? { kind: 'bad' } : { kind: 'incomplete', wantContinue: false };
  const headText = buf.toString('latin1', 0, headerEnd);
  // Request line: METHOD SP TARGET SP VERSION — located by index scans, no split array.
  const lineEnd = headText.indexOf('\r\n');
  const requestLineEnd = lineEnd < 0 ? headText.length : lineEnd;
  const sp1 = headText.indexOf(' ');
  const sp2 = sp1 < 0 ? -1 : headText.indexOf(' ', sp1 + 1);
  const sp3 = sp2 < 0 ? -1 : headText.indexOf(' ', sp2 + 1);
  if (
    sp1 <= 0 || sp2 <= sp1 + 1 || sp2 >= requestLineEnd
    || (sp3 >= 0 && sp3 < requestLineEnd) || sp2 + 1 >= requestLineEnd
  ) return { kind: 'bad' };
  const method = headText.slice(0, sp1);
  const target = headText.slice(sp1 + 1, sp2);
  const version = headText.slice(sp2 + 1, requestLineEnd);
  // Lean scan: walk the header lines in place and materialize only the known headers
  // (name matched without allocation, value sliced once over its trimmed span); the rest
  // of the block is parsed later, and only by the cold path's shim.
  const headers = new Map<string, string>();
  let pos = requestLineEnd + 2;
  while (pos < headText.length) {
    const eol = headText.indexOf('\r\n', pos);
    const end = eol < 0 ? headText.length : eol;
    const colon = headText.indexOf(':', pos);
    if (colon > pos && colon < end) {
      let nameEnd = colon;
      while (nameEnd > pos && (headText.charCodeAt(nameEnd - 1) === 32 || headText.charCodeAt(nameEnd - 1) === 9)) nameEnd -= 1;
      const known = knownHeaderName(headText, pos, nameEnd);
      if (known !== null) {
        let valueStart = colon + 1;
        let valueEnd = end;
        while (valueStart < valueEnd && (headText.charCodeAt(valueStart) === 32 || headText.charCodeAt(valueStart) === 9)) valueStart += 1;
        while (valueEnd > valueStart && (headText.charCodeAt(valueEnd - 1) === 32 || headText.charCodeAt(valueEnd - 1) === 9)) valueEnd -= 1;
        const value = headText.slice(valueStart, valueEnd);
        const prior = headers.get(known);
        headers.set(known, prior === undefined ? value : `${prior}, ${value}`);
      }
    }
    if (eol < 0) break;
    pos = eol + 2;
  }
  const bodyStart = headerEnd + 4;
  const wantContinue = (headers.get('expect') ?? '').toLowerCase() === '100-continue';
  const transferEncoding = (headers.get('transfer-encoding') ?? '').toLowerCase();
  let body: Buffer;
  let consumed: number;
  if (transferEncoding.includes('chunked')) {
    const decoded = decodeChunked(buf, bodyStart);
    if (decoded === null) return { kind: 'incomplete', wantContinue };
    if (decoded === 'bad') return { kind: 'bad' };
    body = decoded.body;
    consumed = decoded.consumed;
  } else {
    const lengthHeader = headers.get('content-length');
    const length = lengthHeader === undefined ? 0 : Number.parseInt(lengthHeader, 10);
    if (Number.isNaN(length) || length < 0 || length > BODY_CAP) return { kind: 'bad' };
    if (buf.length < bodyStart + length) return { kind: 'incomplete', wantContinue };
    body = length === 0 ? EMPTY : buf.subarray(bodyStart, bodyStart + length);
    consumed = bodyStart + length;
  }
  const q = target.indexOf('?');
  return {
    kind: 'request',
    consumed,
    req: {
      method,
      target,
      path: q < 0 ? target : target.slice(0, q),
      query: q < 0 ? '' : target.slice(q + 1),
      headers,
      headText,
      body,
      httpVersion: version,
    },
  };
}

/** Decode a chunked body starting at `start`; null while incomplete. */
function decodeChunked(buf: Buffer, start: number): { body: Buffer; consumed: number } | 'bad' | null {
  const chunks: Buffer[] = [];
  let offset = start;
  for (;;) {
    const lineEnd = buf.indexOf('\r\n', offset);
    if (lineEnd < 0) return null;
    const sizeText = buf.subarray(offset, lineEnd).toString('latin1').split(';')[0] as string;
    const size = Number.parseInt(sizeText, 16);
    if (Number.isNaN(size) || size < 0) return 'bad';
    offset = lineEnd + 2;
    if (size === 0) {
      // Trailer lines run to an empty line.
      for (;;) {
        const end = buf.indexOf('\r\n', offset);
        if (end < 0) return null;
        if (end === offset) return { body: Buffer.concat(chunks), consumed: offset + 2 };
        offset = end + 2;
      }
    }
    if (buf.length < offset + size + 2) return null;
    chunks.push(buf.subarray(offset, offset + size));
    offset += size + 2;
  }
}

function keepAliveOf(req: ParsedRequest): boolean {
  const connection = (req.headers.get('connection') ?? '').toLowerCase();
  if (connection.includes('close')) return false;
  if (req.httpVersion === 'HTTP/1.0') return connection.includes('keep-alive');
  return true;
}

/**
 * Build the front-door server. Hot requests are answered synchronously from buffers;
 * everything else is dispatched to the cold handler through the shim, one request at a
 * time per connection (the suite's clients never pipeline).
 */
export function createFrontServer(hot: HotHandler, cold: ColdHandler): Server {
  const server = createServer((socket) => {
    socket.setNoDelay(true);
    socket.on('error', () => {});
    let buf: Buffer = EMPTY;
    let busy = false;
    let dead = false;
    let continueSent = false;

    const pump = (): void => {
      while (!busy && !dead) {
        const parsed = tryParse(buf);
        if (parsed.kind === 'incomplete') {
          if (parsed.wantContinue && !continueSent) {
            continueSent = true;
            socket.write('HTTP/1.1 100 Continue\r\n\r\n');
          }
          return;
        }
        if (parsed.kind === 'bad') {
          dead = true;
          socket.destroy();
          return;
        }
        continueSent = false;
        buf = buf.subarray(parsed.consumed);
        const req = parsed.req;
        const keep = keepAliveOf(req);
        let hotResponse: FrontResponse | null = null;
        try {
          hotResponse = hot(req);
        } catch {
          hotResponse = null;
        }
        if (hotResponse !== null) {
          writeResponse(socket, hotResponse, keep);
          if (!keep) {
            dead = true;
            socket.end();
            return;
          }
          continue;
        }
        busy = true;
        const shimReq = new ShimRequest(req);
        const shimRes = new ShimResponse();
        void (async () => {
          try {
            await cold(shimReq, shimRes);
          } catch {
            // The cold wrapper answers its own 500s; a response that never ended is
            // completed empty rather than left hanging.
            shimRes.end();
          }
          const response = await shimRes.done;
          busy = false;
          if (dead) return;
          writeResponse(socket, response, keep);
          if (!keep) {
            dead = true;
            socket.end();
            return;
          }
          pump();
        })();
      }
    };

    socket.on('data', (chunk: Buffer) => {
      buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
      pump();
    });
  });
  return server;
}
