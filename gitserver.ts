// Git smart HTTP for the forge: ref advertisement (v0 and v2), ls-refs, upload-pack fetch
// (v0 and v2, shallow included) and receive-pack push with report-status — all over the same
// in-memory object store REST writes (store.ts + git.ts). Packs are written plain (no deltas)
// and read with full delta resolution. Nothing here may throw across the handler boundary:
// a malformed body is a 400 and the server keeps serving (the suite proves exactly that).

import type { IncomingMessage, ServerResponse } from 'node:http';
import { Store, type RepoRecord } from './store.ts';
import {
  collectReachable,
  decodePackets,
  depthLimited,
  getObject,
  isAncestor,
  peelToCommit,
  pktDelim,
  pktFlush,
  pktLine,
  PKT_MAX_PAYLOAD,
  readPack,
  writePack,
  ZERO_OID,
  type Obj,
} from './git.ts';

export interface GitRoute {
  readonly owner: string;
  readonly name: string;
  /** The path after `/{owner}/{repo}.git` ('/info/refs', '/git-upload-pack', ...). */
  readonly rest: string;
  readonly url: URL;
}

const AGENT = 'forge/1.0';

// --------------------------------------------------------------------------- response cache
// Store objects are append-only and content-addressed, and refs only move forward to objects
// that exist, so a fetch/advertisement response is fully determined by its request inputs:
// the same wants/depth/haves always plan the same object set. Caching the built bytes keyed
// by those inputs is therefore sound, and it is what makes 50 concurrent identical clones
// cheap: the pack is built (and deflated) once, then replayed.

const CACHE_LIMIT = 128;
const responseCaches = new WeakMap<RepoRecord, Map<string, Buffer>>();

function cacheGet(repo: RepoRecord, key: string): Buffer | undefined {
  return responseCaches.get(repo)?.get(key);
}

function cacheSet(repo: RepoRecord, key: string, body: Buffer): void {
  let cache = responseCaches.get(repo);
  if (cache === undefined) {
    cache = new Map();
    responseCaches.set(repo, cache);
  }
  if (cache.size >= CACHE_LIMIT) cache.clear();
  cache.set(key, body);
}

/** A fingerprint of everything an advertisement or ls-refs response depends on. */
function refsFingerprint(repo: RepoRecord): string {
  const parts: string[] = [repo.defaultBranch];
  for (const [ref, oid] of sortedRefs(repo)) parts.push(`${ref}=${oid}`);
  return parts.join('|');
}

/**
 * A fast-path cache key for one raw git request body. A fetch or ls-refs response is a
 * pure function of the request bytes plus the repo's ref positions and object count
 * (objects are content-addressed and never mutate; any ingest grows the count, any
 * ref move changes the fingerprint), so an identical body under an identical key
 * replays byte-exactly without packet decoding or argument parsing.
 */
import { createHash } from 'node:crypto';

function rawBodyKey(repo: RepoRecord, kind: string, raw: Buffer): string {
  const digest = createHash('sha1').update(raw).digest('hex');
  return `${kind}|raw|${refsFingerprint(repo)}|${repo.objects.size}|${digest}`;
}

/** The protocol-v2 advertisement carries no repo data at all: build it once. */
const V2_ADVERTISEMENT: Buffer = Buffer.concat([
  pktLine('version 2\n'),
  pktLine(`agent=${AGENT}\n`),
  pktLine('ls-refs=unborn\n'),
  pktLine('fetch=shallow wait-for-done filter\n'),
  pktLine('object-format=sha1\n'),
  pktFlush(),
]);

/** Read a request body to the end (git bodies are binary; no JSON parsing here). */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** A JSON error on a git path (the client's infoRefs only needs the status). */
function sendGitError(res: ServerResponse, status: number, message: string): void {
  const text = `${JSON.stringify({ message })}\n`;
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(text);
}

/** A complete git response as bytes: the buffer core the front door's hot path writes
 *  directly, and handleGit below adapts onto ServerResponse for the cold path. */
export interface GitBufferResult {
  readonly status: number;
  readonly contentType: string;
  readonly body: Buffer;
}

function gitJsonError(status: number, message: string): GitBufferResult {
  return {
    status,
    contentType: 'application/json; charset=utf-8',
    body: Buffer.from(`${JSON.stringify({ message })}\n`, 'utf8'),
  };
}

/** Handle one git smart-HTTP request. True when the request was answered here. */
export async function handleGit(
  store: Store,
  req: IncomingMessage,
  res: ServerResponse,
  route: GitRoute,
): Promise<boolean> {
  const repo = store.repoFor(route.owner, route.name);
  if (repo === undefined) {
    sendGitError(res, 404, 'Not Found');
    return true;
  }
  const method = req.method ?? 'GET';
  try {
    if (route.rest === '/info/refs' && method === 'GET') {
      const service = route.url.searchParams.get('service') ?? '';
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        sendGitError(res, 404, 'Not Found');
        return true;
      }
      advertise(req, res, repo, service);
      return true;
    }
    if (route.rest === '/git-upload-pack' && method === 'POST') {
      await uploadPack(req, res, repo);
      return true;
    }
    if (route.rest === '/git-receive-pack' && method === 'POST') {
      await receivePack(req, res, repo);
      return true;
    }
  } catch {
    if (!res.headersSent) sendGitError(res, 400, 'Bad Request');
    return true;
  }
  return false;
}

// --------------------------------------------------------------------------- advertisement

/** Refs in advertisement order: name-sorted, tags peeled by the caller when needed. */
function sortedRefs(repo: RepoRecord): Array<[string, string]> {
  return [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function headTarget(repo: RepoRecord): string {
  return `refs/heads/${repo.defaultBranch}`;
}

/** The advertisement body for one service (v2's is a module constant; v0's is cached). */
export function advertiseBuffer(repo: RepoRecord, service: string, gitProtocol: string): Buffer {
  const wantsV2 = service === 'git-upload-pack' && gitProtocol.includes('version=2');
  if (wantsV2) return V2_ADVERTISEMENT;
  const key = `advertise|${service}|${refsFingerprint(repo)}`;
  const cached = cacheGet(repo, key);
  if (cached !== undefined) return cached;
  const caps = service === 'git-upload-pack'
    ? `multi_ack_detailed side-band-64k thin-pack ofs-delta shallow symref=HEAD:${headTarget(repo)} agent=${AGENT}`
    : `report-status side-band-64k delete-refs ofs-delta agent=${AGENT}`;
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), pktFlush()];
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const headOid = repo.refs.get(headTarget(repo)) ?? ZERO_OID;
    parts.push(pktLine(`${headOid} HEAD\0${caps}\n`));
    for (const [ref, oid] of refs) {
      parts.push(pktLine(`${oid} ${ref}\n`));
      const peeled = peelToCommit(repo, oid);
      if (peeled !== undefined && peeled !== oid) parts.push(pktLine(`${peeled} ${ref}^{}\n`));
    }
  }
  parts.push(pktFlush());
  const body = Buffer.concat(parts);
  cacheSet(repo, key, body);
  return body;
}

function advertise(req: IncomingMessage, res: ServerResponse, repo: RepoRecord, service: string): void {
  res.writeHead(200, {
    'content-type': `application/x-${service}-advertisement`,
    'cache-control': 'no-cache',
  });
  res.end(advertiseBuffer(repo, service, req.headers['git-protocol'] ?? ''));
}

// --------------------------------------------------------------------------- ls-refs (v2)

interface LsRefsArgs {
  readonly peel: boolean;
  readonly symrefs: boolean;
  readonly prefixes: string[];
}

/** One ls-refs response body: HEAD (prefix permitting) then the matching refs, peeled on request. */
function lsRefsBuffer(repo: RepoRecord, args: LsRefsArgs): Buffer {
  const key = `lsrefs|${refsFingerprint(repo)}|${args.peel ? 1 : 0}|${args.symrefs ? 1 : 0}|${args.prefixes.join(' ')}`;
  const cached = cacheGet(repo, key);
  if (cached !== undefined) return cached;
  const matches = (name: string): boolean =>
    args.prefixes.length === 0 || args.prefixes.some((prefix) => name.startsWith(prefix));
  const parts: Buffer[] = [];
  if (matches('HEAD')) {
    const headOid = repo.refs.get(headTarget(repo)) ?? ZERO_OID;
    const extra = args.symrefs ? ` symref-target:${headTarget(repo)}` : '';
    parts.push(pktLine(`${headOid} HEAD${extra}\n`));
  }
  for (const [ref, oid] of sortedRefs(repo)) {
    if (!matches(ref)) continue;
    let line = `${oid} ${ref}`;
    if (args.peel) {
      const peeled = peelToCommit(repo, oid);
      if (peeled !== undefined && peeled !== oid) line += ` peeled:${peeled}`;
    }
    parts.push(pktLine(`${line}\n`));
  }
  parts.push(pktFlush());
  const body = Buffer.concat(parts);
  cacheSet(repo, key, body);
  return body;
}

// --------------------------------------------------------------------------- fetch

interface FetchArgs {
  readonly wants: string[];
  readonly haves: string[];
  readonly clientShallow: string[];
  readonly depth: number | null;
  readonly done: boolean;
}

/** The cache key of one fetch response: protocol era + every input the response depends on. */
function fetchCacheKey(version: 0 | 2, args: FetchArgs): string {
  return [
    'fetch', String(version),
    args.wants.join(' '),
    args.depth === null ? '' : String(args.depth),
    args.haves.join(' '),
    args.clientShallow.join(' '),
  ].join('|');
}

/** The object set + shallow bookkeeping for one fetch. */
function planFetch(repo: RepoRecord, args: FetchArgs): {
  objects: Set<string>;
  boundary: string[];
  unshallow: string[];
} {
  if (args.depth !== null) {
    const { objects, boundary } = depthLimited(repo, args.wants, args.depth);
    const unshallow = args.clientShallow.filter((oid) => objects.has(oid) && !boundary.includes(oid));
    return { objects, boundary, unshallow };
  }
  const wanted = collectReachable(repo, args.wants);
  const held = collectReachable(repo, args.haves.filter((oid) => getObject(repo, oid) !== undefined));
  for (const oid of held) wanted.delete(oid);
  return { objects: wanted, boundary: [], unshallow: [] };
}

/** A pack of the planned objects, as {type, data} entries for writePack. */
function packOf(repo: RepoRecord, objects: Set<string>): Buffer {
  const entries: Array<{ type: 'commit' | 'tree' | 'blob' | 'tag'; data: Buffer }> = [];
  for (const oid of objects) {
    const object = getObject(repo, oid);
    if (object !== undefined) {
      entries.push({ type: object.type as 'commit' | 'tree' | 'blob' | 'tag', data: object.data });
    }
  }
  return writePack(entries);
}

/** Frame pack bytes as sideband-64k band-1 packets (each within the pkt-line size cap). */
function sidebandPackets(pack: Buffer): Buffer[] {
  const packets: Buffer[] = [];
  const chunkSize = PKT_MAX_PAYLOAD - 1;
  for (let offset = 0; offset < pack.length; offset += chunkSize) {
    packets.push(pktLine(Buffer.concat([Buffer.from([1]), pack.subarray(offset, offset + chunkSize)])));
  }
  if (packets.length === 0) packets.push(pktLine(Buffer.from([1])));
  return packets;
}

const UPLOAD_RESULT_TYPE = 'application/x-git-upload-pack-result';

/** The upload-pack exchange over a raw request body (ls-refs or fetch, v2 or v0). */
export function uploadPackBuffer(repo: RepoRecord, raw: Buffer, gitProtocol: string): GitBufferResult {
  // Fast path: an identical body under identical repo state replays byte-exactly.
  const fastKey = rawBodyKey(repo, 'up', raw);
  const fastHit = cacheGet(repo, fastKey);
  if (fastHit !== undefined) return { status: 200, contentType: UPLOAD_RESULT_TYPE, body: fastHit };
  const v2 = gitProtocol.includes('version=2');
  const { packets } = decodePackets(raw);
  const lines = packets
    .filter((packet) => packet.kind === 'data')
    .map((packet) => (packet.kind === 'data' ? packet.payload.toString('utf8').replace(/\n$/, '') : ''));

  if (v2) {
    const command = lines.find((line) => line.startsWith('command='));
    if (command === 'command=ls-refs') {
      const prefixes: string[] = [];
      let peel = false;
      let symrefs = false;
      for (const line of lines) {
        if (line === 'peel') peel = true;
        else if (line === 'symrefs') symrefs = true;
        else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
      }
      const lsBody = lsRefsBuffer(repo, { peel, symrefs, prefixes });
      cacheSet(repo, fastKey, lsBody);
      return { status: 200, contentType: UPLOAD_RESULT_TYPE, body: lsBody };
    }
    if (command !== 'command=fetch') return gitJsonError(400, 'Bad Request');
    const args = parseFetchArgs(lines);
    const key = fetchCacheKey(2, args);
    const cached = cacheGet(repo, key);
    if (cached !== undefined) return { status: 200, contentType: UPLOAD_RESULT_TYPE, body: cached };
    const plan = planFetch(repo, args);
    const pack = packOf(repo, plan.objects);
    const parts: Buffer[] = [pktLine('acknowledgments\n')];
    const common = args.haves.filter((oid) => getObject(repo, oid) !== undefined);
    if (common.length > 0) {
      for (const oid of common) parts.push(pktLine(`ACK ${oid}\n`));
    } else {
      parts.push(pktLine('NAK\n'));
    }
    parts.push(pktDelim());
    if (args.depth !== null || args.clientShallow.length > 0) {
      parts.push(pktLine('shallow-info\n'));
      for (const oid of plan.boundary) parts.push(pktLine(`shallow ${oid}\n`));
      for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
      parts.push(pktDelim());
    }
    parts.push(pktLine('packfile\n'), ...sidebandPackets(pack), pktFlush());
    const body = Buffer.concat(parts);
    cacheSet(repo, key, body);
    cacheSet(repo, fastKey, body);
    return { status: 200, contentType: UPLOAD_RESULT_TYPE, body };
  }

  // v0: wants in the first section, haves + done after the flush — decode in two rounds.
  const first = decodePackets(raw);
  const second = decodePackets(raw.subarray(first.consumed));
  const allLines = [...first.packets, ...second.packets]
    .filter((packet) => packet.kind === 'data')
    .map((packet) => (packet.kind === 'data' ? packet.payload.toString('utf8').replace(/\n$/, '') : ''));
  if (!allLines.some((line) => line.startsWith('want '))) return gitJsonError(400, 'Bad Request');
  const args = parseFetchArgs(allLines);
  const key = fetchCacheKey(0, args);
  const cached = cacheGet(repo, key);
  if (cached !== undefined) return { status: 200, contentType: UPLOAD_RESULT_TYPE, body: cached };
  const plan = planFetch(repo, args);
  const pack = packOf(repo, plan.objects);
  const parts: Buffer[] = [];
  for (const oid of plan.boundary) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  const common = args.haves.filter((oid) => getObject(repo, oid) !== undefined);
  parts.push(pktLine(common.length > 0 ? `ACK ${common[common.length - 1]}\n` : 'NAK\n'));
  parts.push(...sidebandPackets(pack), pktFlush());
  const body = Buffer.concat(parts);
  cacheSet(repo, key, body);
  cacheSet(repo, fastKey, body);
  return { status: 200, contentType: UPLOAD_RESULT_TYPE, body };
}

async function uploadPack(req: IncomingMessage, res: ServerResponse, repo: RepoRecord): Promise<void> {
  const raw = await readBody(req);
  const result = uploadPackBuffer(repo, raw, req.headers['git-protocol'] ?? '');
  res.writeHead(result.status, { 'content-type': result.contentType });
  res.end(result.body);
}

/** want/have/shallow/deepen/done lines (v2 argument lines or v0 lines) -> fetch arguments. */
function parseFetchArgs(lines: string[]): FetchArgs {
  const wants: string[] = [];
  const haves: string[] = [];
  const clientShallow: string[] = [];
  let depth: number | null = null;
  let done = false;
  for (const line of lines) {
    if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0] as string);
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) clientShallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) depth = Number(line.slice(7)) || null;
    else if (line === 'done') done = true;
  }
  return { wants, haves, clientShallow, depth, done };
}

// --------------------------------------------------------------------------- receive-pack

interface PushCommand {
  readonly oldOid: string;
  readonly newOid: string;
  readonly ref: string;
}

/** The receive-pack exchange over a raw request body (commands + pack -> report-status). */
export function receivePackBuffer(repo: RepoRecord, raw: Buffer): GitBufferResult {
  const { packets, consumed } = decodePackets(raw);
  const commands: PushCommand[] = [];
  let capabilities: string[] = [];
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    let line = packet.payload.toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0');
    if (nul >= 0) {
      capabilities = line.slice(nul + 1).split(' ').filter(Boolean);
      line = line.slice(0, nul);
    }
    const parts = line.split(' ');
    if (parts.length >= 3) {
      commands.push({
        oldOid: parts[0] as string,
        newOid: parts[1] as string,
        ref: parts.slice(2).join(' '),
      });
    }
  }
  if (commands.length === 0) return gitJsonError(400, 'Bad Request');

  // Ingest the pack first: objects land even when a ref update is later refused (as in git).
  const packBytes = raw.subarray(consumed);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const incoming = readPack(packBytes, (oid) => getObject(repo, oid));
      for (const [oid, object] of incoming) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, object as Obj);
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'error';
    }
  }

  const report: Buffer[] = [pktLine(`unpack ${unpackDetail}\n`)];
  for (const command of commands) {
    if (!unpackOk) {
      report.push(pktLine(`ng ${command.ref} unpacker error\n`));
      continue;
    }
    const problem = applyPush(repo, command);
    report.push(pktLine(problem === null ? `ok ${command.ref}\n` : `ng ${command.ref} ${problem}\n`));
  }
  report.push(pktFlush());
  const reportBytes = Buffer.concat(report);
  const body = capabilities.includes('side-band-64k')
    ? Buffer.concat(sidebandPackets(reportBytes))
    : reportBytes;
  return { status: 200, contentType: 'application/x-git-receive-pack-result', body };
}

async function receivePack(req: IncomingMessage, res: ServerResponse, repo: RepoRecord): Promise<void> {
  const raw = await readBody(req);
  const result = receivePackBuffer(repo, raw);
  res.writeHead(result.status, { 'content-type': result.contentType });
  res.end(result.body);
}

/** Apply one ref update; null when applied, otherwise the report-status refusal reason. */
function applyPush(repo: RepoRecord, command: PushCommand): string | null {
  const current = repo.refs.get(command.ref) ?? ZERO_OID;
  if (current !== command.oldOid) {
    return command.oldOid === ZERO_OID ? 'reference already exists' : 'stale info';
  }
  if (command.newOid === ZERO_OID) {
    repo.refs.delete(command.ref);
    return null;
  }
  const target = getObject(repo, command.newOid);
  if (target === undefined) return 'missing objects';
  if (current !== ZERO_OID) {
    const currentCommit = peelToCommit(repo, current);
    const newCommit = peelToCommit(repo, command.newOid);
    if (currentCommit !== undefined && newCommit !== undefined
      && !isAncestor(repo, currentCommit, newCommit)) {
      return 'non-fast-forward';
    }
  }
  repo.refs.set(command.ref, command.newOid);
  return null;
}
