// The git object layer: SHA-1 object hashing, trees, commits, packfiles (read with delta
// resolution, write plain), reachability and the three-way tree merge the pull-request
// squash needs. Everything here is pure over a RepoRecord's object map — no HTTP, no clock:
// forge-authored commits take their timestamp from the store's deterministic sequence.

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { OWNER_LOGIN, type RepoRecord, type Store } from './store.ts';

export type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
export interface Obj {
  readonly type: ObjType;
  readonly data: Buffer;
}

export const ZERO_OID = '0'.repeat(40);
const TYPE_CODE: Readonly<Record<ObjType, number>> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Readonly<Record<number, ObjType>> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

// --------------------------------------------------------------------------- objects

/** git's object id: SHA-1 over `<type> <size>\0` + the object's bytes. */
export function hashObject(type: ObjType, data: Buffer): string {
  const hash = createHash('sha1');
  hash.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  hash.update(data);
  return hash.digest('hex');
}

/** Store an object in the repo (idempotent) and return its id. */
export function storeObject(repo: RepoRecord, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

export function getObject(repo: RepoRecord, oid: string): Obj | undefined {
  return repo.objects.get(oid) as Obj | undefined;
}

// --------------------------------------------------------------------------- trees

export interface TreeEntry {
  readonly mode: string;
  readonly name: string;
  readonly oid: string;
}

/** Parse a tree object into entries, in stored order. */
export function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    const mode = data.subarray(offset, space).toString('ascii');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

/** git's tree-entry sort: byte order of the name, a directory compared as if it ended in '/'. */
function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

/** Build a tree object from entries (sorted the way git sorts them) and store it. */
export function buildTree(repo: RepoRecord, entries: readonly TreeEntry[]): string {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return storeObject(repo, 'tree', Buffer.concat(parts));
}

/** Flatten a tree into path -> blob oid (files only; gitlinks skipped). */
export function flattenTree(repo: RepoRecord, treeOid: string, prefix = '', out = new Map<string, string>()): Map<string, string> {
  const tree = getObject(repo, treeOid);
  if (tree === undefined || tree.type !== 'tree') return out;
  for (const entry of parseTree(tree.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else if (entry.mode !== '160000') out.set(path, entry.oid);
  }
  return out;
}

/** Build (and store) nested trees from a flat path -> blob oid map; returns the root tree id. */
export function buildTreeFromFlat(repo: RepoRecord, files: ReadonlyMap<string, string>): string {
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, oid] of files) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const name = segments[i] as string;
      if (!node.dirs.has(name)) node.dirs.set(name, make());
      node = node.dirs.get(name) as Node;
    }
    node.files.set(segments[segments.length - 1] as string, oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return buildTree(repo, entries);
  };
  return build(root);
}

/** The tree id of a directory inside a tree, or undefined when the path is not a directory. */
export function subtreeAt(repo: RepoRecord, treeOid: string, dirPath: string): string | undefined {
  if (dirPath === '') return treeOid;
  let current = treeOid;
  for (const segment of dirPath.split('/')) {
    const tree = getObject(repo, current);
    if (tree === undefined || tree.type !== 'tree') return undefined;
    const entry = parseTree(tree.data).find((candidate) => candidate.name === segment && candidate.mode === '40000');
    if (entry === undefined) return undefined;
    current = entry.oid;
  }
  return current;
}

// --------------------------------------------------------------------------- commits

export interface CommitView {
  readonly tree: string;
  readonly parents: string[];
  readonly author: string;
  readonly committer: string;
  readonly message: string;
}

/** Parse a commit object. */
export function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5);
    else if (line.startsWith('parent ')) parents.push(line.slice(7));
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8') };
}

/** The identity forge-authored commits carry (the token owner's login, a fixed mailbox). */
export function forgeIdentity(): string {
  return `${OWNER_LOGIN} <${OWNER_LOGIN}@example.invalid>`;
}

/** Build and store a commit object; returns its id. */
export function buildCommit(
  repo: RepoRecord,
  fields: { tree: string; parents: readonly string[]; message: string; author: string; timestampSec: number },
): string {
  const who = `${fields.author} ${fields.timestampSec} +0000`;
  const lines = [`tree ${fields.tree}`];
  for (const parent of fields.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return storeObject(repo, 'commit', Buffer.from(`${lines.join('\n')}\n${fields.message}`, 'utf8'));
}

/** The commit at a ref (branch name or full ref), or undefined when unborn/unknown. */
export function refTip(repo: RepoRecord, ref: string): string | undefined {
  return repo.refs.get(ref);
}

/** Resolve a branch name, full ref, or raw commit id to a commit id in this repo. */
export function resolveCommit(repo: RepoRecord, name: string): string | undefined {
  const candidates = [name, `refs/heads/${name}`, `refs/tags/${name}`];
  for (const candidate of candidates) {
    const tip = repo.refs.get(candidate);
    if (tip !== undefined) {
      const object = getObject(repo, tip);
      if (object !== undefined && object.type === 'tag') {
        const target = parseTagTarget(object.data);
        if (target !== undefined) return target;
      }
      return tip;
    }
  }
  const object = getObject(repo, name);
  if (object !== undefined && object.type === 'commit') return name;
  if (object !== undefined && object.type === 'tag') return parseTagTarget(object.data);
  return undefined;
}

/** The object a tag object points at. */
export function parseTagTarget(data: Buffer): string | undefined {
  const first = data.subarray(0, data.indexOf('\n')).toString('utf8');
  return first.startsWith('object ') ? first.slice(7) : undefined;
}

/** Peel a ref target to its commit (through tag objects), or undefined. */
export function peelToCommit(repo: RepoRecord, oid: string): string | undefined {
  let current = oid;
  for (let depth = 0; depth < 10; depth += 1) {
    const object = getObject(repo, current);
    if (object === undefined) return undefined;
    if (object.type === 'commit') return current;
    if (object.type !== 'tag') return undefined;
    const target = parseTagTarget(object.data);
    if (target === undefined) return undefined;
    current = target;
  }
  return undefined;
}

/**
 * Apply path changes on a branch: `changes` maps a path to its new bytes (a blob is created)
 * or null (the path is removed). Creates one commit on top of the branch tip (or as a root
 * commit on an unborn branch), moves the ref, and returns the commit id.
 */
export function commitPaths(
  store: Store,
  repo: RepoRecord,
  branchRef: string,
  changes: ReadonlyMap<string, Buffer | null>,
  message: string,
): string {
  const tip = repo.refs.get(branchRef);
  const tipCommit = tip !== undefined ? getObject(repo, tip) : undefined;
  const files = tipCommit !== undefined && tipCommit.type === 'commit'
    ? flattenTree(repo, parseCommit(tipCommit.data).tree)
    : new Map<string, string>();
  for (const [path, content] of changes) {
    if (content === null) files.delete(path);
    else files.set(path, storeObject(repo, 'blob', content));
  }
  const tree = buildTreeFromFlat(repo, files);
  const seq = store.nextSeq();
  const timestampSec = Math.floor(Date.parse(store.isoAt(seq)) / 1000);
  const commit = buildCommit(repo, {
    tree,
    parents: tip !== undefined && tipCommit !== undefined ? [tip] : [],
    message: message.endsWith('\n') ? message : `${message}\n`,
    author: forgeIdentity(),
    timestampSec,
  });
  repo.refs.set(branchRef, commit);
  return commit;
}

// --------------------------------------------------------------------------- ancestry

/** Every commit reachable from `tip` through parent links (tip included), bounded for safety. */
export function ancestorsOf(repo: RepoRecord, tip: string): Set<string> {
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = getObject(repo, oid);
    if (object === undefined || object.type !== 'commit') continue;
    seen.add(oid);
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return seen;
}

/** True when `ancestor` is `descendant` itself or one of its ancestors. */
export function isAncestor(repo: RepoRecord, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const queue = [descendant];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = getObject(repo, oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return false;
}

/** A common ancestor of two commits (the first found walking from `b`), or undefined. */
export function mergeBase(repo: RepoRecord, a: string, b: string): string | undefined {
  const ancestors = ancestorsOf(repo, a);
  const seen = new Set<string>();
  const queue = [b];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (ancestors.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = getObject(repo, oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return undefined;
}

// --------------------------------------------------------------------------- tree diff / merge

export interface FileChange {
  readonly path: string;
  readonly status: 'added' | 'removed' | 'modified';
  readonly oldOid: string | undefined;
  readonly newOid: string | undefined;
}

/** The path-level difference between two flat path -> blob maps. */
export function diffFlat(
  before: ReadonlyMap<string, string>,
  after: ReadonlyMap<string, string>,
): FileChange[] {
  const changes: FileChange[] = [];
  for (const [path, oid] of after) {
    const old = before.get(path);
    if (old === undefined) changes.push({ path, status: 'added', oldOid: undefined, newOid: oid });
    else if (old !== oid) changes.push({ path, status: 'modified', oldOid: old, newOid: oid });
  }
  for (const [path, oid] of before) {
    if (!after.has(path)) changes.push({ path, status: 'removed', oldOid: oid, newOid: undefined });
  }
  return changes.sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : 0));
}

/**
 * A path-level three-way merge of flat file maps. Returns the merged map, or null when both
 * sides changed the same path incompatibly (the squash-merge conflict the suite exercises).
 */
export function mergeFlat(
  base: ReadonlyMap<string, string>,
  ours: ReadonlyMap<string, string>,
  theirs: ReadonlyMap<string, string>,
): Map<string, string> | null {
  const merged = new Map<string, string>();
  const paths = new Set([...base.keys(), ...ours.keys(), ...theirs.keys()]);
  for (const path of paths) {
    const b = base.get(path);
    const o = ours.get(path);
    const t = theirs.get(path);
    if (o === t) {
      if (o !== undefined) merged.set(path, o);
    } else if (b === o) {
      if (t !== undefined) merged.set(path, t);
    } else if (b === t) {
      if (o !== undefined) merged.set(path, o);
    } else {
      return null;
    }
  }
  return merged;
}

// --------------------------------------------------------------------------- reachability

/** Every object reachable from `roots` that this repo holds (missing objects are skipped). */
export function collectReachable(repo: RepoRecord, roots: Iterable<string>): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...roots];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = getObject(repo, oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      const target = parseTagTarget(object.data);
      if (target !== undefined) queue.push(target);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

/** True when every object reachable from `roots` is present in the repo. */
export function closureComplete(repo: RepoRecord, roots: Iterable<string>): boolean {
  const queue: string[] = [...roots];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = getObject(repo, oid);
    if (object === undefined) return false;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      const target = parseTagTarget(object.data);
      if (target !== undefined) queue.push(target);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return true;
}

export interface DepthResult {
  /** The objects a depth-limited fetch sends (commits within depth, their trees and blobs). */
  readonly objects: Set<string>;
  /** Commits at exactly the depth limit whose parents were cut: the shallow boundary. */
  readonly boundary: string[];
}

/**
 * The object set of a shallow fetch: commits up to `depth` generations from the wants
 * (a want commit is generation 1), each with its full tree closure. Tag wants peel to
 * their commit first (the tag object itself is always included).
 */
export function depthLimited(repo: RepoRecord, wants: readonly string[], depth: number): DepthResult {
  const objects = new Set<string>();
  const boundary: string[] = [];
  const addTreeClosure = (oid: string): void => {
    for (const found of collectReachable(repo, [oid])) objects.add(found);
  };
  // Breadth-first by generation over commits.
  const generations = new Map<string, number>();
  const queue: Array<{ oid: string; gen: number }> = [];
  for (const want of wants) {
    const object = getObject(repo, want);
    if (object === undefined) continue;
    if (object.type === 'tag') {
      objects.add(want);
      const target = parseTagTarget(object.data);
      if (target !== undefined) queue.push({ oid: target, gen: 1 });
    } else if (object.type === 'commit') {
      queue.push({ oid: want, gen: 1 });
    } else {
      addTreeClosure(want);
    }
  }
  while (queue.length > 0) {
    const { oid, gen } = queue.shift() as { oid: string; gen: number };
    const known = generations.get(oid);
    if (known !== undefined && known <= gen) continue;
    generations.set(oid, gen);
    const object = getObject(repo, oid);
    if (object === undefined || object.type !== 'commit') continue;
    objects.add(oid);
    const commit = parseCommit(object.data);
    addTreeClosure(commit.tree);
    const parents = commit.parents;
    if (gen >= depth) {
      if (parents.length > 0 && !boundary.includes(oid)) boundary.push(oid);
      continue;
    }
    for (const parent of parents) queue.push({ oid: parent, gen: gen + 1 });
  }
  return { objects, boundary };
}

// --------------------------------------------------------------------------- packfiles

function readVarintSize(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buffer[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    byte = buffer[offset] as number;
    offset += 1;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: offset, first };
}

function readOfsDeltaBase(buffer: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buffer[start] as number;
  let offset = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buffer[offset] as number;
    offset += 1;
    value = (value + 1) * 128 + (byte & 0x7f);
  }
  return { baseOffset: value, next: offset };
}

/** Inflate one zlib stream at `offset`; returns its bytes and the offset just past the stream. */
function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const result = inflateSync(buffer.subarray(offset), { info: true }) as unknown as {
    buffer: Buffer;
    engine: { bytesWritten: number };
  };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}

/** Apply a git delta (the copy/insert instruction stream) to a base object's bytes. */
export function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset] as number;
      offset += 1;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error(`delta base size mismatch: ${sourceSize} vs ${base.length}`);
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset] as number;
    offset += 1;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) {
          copyOffset += (delta[offset] as number) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) {
          copySize += (delta[offset] as number) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  if (written !== targetSize) throw new Error(`delta produced ${written} of ${targetSize} bytes`);
  return out;
}

/**
 * Read a packfile and resolve every object (OFS_DELTA and REF_DELTA included; a REF_DELTA
 * base the pack omits comes from `resolveBase`). Throws on any structural problem — the
 * receive-pack handler turns that into `unpack <detail>`.
 */
export function readPack(pack: Buffer, resolveBase?: (oid: string) => Obj | undefined): Map<string, Obj> {
  if (pack.length < 32) throw new Error('pack is too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack does not start with PACK');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  const computed = createHash('sha1').update(pack.subarray(0, trailerStart)).digest('hex');
  if (trailer !== computed) throw new Error('pack checksum mismatch');

  interface Raw {
    offset: number;
    typeCode: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
    resolved?: Obj & { oid: string };
  }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const entryOffset = offset;
    const header = readVarintSize(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: Raw = { offset: entryOffset, typeCode, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsDeltaBase(pack, offset);
      offset = base.next;
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (CODE_TYPE[typeCode] === undefined) {
      throw new Error(`unknown pack type code ${typeCode}`);
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (offset !== trailerStart) throw new Error('pack has stray bytes before its trailer');

  const objects = new Map<string, Obj>();
  const resolve = (entry: Raw): Obj & { oid: string } => {
    if (entry.resolved !== undefined) return entry.resolved;
    let type: ObjType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (baseEntry === undefined) throw new Error('ofs-delta base is not in the pack');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const baseOid = entry.baseOid as string;
      let base: (Obj & { oid: string }) | undefined;
      for (const candidate of raw) {
        if (candidate === entry) continue;
        const resolved = candidate.resolved;
        if (resolved !== undefined && resolved.oid === baseOid) base = resolved;
      }
      if (base === undefined) {
        const external = resolveBase?.(baseOid);
        if (external === undefined) throw new Error(`ref-delta base ${baseOid} is not available`);
        type = external.type;
        data = applyDelta(external.data, entry.data);
      } else {
        type = base.type;
        data = applyDelta(base.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode] as ObjType;
      data = entry.data;
    }
    const resolved = { type, data, oid: hashObject(type, data) };
    entry.resolved = resolved;
    return resolved;
  };
  for (const entry of raw) {
    const resolved = resolve(entry);
    if (!objects.has(resolved.oid)) objects.set(resolved.oid, { type: resolved.type, data: resolved.data });
  }
  return objects;
}

/** Encode one object's pack header: the type/size varint git's pack format uses. */
function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas — the suite accepts them and they are simple). */
export function writePack(objects: Iterable<{ type: ObjType; data: Buffer }>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

// --------------------------------------------------------------------------- pkt-line

export const PKT_MAX_PAYLOAD = 65520 - 4;

/** Encode one data packet. */
export function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

export const pktFlush = (): Buffer => Buffer.from('0000', 'ascii');
export const pktDelim = (): Buffer => Buffer.from('0001', 'ascii');

/** One decoded packet from a request body. */
export type Packet = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'end' };

/**
 * Decode pkt-lines from the front of `buffer`; returns the packets and the number of bytes
 * consumed (receive-pack's pack follows the command list's flush in the same body).
 */
export function decodePackets(buffer: Buffer, maxPackets = 100_000): { packets: Packet[]; consumed: number } {
  const packets: Packet[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length && packets.length < maxPackets) {
    const header = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) break;
    const length = Number.parseInt(header, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
      break; // a flush ends the pkt-line section (the rest is raw pack, if any)
    }
    if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push({ kind: 'end' });
      offset += 4;
      continue;
    }
    if (length < 4 || offset + length > buffer.length) break;
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return { packets, consumed: offset };
}
