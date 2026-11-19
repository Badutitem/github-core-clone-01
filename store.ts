// The forge's store — in exp3 this is a facade over the native core's store.
//
// The one source of truth lives in forge-native.c (the C store inside forge.node):
// repositories, issues, pulls, comments, labels and the deterministic sequence
// clock. This file keeps the exact Store / RepoRecord surface app.ts, git.ts and
// gitserver.ts were built against, but every read and write goes through the
// addon's synchronous facade calls, so the C epoll thread's hot routes and the
// TypeScript cold surfaces always see the same state. Git objects and refs stay
// in per-repo JS Maps for now (stage 1); they move into the C store in stage 2.
//
// Determinism is unchanged: timestamps come from the C isoAt (base + seq seconds,
// proven byte-identical to the old store.ts), and no wall clock or randomness is
// read anywhere in this layer.

import { createRequire } from 'node:module';

/**
 * The login the suite's bearer token owns. The suite's scenario (kit wire.ts buildScenario(),
 * fixed seed) names the viewer "adaiversen", its checks address repositories under that login,
 * and GET /api/v3/user plus GraphQL viewer{login} must answer it. Everything the token creates
 * belongs to this login; any other owner in a path is a 404, never a 403.
 */
export const OWNER_LOGIN = 'adaiversen';

export interface GitObject {
  /** 'blob' | 'tree' | 'commit' | 'tag' */
  readonly type: string;
  /** The object's raw bytes (for a commit/tree, the uncompressed payload). */
  readonly data: Buffer;
}

export interface IssueRecord {
  readonly number: number;
  title: string;
  body: string;
  /** 'open' | 'closed' */
  state: string;
  readonly labels: string[];
  readonly createdSeq: number;
}

export interface PullRecord {
  readonly number: number;
  title: string;
  body: string;
  /** 'open' | 'closed' */
  state: string;
  readonly headRef: string;
  readonly baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergeCommitSha: string | null;
  /** Sequence stamp of the merge (0 while unmerged): the merged_at timestamp source. */
  mergedSeq: number;
  readonly createdSeq: number;
}

export interface CommentRecord {
  readonly id: number;
  readonly issueNumber: number;
  body: string;
  readonly createdSeq: number;
}

export interface RepoRecord {
  readonly id: number;
  readonly owner: string;
  readonly name: string;
  description: string;
  readonly isPrivate: boolean;
  defaultBranch: string;
  /** Full ref name ('refs/heads/main') -> commit sha. */
  readonly refs: Map<string, string>;
  /** Object sha -> object. The git object store for this repository. */
  readonly objects: Map<string, GitObject>;
  /** Issue and pull numbers share one sequence per repository, as on GitHub. */
  nextNumber: number;
  readonly issues: Map<number, IssueRecord>;
  readonly pulls: Map<number, PullRecord>;
  readonly comments: Map<number, CommentRecord[]>;
  /** Label name -> color, as POST /labels created them. */
  readonly labels: Map<string, string>;
  readonly createdSeq: number;
}

// ---------------------------------------------------------------- the addon

interface RepoSnapshot {
  id: number;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdSeq: number;
  nextNumber: number;
}

interface IssueSnapshot {
  number: number;
  title: string;
  body: string;
  state: string;
  labels: string[];
  createdSeq: number;
  comments: number;
}

interface PullSnapshot {
  number: number;
  title: string;
  body: string;
  state: string;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergeCommitSha: string | null;
  mergedSeq: number;
  createdSeq: number;
}

interface CommentSnapshot {
  id: number;
  issueNumber: number;
  body: string;
  createdSeq: number;
}

interface NativeStore {
  storeReset(): void;
  nextSeq(): number;
  nextCommentId(): number;
  isoAt(seq: number): string;
  createRepoNative(name: string, description: string, isPrivate: boolean): number;
  repoId(name: string): number;
  repoNames(): string[];
  getRepoNative(id: number): RepoSnapshot | null;
  deleteRepoNative(name: string): boolean;
  setRepoField(id: number, field: string, value: string): void;
  setLabelNative(repoId: number, name: string, color: string): void;
  getLabelNative(repoId: number, name: string): string | null;
  labelNames(repoId: number): string[];
  createIssueNative(repoId: number, title: string, body: string, labels: string[]): number;
  getIssueNative(repoId: number, number: number): IssueSnapshot | null;
  issueNumbers(repoId: number): number[];
  setIssueField(repoId: number, number: number, field: string, value: string | string[]): void;
  addCommentNative(repoId: number, issueNumber: number, body: string): CommentSnapshot | null;
  commentsNative(repoId: number, issueNumber: number): CommentSnapshot[];
  createPullNative(
    repoId: number,
    title: string,
    body: string,
    headRef: string,
    headSha: string,
    baseRef: string,
    baseSha: string,
  ): number;
  getPullNative(repoId: number, number: number): PullSnapshot | null;
  pullNumbers(repoId: number): number[];
  setPullField(repoId: number, number: number, field: string, value: string | number | boolean): void;
  objPut(repoId: number, sha: string, type: string, data: Buffer): void;
  objGet(repoId: number, sha: string): { type: string; data: Buffer } | null;
  objHas(repoId: number, sha: string): boolean;
  objSize(repoId: number): number;
  objKeys(repoId: number): string[];
  refGet(repoId: number, name: string): string | null;
  refSet(repoId: number, name: string, sha: string): void;
  refDelete(repoId: number, name: string): boolean;
  refEntries(repoId: number): Array<[string, string]>;
}

const native = createRequire(import.meta.url)('./forge.node') as NativeStore;

// ---------------------------------------------------------------- record facades

class IssueFacade implements IssueRecord {
  readonly number: number;
  readonly createdSeq: number;
  private readonly repoId: number;

  constructor(repoId: number, snapshot: IssueSnapshot) {
    this.repoId = repoId;
    this.number = snapshot.number;
    this.createdSeq = snapshot.createdSeq;
  }

  private snap(): IssueSnapshot {
    const snap = native.getIssueNative(this.repoId, this.number);
    if (snap === null) throw new Error(`issue ${this.number} no longer exists`);
    return snap;
  }

  get title(): string {
    return this.snap().title;
  }
  set title(value: string) {
    native.setIssueField(this.repoId, this.number, 'title', value);
  }
  get body(): string {
    return this.snap().body;
  }
  set body(value: string) {
    native.setIssueField(this.repoId, this.number, 'body', value);
  }
  get state(): string {
    return this.snap().state;
  }
  set state(value: string) {
    native.setIssueField(this.repoId, this.number, 'state', value);
  }
  get labels(): string[] {
    return this.snap().labels;
  }
  set labels(value: string[]) {
    native.setIssueField(this.repoId, this.number, 'labels', [...value]);
  }
}

class PullFacade implements PullRecord {
  readonly number: number;
  readonly createdSeq: number;
  private readonly repoId: number;

  constructor(repoId: number, snapshot: PullSnapshot) {
    this.repoId = repoId;
    this.number = snapshot.number;
    this.createdSeq = snapshot.createdSeq;
  }

  private snap(): PullSnapshot {
    const snap = native.getPullNative(this.repoId, this.number);
    if (snap === null) throw new Error(`pull ${this.number} no longer exists`);
    return snap;
  }

  get title(): string {
    return this.snap().title;
  }
  set title(value: string) {
    native.setPullField(this.repoId, this.number, 'title', value);
  }
  get body(): string {
    return this.snap().body;
  }
  set body(value: string) {
    native.setPullField(this.repoId, this.number, 'body', value);
  }
  get state(): string {
    return this.snap().state;
  }
  set state(value: string) {
    native.setPullField(this.repoId, this.number, 'state', value);
  }
  get headRef(): string {
    return this.snap().headRef;
  }
  get baseRef(): string {
    return this.snap().baseRef;
  }
  get headSha(): string {
    return this.snap().headSha;
  }
  set headSha(value: string) {
    native.setPullField(this.repoId, this.number, 'headSha', value);
  }
  get baseSha(): string {
    return this.snap().baseSha;
  }
  set baseSha(value: string) {
    native.setPullField(this.repoId, this.number, 'baseSha', value);
  }
  get merged(): boolean {
    return this.snap().merged;
  }
  set merged(value: boolean) {
    native.setPullField(this.repoId, this.number, 'merged', value);
  }
  get mergeCommitSha(): string | null {
    return this.snap().mergeCommitSha;
  }
  set mergeCommitSha(value: string | null) {
    native.setPullField(this.repoId, this.number, 'mergeCommitSha', value as unknown as string);
  }
  get mergedSeq(): number {
    return this.snap().mergedSeq;
  }
  set mergedSeq(value: number) {
    native.setPullField(this.repoId, this.number, 'mergedSeq', value);
  }
}

/** Map-shaped view of one repo's issues, backed by the C store. */
class IssuesMap {
  private readonly repoId: number;
  constructor(repoId: number) {
    this.repoId = repoId;
  }
  get(number: number): IssueRecord | undefined {
    const snap = native.getIssueNative(this.repoId, number);
    return snap === null ? undefined : new IssueFacade(this.repoId, snap);
  }
  has(number: number): boolean {
    return native.getIssueNative(this.repoId, number) !== null;
  }
  get size(): number {
    return native.issueNumbers(this.repoId).length;
  }
  keys(): IterableIterator<number> {
    return native.issueNumbers(this.repoId)[Symbol.iterator]() as IterableIterator<number>;
  }
  values(): IterableIterator<IssueRecord> {
    const repoId = this.repoId;
    return native
      .issueNumbers(repoId)
      .map((n) => new IssueFacade(repoId, native.getIssueNative(repoId, n) as IssueSnapshot))
      [Symbol.iterator]() as IterableIterator<IssueRecord>;
  }
  entries(): IterableIterator<readonly [number, IssueRecord]> {
    const repoId = this.repoId;
    return native
      .issueNumbers(repoId)
      .map(
        (n) =>
          [n, new IssueFacade(repoId, native.getIssueNative(repoId, n) as IssueSnapshot)] as const,
      )
      [Symbol.iterator]() as IterableIterator<readonly [number, IssueRecord]>;
  }
  [Symbol.iterator](): IterableIterator<readonly [number, IssueRecord]> {
    return this.entries();
  }
}

/** Map-shaped view of one repo's pulls, backed by the C store. */
class PullsMap {
  private readonly repoId: number;
  constructor(repoId: number) {
    this.repoId = repoId;
  }
  get(number: number): PullRecord | undefined {
    const snap = native.getPullNative(this.repoId, number);
    return snap === null ? undefined : new PullFacade(this.repoId, snap);
  }
  has(number: number): boolean {
    return native.getPullNative(this.repoId, number) !== null;
  }
  get size(): number {
    return native.pullNumbers(this.repoId).length;
  }
  keys(): IterableIterator<number> {
    return native.pullNumbers(this.repoId)[Symbol.iterator]() as IterableIterator<number>;
  }
  values(): IterableIterator<PullRecord> {
    const repoId = this.repoId;
    return native
      .pullNumbers(repoId)
      .map((n) => new PullFacade(repoId, native.getPullNative(repoId, n) as PullSnapshot))
      [Symbol.iterator]() as IterableIterator<PullRecord>;
  }
  entries(): IterableIterator<readonly [number, PullRecord]> {
    const repoId = this.repoId;
    return native
      .pullNumbers(repoId)
      .map(
        (n) => [n, new PullFacade(repoId, native.getPullNative(repoId, n) as PullSnapshot)] as const,
      )
      [Symbol.iterator]() as IterableIterator<readonly [number, PullRecord]>;
  }
  [Symbol.iterator](): IterableIterator<readonly [number, PullRecord]> {
    return this.entries();
  }
}

/** Map-shaped view of one repo's comments (number -> records in creation order). */
class CommentsMap {
  private readonly repoId: number;
  constructor(repoId: number) {
    this.repoId = repoId;
  }
  get(issueNumber: number): CommentRecord[] {
    return native.commentsNative(this.repoId, issueNumber) as CommentRecord[];
  }
  has(issueNumber: number): boolean {
    return native.commentsNative(this.repoId, issueNumber).length > 0;
  }
}

/** Map-shaped view of one repo's labels (name -> color). */
class LabelsMap {
  private readonly repoId: number;
  constructor(repoId: number) {
    this.repoId = repoId;
  }
  get(name: string): string | undefined {
    const color = native.getLabelNative(this.repoId, name);
    return color === null ? undefined : color;
  }
  set(name: string, color: string): this {
    native.setLabelNative(this.repoId, name, color);
    return this;
  }
  has(name: string): boolean {
    return native.getLabelNative(this.repoId, name) !== null;
  }
  keys(): IterableIterator<string> {
    return native.labelNames(this.repoId)[Symbol.iterator]() as IterableIterator<string>;
  }
  get size(): number {
    return native.labelNames(this.repoId).length;
  }
}

/** Map-shaped view of one repo's git objects, backed by the C object store. */
class ObjectsMap {
  private readonly repoId: number;
  constructor(repoId: number) {
    this.repoId = repoId;
  }
  get(oid: string): GitObject | undefined {
    const found = native.objGet(this.repoId, oid);
    return found === null ? undefined : found;
  }
  set(oid: string, object: GitObject): this {
    native.objPut(this.repoId, oid, object.type, object.data);
    return this;
  }
  has(oid: string): boolean {
    return native.objHas(this.repoId, oid);
  }
  get size(): number {
    return native.objSize(this.repoId);
  }
  keys(): IterableIterator<string> {
    return native.objKeys(this.repoId)[Symbol.iterator]() as IterableIterator<string>;
  }
}

/** Map-shaped view of one repo's git refs, backed by the C ref store. */
class RefsMap {
  private readonly repoId: number;
  constructor(repoId: number) {
    this.repoId = repoId;
  }
  get(name: string): string | undefined {
    const sha = native.refGet(this.repoId, name);
    return sha === null ? undefined : sha;
  }
  set(name: string, sha: string): this {
    native.refSet(this.repoId, name, sha);
    return this;
  }
  has(name: string): boolean {
    return native.refGet(this.repoId, name) !== null;
  }
  delete(name: string): boolean {
    return native.refDelete(this.repoId, name);
  }
  get size(): number {
    return native.refEntries(this.repoId).length;
  }
  entries(): IterableIterator<readonly [string, string]> {
    return native.refEntries(this.repoId)[Symbol.iterator]() as IterableIterator<
      readonly [string, string]
    >;
  }
  keys(): IterableIterator<string> {
    return native
      .refEntries(this.repoId)
      .map(([name]) => name)
      [Symbol.iterator]() as IterableIterator<string>;
  }
  values(): IterableIterator<string> {
    return native
      .refEntries(this.repoId)
      .map(([, sha]) => sha)
      [Symbol.iterator]() as IterableIterator<string>;
  }
  [Symbol.iterator](): IterableIterator<readonly [string, string]> {
    return this.entries();
  }
}

class RepoFacade implements RepoRecord {
  readonly id: number;
  readonly owner = OWNER_LOGIN;
  readonly name: string;
  readonly isPrivate: boolean;
  readonly createdSeq: number;
  readonly refs: Map<string, string>;
  readonly objects: Map<string, GitObject>;
  readonly issues: Map<number, IssueRecord>;
  readonly pulls: Map<number, PullRecord>;
  readonly comments: Map<number, CommentRecord[]>;
  readonly labels: Map<string, string>;
  private descriptionCache: string;
  private defaultBranchCache: string;

  constructor(snapshot: RepoSnapshot) {
    this.id = snapshot.id;
    this.name = snapshot.name;
    this.isPrivate = snapshot.isPrivate;
    this.createdSeq = snapshot.createdSeq;
    this.descriptionCache = snapshot.description;
    this.defaultBranchCache = snapshot.defaultBranch;
    this.refs = new RefsMap(snapshot.id) as unknown as Map<string, string>;
    this.objects = new ObjectsMap(snapshot.id) as unknown as Map<string, GitObject>;
    this.issues = new IssuesMap(snapshot.id) as unknown as Map<number, IssueRecord>;
    this.pulls = new PullsMap(snapshot.id) as unknown as Map<number, PullRecord>;
    this.comments = new CommentsMap(snapshot.id) as unknown as Map<number, CommentRecord[]>;
    this.labels = new LabelsMap(snapshot.id) as unknown as Map<string, string>;
  }

  get description(): string {
    return this.descriptionCache;
  }
  set description(value: string) {
    this.descriptionCache = value;
    native.setRepoField(this.id, 'description', value);
  }
  get defaultBranch(): string {
    return this.defaultBranchCache;
  }
  set defaultBranch(value: string) {
    this.defaultBranchCache = value;
    native.setRepoField(this.id, 'defaultBranch', value);
  }
  get nextNumber(): number {
    const snap = native.getRepoNative(this.id);
    return snap === null ? 0 : snap.nextNumber;
  }
  set nextNumber(_value: number) {
    // The shared issue/pull sequence lives in the C store and advances only
    // through createIssueNative / createPullNative; nothing may rewind it.
    throw new Error('nextNumber is owned by the native store');
  }
}

/** Map-shaped view of the store's repositories (name -> record). */
class ReposMap {
  private readonly store: Store;
  constructor(store: Store) {
    this.store = store;
  }
  has(name: string): boolean {
    return native.repoId(name) !== 0;
  }
  get(name: string): RepoRecord | undefined {
    return this.store.wrap(name);
  }
  delete(name: string): boolean {
    this.store.dropWrapper(name);
    return native.deleteRepoNative(name);
  }
  keys(): IterableIterator<string> {
    return native.repoNames()[Symbol.iterator]() as IterableIterator<string>;
  }
  values(): IterableIterator<RepoRecord> {
    const store = this.store;
    return native
      .repoNames()
      .map((name) => store.wrap(name) as RepoRecord)
      [Symbol.iterator]() as IterableIterator<RepoRecord>;
  }
  get size(): number {
    return native.repoNames().length;
  }
}

/** The whole forge state: a facade over the native core's one store. */
export class Store {
  readonly repos: Map<string, RepoRecord>;
  private readonly wrappers = new Map<string, RepoFacade>();

  constructor() {
    native.storeReset();
    this.repos = new ReposMap(this) as unknown as Map<string, RepoRecord>;
  }

  /** The wrapper for a repository by name, or undefined when it does not exist. */
  wrap(name: string): RepoFacade | undefined {
    const id = native.repoId(name);
    if (id === 0) return undefined;
    const prior = this.wrappers.get(name);
    if (prior !== undefined && prior.id === id) return prior;
    const snap = native.getRepoNative(id);
    if (snap === null) return undefined;
    const facade = new RepoFacade(snap);
    this.wrappers.set(name, facade);
    return facade;
  }

  dropWrapper(name: string): void {
    this.wrappers.delete(name);
  }

  /** The next deterministic sequence stamp (orders issues/pulls/comments by creation). */
  nextSeq(): number {
    return native.nextSeq();
  }

  /** A deterministic ISO timestamp for a sequence stamp: base + seq seconds. */
  isoAt(seq: number): string {
    return native.isoAt(seq);
  }

  createRepo(name: string, description = '', isPrivate = false): RepoRecord {
    native.createRepoNative(name, description, isPrivate);
    const facade = this.wrap(name);
    if (facade === undefined) throw new Error(`repo ${name} vanished at creation`);
    return facade;
  }

  /** A repository by name, only when the path's owner is the token's login. */
  repoFor(owner: string, name: string): RepoRecord | undefined {
    if (owner !== OWNER_LOGIN) return undefined;
    return this.wrap(name);
  }

  nextCommentId(): number {
    return native.nextCommentId();
  }

  /** A new issue in a repository, numbered from the shared issue/pull sequence. */
  createIssue(repo: RepoRecord, title: string, body: string, labels: string[] = []): IssueRecord {
    const number = native.createIssueNative(repo.id, title, body, labels);
    const snap = native.getIssueNative(repo.id, number);
    if (snap === null) throw new Error(`issue ${number} vanished at creation`);
    return new IssueFacade(repo.id, snap);
  }

  /** A new pull request in a repository, numbered from the shared issue/pull sequence. */
  createPull(
    repo: RepoRecord,
    title: string,
    body: string,
    headRef: string,
    headSha: string,
    baseRef: string,
    baseSha: string,
  ): PullRecord {
    const number = native.createPullNative(repo.id, title, body, headRef, headSha, baseRef, baseSha);
    const snap = native.getPullNative(repo.id, number);
    if (snap === null) throw new Error(`pull ${number} vanished at creation`);
    return new PullFacade(repo.id, snap);
  }

  /** A comment on an issue or pull number in a repository. */
  addComment(repo: RepoRecord, issueNumber: number, body: string): CommentRecord {
    const snap = native.addCommentNative(repo.id, issueNumber, body);
    if (snap === null) throw new Error('comment vanished at creation');
    return snap as CommentRecord;
  }
}

/** An opaque, stable GraphQL node id for a typed numeric id (stable across reads of one run). */
export function nodeId(type: string, id: number): string {
  return Buffer.from(`${type}:${id}`, 'utf8').toString('base64');
}

/** Decode a node id back to its numeric id, or undefined when it is not one of ours. */
export function idFromNodeId(type: string, raw: string): number | undefined {
  try {
    const text = Buffer.from(raw, 'base64').toString('utf8');
    const [kind, digits] = text.split(':');
    if (kind !== type) return undefined;
    const value = Number(digits);
    return Number.isInteger(value) && value > 0 ? value : undefined;
  } catch {
    return undefined;
  }
}
