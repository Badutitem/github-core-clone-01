// The forge's in-memory store: every object the four surfaces serve lives here, in one place, so
// REST, GraphQL, MCP and git smart HTTP all read and write the same state (the suite checks that
// an object created on one surface reads back identically on the others).
//
// Determinism: nothing in this store reads the wall clock or Math.random. Forge-authored
// timestamps come from a fixed base plus a monotonic counter, so two runs of the same trial
// produce the same bytes in the same order.

/**
 * The login the suite's bearer token owns. The suite's scenario (kit wire.ts buildScenario(),
 * fixed seed) names the viewer "adaiversen", its checks address repositories under that login,
 * and GET /api/v3/user plus GraphQL viewer{login} must answer it. Everything the token creates
 * belongs to this login; any other owner in a path is a 404, never a 403.
 */
export const OWNER_LOGIN = 'adaiversen';

/** Fixed base for forge-authored timestamps (2026-11-14T06:30:00Z, the competition's opening). */
const CLOCK_BASE_MS = 1_794_637_800_000;

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

/** The whole forge state: repositories keyed by name (all belong to OWNER_LOGIN). */
export class Store {
  readonly repos = new Map<string, RepoRecord>();
  private repoIdSeq = 5000;
  private commentIdSeq = 1;
  private seq = 0;

  /** The next deterministic sequence stamp (orders issues/pulls/comments by creation). */
  nextSeq(): number {
    this.seq += 1;
    return this.seq;
  }

  /** A deterministic ISO timestamp for a sequence stamp: base + seq seconds. */
  isoAt(seq: number): string {
    return new Date(CLOCK_BASE_MS + seq * 1000).toISOString();
  }

  createRepo(name: string, description = '', isPrivate = false): RepoRecord {
    this.repoIdSeq += 1;
    const repo: RepoRecord = {
      id: this.repoIdSeq,
      owner: OWNER_LOGIN,
      name,
      description,
      isPrivate,
      defaultBranch: 'main',
      refs: new Map(),
      objects: new Map(),
      nextNumber: 1,
      issues: new Map(),
      pulls: new Map(),
      comments: new Map(),
      labels: new Map(),
      createdSeq: this.nextSeq(),
    };
    this.repos.set(name, repo);
    return repo;
  }

  /** A repository by name, only when the path's owner is the token's login. */
  repoFor(owner: string, name: string): RepoRecord | undefined {
    if (owner !== OWNER_LOGIN) return undefined;
    return this.repos.get(name);
  }

  nextCommentId(): number {
    this.commentIdSeq += 1;
    return this.commentIdSeq;
  }

  /** A new issue in a repository, numbered from the shared issue/pull sequence. */
  createIssue(repo: RepoRecord, title: string, body: string, labels: string[] = []): IssueRecord {
    const number = repo.nextNumber;
    repo.nextNumber = number + 1;
    const issue: IssueRecord = {
      number,
      title,
      body,
      state: 'open',
      labels,
      createdSeq: this.nextSeq(),
    };
    repo.issues.set(number, issue);
    return issue;
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
    const number = repo.nextNumber;
    repo.nextNumber = number + 1;
    const pull: PullRecord = {
      number,
      title,
      body,
      state: 'open',
      headRef,
      baseRef,
      headSha,
      baseSha,
      merged: false,
      mergeCommitSha: null,
      mergedSeq: 0,
      createdSeq: this.nextSeq(),
    };
    repo.pulls.set(number, pull);
    return pull;
  }

  /** A comment on an issue or pull number in a repository. */
  addComment(repo: RepoRecord, issueNumber: number, body: string): CommentRecord {
    const comment: CommentRecord = {
      id: this.nextCommentId(),
      issueNumber,
      body,
      createdSeq: this.nextSeq(),
    };
    const list = repo.comments.get(issueNumber) ?? [];
    list.push(comment);
    repo.comments.set(issueNumber, list);
    return comment;
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
