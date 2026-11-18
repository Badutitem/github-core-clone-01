// The forge's HTTP surface: one node:http server routing the four surfaces the suite drives —
// git smart HTTP at /{owner}/{repo}.git, REST v3 under /api/v3, GraphQL at /api/graphql and MCP
// at /mcp — all backed by the one store in store.ts.
//
// The REST surface below covers repositories, branches, commits, the contents API (which is
// also the fixture path half the suite seeds through), labels, issues, comments and pull
// requests with squash merges. Git smart HTTP lives in gitserver.ts; GraphQL and MCP answer
// the JSON 404 until their phases land. main.ts is the lifecycle and stays as the starter
// shipped it.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import {
  OWNER_LOGIN,
  Store,
  idFromNodeId,
  nodeId,
  type IssueRecord,
  type PullRecord,
  type RepoRecord,
} from './store.ts';
import { handleGit } from './gitserver.ts';
import {
  buildCommit,
  buildTreeFromFlat,
  commitPaths,
  diffFlat,
  flattenTree,
  forgeIdentity,
  getObject,
  hashObject,
  mergeBase,
  mergeFlat,
  parseCommit,
  parseTree as parseTreeEntries,
  peelToCommit,
  refTip,
  resolveCommit,
  storeObject,
  subtreeAt,
  ZERO_OID,
} from './git.ts';

const JSON_TYPE = 'application/json; charset=utf-8';

/** The token the suite presents; in a trial it is in our environment as MAKEFUN_SHOP_TOKEN. */
function expectedToken(): string {
  return process.env.MAKEFUN_SHOP_TOKEN ?? '';
}

let requestSeq = 0;

/** A non-empty, run-unique request id for the X-GitHub-Request-Id every REST reply carries. */
function nextRequestId(): string {
  requestSeq += 1;
  return `forge-${requestSeq}`;
}

/** Answer one request with a JSON body and the headers every reply carries. */
function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Readonly<Record<string, string>> = {},
): void {
  const text = body === undefined ? '' : `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'x-github-request-id': nextRequestId(),
    ...(text === '' ? {} : { 'content-length': Buffer.byteLength(text) }),
    ...headers,
  });
  res.end(text);
}

/** An error reply: a JSON body with a string message, as the wire contract requires. */
function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

/** Read a request body to the end. */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** The origin the caller dialed (from the Host header): pagination Links must stay on it. */
function originOf(req: IncomingMessage): string {
  return `http://${req.headers.host ?? 'entry'}`;
}

interface Page {
  readonly perPage: number;
  readonly page: number;
}

function pageOf(url: URL): Page {
  const perPage = Math.max(1, Number(url.searchParams.get('per_page') ?? '30') || 30);
  const page = Math.max(1, Number(url.searchParams.get('page') ?? '1') || 1);
  return { perPage, page };
}

/**
 * Send one page of a list with an absolute `Link: rel="next"` header when more pages remain
 * (the suite follows the Link chain and refuses a next link that leaves the entry's origin).
 */
function sendList<T>(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  items: readonly T[],
  map: (item: T) => unknown,
): void {
  const { perPage, page } = pageOf(url);
  const slice = items.slice((page - 1) * perPage, page * perPage);
  const headers: Record<string, string> = {};
  if (page * perPage < items.length) {
    const params = new URLSearchParams(url.searchParams);
    params.set('per_page', String(perPage));
    params.set('page', String(page + 1));
    headers.link = `<${originOf(req)}${url.pathname}?${params.toString()}>; rel="next"`;
  }
  sendJson(res, 200, slice.map(map), headers);
}

/** The repository object as REST v3 returns it. */
function repoJson(store: Store, repo: RepoRecord): Record<string, unknown> {
  const stamp = store.isoAt(repo.createdSeq);
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: 1000, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: stamp,
    updated_at: stamp,
    pushed_at: stamp,
  };
}

/** A stable REST id for an issue or pull: unique per repository, deterministic per run. */
function restId(repo: RepoRecord, number: number): number {
  return repo.id * 100_000 + number;
}

function labelJson(repo: RepoRecord, name: string): Record<string, unknown> {
  return { name, color: repo.labels.get(name) ?? 'ededed' };
}

/** The issue object as REST v3 returns it. */
function issueJson(store: Store, repo: RepoRecord, issue: IssueRecord): Record<string, unknown> {
  const stamp = store.isoAt(issue.createdSeq);
  return {
    id: restId(repo, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => labelJson(repo, name)),
    user: { login: repo.owner, id: 1000, type: 'User' },
    comments: (repo.comments.get(issue.number) ?? []).length,
    created_at: stamp,
    updated_at: stamp,
  };
}

/** The pull-request object as REST v3 returns it. */
function pullJson(store: Store, repo: RepoRecord, pull: PullRecord): Record<string, unknown> {
  const stamp = store.isoAt(pull.createdSeq);
  return {
    id: restId(repo, pull.number),
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}` },
    merged: pull.merged,
    merged_at: pull.merged ? store.isoAt(pull.mergedSeq) : null,
    merge_commit_sha: pull.mergeCommitSha,
    user: { login: repo.owner, id: 1000, type: 'User' },
    created_at: stamp,
    updated_at: stamp,
  };
}

/** True when the request carries the suite's bearer token (any token at all in local dev). */
function authorized(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  const expected = expectedToken();
  if (expected === '') return header.startsWith('Bearer ') && header.length > 'Bearer '.length;
  return header === `Bearer ${expected}`;
}

/** Build the server. It binds nothing until the caller listens; the entry listens ephemerally. */
export function createApp(store: Store = new Store()): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void handle(store, req, res).catch((err: unknown) => {
      console.error('HANDLE ERROR', err);
      if (!res.headersSent) sendError(res, 500, 'Internal Server Error');
    });
  });
}

/** The git smart-HTTP path shape: /{owner}/{repo}.git[/...]. */
const GIT_PATH = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/;

async function handle(store: Store, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://entry');
  const path = url.pathname;
  const method = req.method ?? 'GET';

  // The env's boot probe takes no token.
  if (method === 'GET' && path === '/healthz') {
    sendJson(res, 200, { ok: true });
    return;
  }

  // Everything else is the suite's: a request without its token is a 401.
  if (!authorized(req)) {
    sendError(res, 401, 'Bad credentials');
    return;
  }

  // Git smart HTTP carries binary pkt-line bodies, never JSON: it routes before the JSON
  // body parse below (gitserver.ts reads the raw body itself).
  const gitMatch = GIT_PATH.exec(path);
  if (gitMatch) {
    const handled = await handleGit(store, req, res, {
      owner: gitMatch[1] as string,
      name: gitMatch[2] as string,
      rest: gitMatch[3] ?? '',
      url,
    });
    if (!handled) sendError(res, 404, 'Not Found');
    return;
  }

  // MCP speaks JSON-RPC with its own error shapes (a body that is not JSON is a -32700 parse
  // error, not the REST {message} 400), so it routes before the JSON body parse below and
  // reads the raw body itself. Auth was already enforced above: an unauthenticated MCP call
  // is the same 401 as anywhere else.
  if (path === '/mcp') {
    await handleMcp(store, req, res);
    return;
  }

  // GraphQL also reads its own body: a batched request is a JSON array of operations,
  // which the object-only parse below would refuse with a 400.
  if (path === '/api/graphql') {
    await handleGraphql(store, req, res);
    return;
  }

  // Parse a JSON body once, up front: a malformed one is a 400 on any API route.
  let body: Record<string, unknown> = {};
  if (method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') {
    const raw = await readBody(req);
    if (raw.length > 0) {
      try {
        const parsed: unknown = JSON.parse(raw.toString('utf8'));
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          sendError(res, 400, 'Problems parsing JSON');
          return;
        }
        body = parsed as Record<string, unknown>;
      } catch {
        sendError(res, 400, 'Problems parsing JSON');
        return;
      }
    }
  }

  // ---- REST v3: the API root ----
  if ((path === '/api/v3' || path === '/api/v3/') && method === 'GET') {
    sendJson(
      res,
      200,
      { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' },
      { 'x-oauth-scopes': 'repo, read:org' },
    );
    return;
  }

  if (path === '/api/v3/meta' && method === 'GET') {
    sendJson(res, 200, { installed_version: '1.0.0-forge', api: ['api.github.com'] });
    return;
  }

  if (path === '/api/v3/user' && method === 'GET') {
    sendJson(res, 200, { login: OWNER_LOGIN, id: 1000, type: 'User' });
    return;
  }

  // ---- REST v3: the viewer's repositories ----
  if (path === '/api/v3/user/repos') {
    if (method === 'POST') {
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') {
        sendError(res, 422, 'Repository creation failed: name is required');
        return;
      }
      if (store.repos.has(name)) {
        sendError(res, 422, 'Repository creation failed: name already exists on this account');
        return;
      }
      const repo = store.createRepo(
        name,
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      if (typeof body.default_branch === 'string' && body.default_branch !== '') {
        repo.defaultBranch = body.default_branch;
      }
      sendJson(res, 201, repoJson(store, repo));
      return;
    }
    if (method === 'GET') {
      sendList(req, res, url, [...store.repos.values()], (repo) => repoJson(store, repo));
      return;
    }
  }

  // ---- REST v3: one repository and everything under it ----
  const repoMatch = /^\/api\/v3\/repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(path);
  if (repoMatch) {
    const repo = store.repoFor(repoMatch[1] as string, repoMatch[2] as string);
    if (repo === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const sub = repoMatch[3] ?? '';
    if (sub === '') {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(store, repo));
        return;
      }
      if (method === 'PATCH') {
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.default_branch === 'string' && body.default_branch !== '') {
          repo.defaultBranch = body.default_branch;
        }
        sendJson(res, 200, repoJson(store, repo));
        return;
      }
      if (method === 'DELETE') {
        store.repos.delete(repo.name);
        res.writeHead(204, { 'x-github-request-id': nextRequestId() });
        res.end();
        return;
      }
    }
    if (await routeRepo(store, req, res, { repo, sub, url, body })) return;
  }

  // Anything else is an unknown route: the JSON 404 (MCP and GraphQL routed above).
  sendError(res, 404, 'Not Found');
}

interface RepoRoute {
  readonly repo: RepoRecord;
  readonly sub: string;
  readonly url: URL;
  readonly body: Record<string, unknown>;
}

/** A branch's full ref from its short name. */
function branchRef(name: string): string {
  return `refs/heads/${name}`;
}

/** The routes under /api/v3/repos/{owner}/{repo}/... — false when nothing matched. */
async function routeRepo(
  store: Store,
  req: IncomingMessage,
  res: ServerResponse,
  route: RepoRoute,
): Promise<boolean> {
  const { repo, sub, url, body } = route;
  const method = req.method ?? 'GET';

  // ---- branches ----
  if (sub === '/branches' && method === 'GET') {
    const branches: Array<{ name: string; commit: { sha: string } }> = [];
    for (const [ref, sha] of repo.refs) {
      if (ref.startsWith('refs/heads/')) branches.push({ name: ref.slice('refs/heads/'.length), commit: { sha } });
    }
    sendList(req, res, url, branches, (branch) => ({ name: branch.name, commit: branch.commit, protected: false }));
    return true;
  }

  // ---- commits ----
  if (sub === '/commits' && method === 'GET') {
    const wanted = url.searchParams.get('sha') ?? repo.defaultBranch;
    const tip = resolveCommit(repo, wanted);
    if (tip === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const commits: Array<Record<string, unknown>> = [];
    let current: string | undefined = tip;
    const seen = new Set<string>();
    while (current !== undefined && !seen.has(current)) {
      seen.add(current);
      const object = getObject(repo, current);
      if (object === undefined || object.type !== 'commit') break;
      const commit = parseCommit(object.data);
      const message = commit.message.endsWith('\n') ? commit.message.slice(0, -1) : commit.message;
      commits.push({
        sha: current,
        commit: {
          message,
          author: { name: authorName(commit.author), email: authorEmail(commit.author) },
          committer: { name: authorName(commit.committer), email: authorEmail(commit.committer) },
        },
        author: { login: repo.owner },
        committer: { login: repo.owner },
      });
      current = commit.parents[0];
    }
    sendList(req, res, url, commits, (entry) => entry);
    return true;
  }

  // ---- git refs (branch creation) ----
  if (sub === '/git/refs' && method === 'POST') {
    const ref = typeof body.ref === 'string' ? body.ref : '';
    const sha = typeof body.sha === 'string' ? body.sha : '';
    if (!ref.startsWith('refs/') || sha === '') {
      sendError(res, 422, 'Reference creation failed: ref and sha are required');
      return true;
    }
    const target = getObject(repo, sha);
    if (target === undefined) {
      sendError(res, 422, `Reference creation failed: object ${sha} does not exist`);
      return true;
    }
    if (repo.refs.has(ref)) {
      sendError(res, 422, 'Reference already exists');
      return true;
    }
    repo.refs.set(ref, sha);
    sendJson(res, 201, { ref, object: { sha, type: target.type } });
    return true;
  }

  // ---- labels ----
  if (sub === '/labels') {
    if (method === 'POST') {
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') {
        sendError(res, 422, 'Label creation failed: name is required');
        return true;
      }
      if (repo.labels.has(name)) {
        sendError(res, 422, 'Label creation failed: name already exists');
        return true;
      }
      repo.labels.set(name, typeof body.color === 'string' ? body.color : 'ededed');
      sendJson(res, 201, labelJson(repo, name));
      return true;
    }
    if (method === 'GET') {
      sendList(req, res, url, [...repo.labels.keys()], (name) => labelJson(repo, name));
      return true;
    }
  }

  // ---- contents ----
  if (sub === '/contents' || sub.startsWith('/contents/')) {
    const rawPath = sub === '/contents' ? '' : sub.slice('/contents/'.length);
    const filePath = rawPath.split('/').map((segment) => decodeURIComponent(segment)).join('/');
    routeContents(store, req, res, { repo, filePath, url, body });
    return true;
  }

  // ---- issues, comments, pulls ----
  if (await routeIssuesPulls(store, req, res, route)) return true;

  return false;
}

/** `Name <email> 1700000000 +0000` -> `Name`. */
function authorName(line: string): string {
  const at = line.indexOf(' <');
  return at < 0 ? line : line.slice(0, at);
}

/** `Name <email> 1700000000 +0000` -> `email`. */
function authorEmail(line: string): string {
  const open = line.indexOf('<');
  const close = line.indexOf('>');
  return open < 0 || close < 0 ? '' : line.slice(open + 1, close);
}

interface ContentsRoute {
  readonly repo: RepoRecord;
  readonly filePath: string;
  readonly url: URL;
  readonly body: Record<string, unknown>;
}

/**
 * The contents API: files and directories over the branch trees. A PUT authors a real git
 * commit through commitPaths (the fixture path the suite seeds most of its state through);
 * the blob id it reports is the git blob id, so REST and git reads agree byte for byte.
 */
function routeContents(
  store: Store,
  req: IncomingMessage,
  res: ServerResponse,
  route: ContentsRoute,
): void {
  const { repo, filePath, url, body } = route;
  const method = req.method ?? 'GET';
  const branchName = typeof body.branch === 'string' && body.branch !== ''
    ? body.branch
    : (url.searchParams.get('ref') ?? repo.defaultBranch);
  const ref = branchRef(branchName);

  if (method === 'PUT') {
    const tip = refTip(repo, ref);
    if (tip === undefined && repo.refs.size > 0) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const encoded = typeof body.content === 'string' ? body.content : '';
    const content = Buffer.from(encoded.replace(/\s+/g, ''), 'base64');
    const message = typeof body.message === 'string' ? body.message : 'Update file';
    const tipCommit = tip !== undefined ? getObject(repo, tip) : undefined;
    const files = tipCommit !== undefined && tipCommit.type === 'commit'
      ? flattenTree(repo, parseCommit(tipCommit.data).tree)
      : new Map<string, string>();
    const existing = files.get(filePath);
    let status = 201;
    if (existing !== undefined) {
      const sha = typeof body.sha === 'string' ? body.sha : undefined;
      if (sha === undefined) {
        sendError(res, 422, 'Invalid request: sha is required to update an existing file');
        return;
      }
      if (sha !== existing) {
        sendError(res, 409, 'Conflict: the sha does not match the current content');
        return;
      }
      status = 200;
    } else if (body.sha !== undefined) {
      sendError(res, 422, 'Invalid request: sha must not be supplied for a new file');
      return;
    }
    const commitSha = commitPaths(store, repo, ref, new Map([[filePath, content]]), message);
    const blobSha = hashObject('blob', content);
    sendJson(res, status, {
      content: {
        name: filePath.split('/').pop() ?? filePath,
        path: filePath,
        sha: blobSha,
        size: content.length,
        type: 'file',
        encoding: 'base64',
      },
      commit: { sha: commitSha },
    });
    return;
  }

  if (method === 'DELETE') {
    const tip = refTip(repo, ref);
    const tipCommit = tip !== undefined ? getObject(repo, tip) : undefined;
    if (tipCommit === undefined || tipCommit.type !== 'commit') {
      sendError(res, 404, 'Not Found');
      return;
    }
    const files = flattenTree(repo, parseCommit(tipCommit.data).tree);
    const existing = files.get(filePath);
    if (existing === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const sha = typeof body.sha === 'string' ? body.sha : undefined;
    if (sha === undefined) {
      sendError(res, 422, 'Invalid request: sha is required');
      return;
    }
    if (sha !== existing) {
      sendError(res, 409, 'Conflict: the sha does not match the current content');
      return;
    }
    const message = typeof body.message === 'string' ? body.message : 'Delete file';
    const commitSha = commitPaths(store, repo, ref, new Map([[filePath, null]]), message);
    sendJson(res, 200, { content: null, commit: { sha: commitSha } });
    return;
  }

  if (method === 'GET') {
    const wanted = url.searchParams.get('ref') ?? repo.defaultBranch;
    const commitSha = resolveCommit(repo, wanted);
    if (commitSha === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const commit = getObject(repo, commitSha);
    if (commit === undefined || commit.type !== 'commit') {
      sendError(res, 404, 'Not Found');
      return;
    }
    const rootTree = parseCommit(commit.data).tree;
    if (filePath !== '') {
      const files = flattenTree(repo, rootTree);
      const blobSha = files.get(filePath);
      if (blobSha !== undefined) {
        const blob = getObject(repo, blobSha);
        if (blob !== undefined) {
          sendJson(res, 200, {
            type: 'file',
            encoding: 'base64',
            content: blob.data.toString('base64'),
            name: filePath.split('/').pop() ?? filePath,
            path: filePath,
            sha: blobSha,
            size: blob.data.length,
          });
          return;
        }
      }
    }
    const dirTree = subtreeAt(repo, rootTree, filePath);
    if (dirTree === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const tree = getObject(repo, dirTree);
    if (tree === undefined || tree.type !== 'tree') {
      sendError(res, 404, 'Not Found');
      return;
    }
    const entries = parseTreeEntries(tree.data).map((entry) => ({
      type: entry.mode === '40000' ? 'dir' : 'file',
      name: entry.name,
      path: filePath === '' ? entry.name : `${filePath}/${entry.name}`,
      sha: entry.oid,
    }));
    sendJson(res, 200, entries);
    return;
  }

  sendError(res, 404, 'Not Found');
}

/** Label names from a request body, validated against the repository's label set. */
function bodyLabels(repo: RepoRecord, body: Record<string, unknown>): string[] | null {
  const raw = body.labels;
  if (!Array.isArray(raw)) return [];
  const names: string[] = [];
  for (const entry of raw) {
    const name = typeof entry === 'string' ? entry : '';
    if (name === '' || !repo.labels.has(name)) return null;
    names.push(name);
  }
  return names;
}

/** Issues + comments + pulls under one repository. False when nothing matched. */
async function routeIssuesPulls(
  store: Store,
  req: IncomingMessage,
  res: ServerResponse,
  route: RepoRoute,
): Promise<boolean> {
  const { repo, sub, url, body } = route;
  const method = req.method ?? 'GET';

  // ---- issues ----
  if (sub === '/issues') {
    if (method === 'POST') {
      const title = typeof body.title === 'string' ? body.title : '';
      if (title === '') {
        sendError(res, 422, 'Issue creation failed: title is required');
        return true;
      }
      const labels = bodyLabels(repo, body);
      if (labels === null) {
        sendError(res, 422, 'Validation Failed: one or more labels do not exist');
        return true;
      }
      const issue = store.createIssue(repo, title, typeof body.body === 'string' ? body.body : '', labels);
      sendJson(res, 201, issueJson(store, repo, issue));
      return true;
    }
    if (method === 'GET') {
      const state = url.searchParams.get('state') ?? 'open';
      let issues = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') issues = issues.filter((i) => i.state === state);
      const direction = url.searchParams.get('direction') ?? 'desc';
      issues.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
      sendList(req, res, url, issues, (issue) => issueJson(store, repo, issue));
      return true;
    }
  }

  const issueMatch = /^\/issues\/(\d+)$/.exec(sub);
  if (issueMatch) {
    const number = Number(issueMatch[1]);
    const issue = repo.issues.get(number);
    if (issue === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (method === 'GET') {
      sendJson(res, 200, issueJson(store, repo, issue));
      return true;
    }
    if (method === 'PATCH') {
      if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (body.labels !== undefined) {
        const labels = bodyLabels(repo, body);
        if (labels === null) {
          sendError(res, 422, 'Validation Failed: one or more labels do not exist');
          return true;
        }
        issue.labels = labels;
      }
      sendJson(res, 200, issueJson(store, repo, issue));
      return true;
    }
  }

  const commentsMatch = /^\/issues\/(\d+)\/comments$/.exec(sub);
  if (commentsMatch) {
    const number = Number(commentsMatch[1]);
    // Issue comments live on pull requests too (one shared number sequence, as on GitHub).
    if (repo.issues.get(number) === undefined && repo.pulls.get(number) === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (method === 'POST') {
      const text = typeof body.body === 'string' ? body.body : '';
      if (text === '') {
        sendError(res, 422, 'Comment creation failed: body is required');
        return true;
      }
      const comment = store.addComment(repo, number, text);
      sendJson(res, 201, {
        id: comment.id,
        body: comment.body,
        user: { login: repo.owner, id: 1000, type: 'User' },
        created_at: store.isoAt(comment.createdSeq),
        updated_at: store.isoAt(comment.createdSeq),
      });
      return true;
    }
    if (method === 'GET') {
      const comments = repo.comments.get(number) ?? [];
      sendList(req, res, url, comments, (comment) => ({
        id: comment.id,
        body: comment.body,
        user: { login: repo.owner, id: 1000, type: 'User' },
        created_at: store.isoAt(comment.createdSeq),
        updated_at: store.isoAt(comment.createdSeq),
      }));
      return true;
    }
  }

  // ---- pulls ----
  if (sub === '/pulls') {
    if (method === 'POST') {
      const head = shortRef(typeof body.head === 'string' ? body.head : '');
      const base = shortRef(typeof body.base === 'string' ? body.base : '');
      const title = typeof body.title === 'string' ? body.title : '';
      const headSha = head === '' ? undefined : refTip(repo, branchRef(head));
      const baseSha = base === '' ? undefined : refTip(repo, branchRef(base));
      if (headSha === undefined || baseSha === undefined) {
        sendError(res, 422, 'Validation Failed: head or base ref does not exist');
        return true;
      }
      if (head === base) {
        sendError(res, 422, 'Validation Failed: head and base must differ');
        return true;
      }
      for (const pull of repo.pulls.values()) {
        if (pull.state === 'open' && pull.headRef === head && pull.baseRef === base) {
          sendError(res, 422, 'Validation Failed: a pull request already exists for this branch');
          return true;
        }
      }
      const pull = store.createPull(
        repo,
        title,
        typeof body.body === 'string' ? body.body : '',
        head,
        headSha,
        base,
        baseSha,
      );
      sendJson(res, 201, pullJson(store, repo, pull));
      return true;
    }
    if (method === 'GET') {
      const state = url.searchParams.get('state') ?? 'open';
      let pulls = [...repo.pulls.values()];
      if (state === 'open') pulls = pulls.filter((p) => p.state === 'open');
      if (state === 'closed') pulls = pulls.filter((p) => p.state === 'closed');
      sendList(req, res, url, pulls, (pull) => pullJson(store, repo, pull));
      return true;
    }
  }

  const pullMatch = /^\/pulls\/(\d+)$/.exec(sub);
  if (pullMatch && method === 'GET') {
    const pull = repo.pulls.get(Number(pullMatch[1]));
    if (pull === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, pullJson(store, repo, pull));
    return true;
  }

  const filesMatch = /^\/pulls\/(\d+)\/files$/.exec(sub);
  if (filesMatch && method === 'GET') {
    const pull = repo.pulls.get(Number(filesMatch[1]));
    if (pull === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const baseCommit = getObject(repo, pull.baseSha);
    const headCommit = getObject(repo, pull.headSha);
    if (baseCommit?.type !== 'commit' || headCommit?.type !== 'commit') {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const baseFlat = flattenTree(repo, parseCommit(baseCommit.data).tree);
    const headFlat = flattenTree(repo, parseCommit(headCommit.data).tree);
    const files = diffFlat(baseFlat, headFlat).map((change) => {
      const oldLines = change.oldOid !== undefined ? lineCount(repo, change.oldOid) : 0;
      const newLines = change.newOid !== undefined ? lineCount(repo, change.newOid) : 0;
      const additions = change.status === 'added' ? newLines : Math.max(0, newLines - oldLines);
      const deletions = change.status === 'removed' ? oldLines : Math.max(0, oldLines - newLines);
      return {
        filename: change.path,
        status: change.status === 'modified' ? 'modified' : change.status,
        additions,
        deletions,
        changes: additions + deletions,
        sha: change.newOid ?? change.oldOid ?? ZERO_OID,
      };
    });
    sendList(req, res, url, files, (file) => file);
    return true;
  }

  const mergeMatch = /^\/pulls\/(\d+)\/merge$/.exec(sub);
  if (mergeMatch && method === 'PUT') {
    const pull = repo.pulls.get(Number(mergeMatch[1]));
    if (pull === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (pull.state !== 'open') {
      sendError(res, 405, 'Pull Request is not mergeable');
      return true;
    }
    const mergeSha = mergePull(store, repo, pull, body);
    if (mergeSha === undefined) {
      sendError(res, 405, 'Pull Request is not mergeable');
      return true;
    }
    sendJson(res, 200, { sha: mergeSha, merged: true, message: 'Pull Request successfully merged' });
    return true;
  }

  return false;
}

/** A branch name from a ref the caller passed, full (`refs/heads/x`) or short (`x`). */
function shortRef(ref: string): string {
  return ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref;
}

/** Lines in a blob's content (the /files counts: a trailing newline ends the last line). */
function lineCount(repo: RepoRecord, oid: string): number {
  const blob = getObject(repo, oid);
  if (blob === undefined) return 0;
  const text = blob.data.toString('utf8');
  if (text === '') return 0;
  const lines = text.split('\n');
  return text.endsWith('\n') ? lines.length - 1 : lines.length;
}

/**
 * Merge a pull request into its base branch: a path-level three-way tree merge against the
 * merge-base of the CURRENT base and head tips. Squash (the default, and what the suite
 * drives) authors one commit parented on the base tip; `merge` authors a two-parent commit.
 * Returns the merge commit id, or undefined when the trees conflict.
 */
function mergePull(
  store: Store,
  repo: RepoRecord,
  pull: PullRecord,
  body: Record<string, unknown>,
): string | undefined {
  const baseRef = branchRef(pull.baseRef);
  const headRef = branchRef(pull.headRef);
  const baseTip = refTip(repo, baseRef);
  const headTip = refTip(repo, headRef);
  if (baseTip === undefined || headTip === undefined) return undefined;
  const ancestor = mergeBase(repo, baseTip, headTip);
  if (ancestor === undefined) return undefined;
  const flatAt = (commitSha: string): Map<string, string> => {
    const commit = getObject(repo, commitSha);
    return commit?.type === 'commit' ? flattenTree(repo, parseCommit(commit.data).tree) : new Map();
  };
  const merged = mergeFlat(flatAt(ancestor), flatAt(baseTip), flatAt(headTip));
  if (merged === null) return undefined;
  const tree = buildTreeFromFlat(repo, merged);
  const method = typeof body.merge_method === 'string' ? body.merge_method : 'squash';
  const parents = method === 'merge' ? [baseTip, headTip] : [baseTip];
  const title = typeof body.commit_title === 'string' ? body.commit_title : pull.title;
  const detail = typeof body.commit_message === 'string' ? body.commit_message : pull.body;
  const message = detail === '' ? title : `${title}\n\n${detail}`;
  const seq = store.nextSeq();
  const commitSha = buildCommit(repo, {
    tree,
    parents,
    message: message.endsWith('\n') ? message : `${message}\n`,
    author: forgeIdentity(),
    timestampSec: Math.floor(Date.parse(store.isoAt(seq)) / 1000),
  });
  repo.refs.set(baseRef, commitSha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergeCommitSha = commitSha;
  pull.mergedSeq = store.nextSeq();
  return commitSha;
}

// ------------------------------------------------------------------ MCP
//
// The agent-native surface: streamable-HTTP JSON-RPC at /mcp, modern era first. A
// `server/discover` result (identity, capabilities, supportedVersions in one answer) makes
// the suite's client settle modern with no handshake and no session; `initialize` is also
// answered for the legacy era. Everything is stateless: no session id is ever issued, each
// POST is one JSON-RPC call answered by one JSON body, and the tools below read and write
// the same store as REST, so an object created here is the same object there.

/** The MCP server's identity, answered by server/discover and initialize. */
const MCP_SERVER_INFO = { name: 'makefun-forge', version: '1.0.0' };

/** The protocol revisions server/discover advertises (the suite negotiates 2026-07-28). */
const MCP_SUPPORTED_VERSIONS: readonly string[] = ['2026-07-28', '2025-11-25', '2025-06-18'];

/**
 * The tool table tools/list answers: the six tools the suite requires, by their
 * github-mcp-server names. A static value in a fixed key order — the suite compares two
 * tools/list answers byte for byte, so this array is built once and never mutated.
 * Property names are the documented ones; the suite maps its arguments onto them.
 */
const MCP_TOOLS: readonly Record<string, unknown>[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The name of the new repository.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by its owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed, or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The branch the changes come from.' },
        base: { type: 'string', description: 'The branch the changes merge into.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'number', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

/** A JSON-RPC success answer. */
function sendRpc(res: ServerResponse, id: unknown, result: unknown): void {
  sendJson(res, 200, { jsonrpc: '2.0', id: id ?? null, result });
}

/** A JSON-RPC error answer (the HTTP status is the caller's to choose). */
function sendRpcError(res: ServerResponse, status: number, id: unknown, code: number, message: string): void {
  sendJson(res, status, { jsonrpc: '2.0', id: id ?? null, error: { code, message } });
}

/** A tool's success: the object as a JSON text block plus structured content. */
function sendToolResult(res: ServerResponse, id: unknown, value: unknown): void {
  sendRpc(res, id, {
    content: [{ type: 'text', text: JSON.stringify(value) }],
    structuredContent: value,
    isError: false,
  });
}

/** A tool's own failure: the call succeeded, the tool reports isError. */
function sendToolError(res: ServerResponse, id: unknown, message: string): void {
  sendRpc(res, id, { content: [{ type: 'text', text: message }], isError: true });
}

/** A non-empty string argument, or undefined when absent or of another type. */
function mcpStringArg(args: Record<string, unknown>, key: string): string | undefined {
  const value = args[key];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/** The repository a tool call addresses, once its owner/repo arguments are present. */
function mcpRepo(store: Store, args: Record<string, unknown>): RepoRecord | undefined {
  const owner = mcpStringArg(args, 'owner');
  const repo = mcpStringArg(args, 'repo');
  if (owner === undefined || repo === undefined) return undefined;
  return store.repoFor(owner, repo);
}

/** The /mcp endpoint: one JSON-RPC request per POST, answered whole. */
async function handleMcp(store: Store, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if ((req.method ?? 'GET') !== 'POST') {
    sendRpcError(res, 405, null, -32601, 'Method not allowed: MCP answers POST only');
    return;
  }
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    // A body that is not JSON is a JSON-RPC parse error: HTTP 400, code -32700.
    sendRpcError(res, 400, null, -32700, 'Parse error');
    return;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    sendRpcError(res, 400, null, -32600, 'Invalid Request: a single JSON-RPC object is required');
    return;
  }
  const call = parsed as Record<string, unknown>;
  const id = call.id;
  const method = typeof call.method === 'string' ? call.method : '';
  const params = (
    typeof call.params === 'object' && call.params !== null ? call.params : {}
  ) as Record<string, unknown>;

  // Notifications carry no id: accept them with a bare 202 and no body.
  if (id === undefined) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }

  switch (method) {
    case 'server/discover':
      sendRpc(res, id, {
        resultType: 'complete',
        supportedVersions: MCP_SUPPORTED_VERSIONS,
        capabilities: { tools: {} },
        serverInfo: MCP_SERVER_INFO,
      });
      return;
    case 'initialize': {
      const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
      sendRpc(res, id, {
        protocolVersion: MCP_SUPPORTED_VERSIONS.includes(offered) ? offered : '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: MCP_SERVER_INFO,
      });
      return;
    }
    case 'ping':
      sendRpc(res, id, {});
      return;
    case 'tools/list':
      sendRpc(res, id, { tools: MCP_TOOLS });
      return;
    case 'tools/call':
      handleMcpToolCall(store, res, id, params);
      return;
    default:
      sendRpcError(res, 200, id, -32601, `Method not found: ${method}`);
  }
}

/** One tools/call: argument-shape failures are -32602; a tool's own failures are isError. */
function handleMcpToolCall(
  store: Store,
  res: ServerResponse,
  id: unknown,
  params: Record<string, unknown>,
): void {
  const name = typeof params.name === 'string' ? params.name : '';
  const args = (
    typeof params.arguments === 'object' && params.arguments !== null ? params.arguments : {}
  ) as Record<string, unknown>;
  const invalid = (message: string): void => {
    sendRpcError(res, 200, id, -32602, `Invalid arguments: ${message}`);
  };
  /** owner+repo presence (-32602), then the repository itself (isError when it is not there). */
  const addressedRepo = (): RepoRecord | undefined => {
    if (mcpStringArg(args, 'owner') === undefined || mcpStringArg(args, 'repo') === undefined) {
      invalid('owner and repo are required');
      return undefined;
    }
    const repo = mcpRepo(store, args);
    if (repo === undefined) sendToolError(res, id, 'Repository not found');
    return repo;
  };

  switch (name) {
    case 'create_repo': {
      const repoName = mcpStringArg(args, 'name');
      if (repoName === undefined) {
        invalid('name is required');
        return;
      }
      const repo =
        store.repos.get(repoName) ??
        store.createRepo(
          repoName,
          typeof args.description === 'string' ? args.description : '',
          args.private === true,
        );
      sendToolResult(res, id, repoJson(store, repo));
      return;
    }
    case 'get_repo': {
      const repo = addressedRepo();
      if (repo === undefined) return;
      sendToolResult(res, id, repoJson(store, repo));
      return;
    }
    case 'create_issue': {
      if (mcpStringArg(args, 'title') === undefined) {
        invalid('title is required');
        return;
      }
      const repo = addressedRepo();
      if (repo === undefined) return;
      const issue = store.createIssue(
        repo,
        args.title as string,
        typeof args.body === 'string' ? args.body : '',
      );
      sendToolResult(res, id, issueJson(store, repo, issue));
      return;
    }
    case 'list_issues': {
      const repo = addressedRepo();
      if (repo === undefined) return;
      const state = typeof args.state === 'string' ? args.state : 'open';
      let issues = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') issues = issues.filter((i) => i.state === state);
      issues.sort((a, b) => b.createdSeq - a.createdSeq);
      sendToolResult(res, id, issues.map((issue) => issueJson(store, repo, issue)));
      return;
    }
    case 'create_pull_request': {
      for (const key of ['title', 'head', 'base'] as const) {
        if (mcpStringArg(args, key) === undefined) {
          invalid(`${key} is required`);
          return;
        }
      }
      const repo = addressedRepo();
      if (repo === undefined) return;
      const head = shortRef(args.head as string);
      const base = shortRef(args.base as string);
      const headSha = refTip(repo, branchRef(head));
      const baseSha = refTip(repo, branchRef(base));
      if (headSha === undefined || baseSha === undefined) {
        sendToolError(res, id, 'Validation Failed: head or base ref does not exist');
        return;
      }
      if (head === base) {
        sendToolError(res, id, 'Validation Failed: head and base must differ');
        return;
      }
      for (const pull of repo.pulls.values()) {
        if (pull.state === 'open' && pull.headRef === head && pull.baseRef === base) {
          sendToolError(res, id, 'Validation Failed: a pull request already exists for this branch');
          return;
        }
      }
      const pull = store.createPull(
        repo,
        args.title as string,
        typeof args.body === 'string' ? args.body : '',
        head,
        headSha,
        base,
        baseSha,
      );
      sendToolResult(res, id, pullJson(store, repo, pull));
      return;
    }
    case 'merge_pull_request': {
      const rawNumber = args.pull_number;
      const number =
        typeof rawNumber === 'number'
          ? rawNumber
          : typeof rawNumber === 'string' && /^\d+$/.test(rawNumber)
            ? Number(rawNumber)
            : Number.NaN;
      if (!Number.isInteger(number)) {
        invalid('pull_number is required');
        return;
      }
      const repo = addressedRepo();
      if (repo === undefined) return;
      const pull = repo.pulls.get(number);
      if (pull === undefined) {
        sendToolError(res, id, 'Pull request not found');
        return;
      }
      if (pull.state !== 'open') {
        sendToolError(res, id, 'Pull Request is not mergeable');
        return;
      }
      const mergeSha = mergePull(store, repo, pull, {});
      if (mergeSha === undefined) {
        sendToolError(res, id, 'Pull Request is not mergeable');
        return;
      }
      sendToolResult(res, id, pullJson(store, repo, pull));
      return;
    }
    default:
      sendRpcError(res, 200, id, -32601, `Tool not found: ${name}`);
  }
}

// --------------------------------------------------------------- GraphQL
//
// The v4 surface at /api/graphql: the documents gh and github-mcp-server send, executed by
// the small parser + projector below (no library — the entry ships stdlib only). Objects are
// tagged values ({__typename, ...props}) resolved field by field against the schema tables;
// those tables are also what __type introspection answers, so the schema the suite probes is
// the schema it gets. Global ids are store.ts's opaque node ids, stable across reads, and
// mutations write the same store as REST, so a GraphQL-created issue is the REST issue.

/** The fields each type holds: validation, projection and __type all read this one table. */
const GQL_TYPE_FIELDS: Readonly<Record<string, readonly string[]>> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  User: ['id', 'login', 'name', 'url', 'avatarUrl'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission',
    'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'description',
    'isPrivate', 'createdAt', 'updatedAt', 'url',
  ],
  Issue: [
    'id', 'number', 'title', 'state', 'body', 'author', 'createdAt', 'updatedAt', 'closedAt',
    'labels', 'comments', 'repository', 'url',
  ],
  PullRequest: [
    'id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName',
    'baseRefName', 'files', 'author', 'createdAt', 'updatedAt', 'closedAt', 'url',
  ],
  IssueConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  Ref: ['name', 'prefix', 'target'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  CommentEdge: ['node', 'cursor'],
  IssueComment: ['id', 'body', 'author', 'createdAt', 'updatedAt'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'possibleTypes', 'inputFields', 'ofType'],
  __Field: ['name', 'description', 'args', 'type', 'isDeprecated', 'deprecationReason'],
  __EnumValue: ['name', 'description', 'isDeprecated', 'deprecationReason'],
  __InputValue: ['name', 'description', 'type', 'defaultValue'],
  __Schema: ['types', 'queryType', 'mutationType', 'directives'],
};

/** The enum values __type answers for the enum types the suite probes. */
const GQL_ENUM_VALUES: Readonly<Record<string, readonly string[]>> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
};

// ---- lexer ----

interface GqlToken {
  readonly kind: 'name' | 'int' | 'float' | 'string' | 'punct' | 'spread' | 'eof';
  readonly value: string;
}

/** Tokenize a GraphQL document (whitespace, commas and comments are insignificant). */
function gqlTokenize(src: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (src.startsWith('...', i)) {
      tokens.push({ kind: 'spread', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:=!$@|&'.includes(c)) {
      tokens.push({ kind: 'punct', value: c });
      i += 1;
      continue;
    }
    if (c === '"') {
      if (src.startsWith('"""', i)) {
        const end = src.indexOf('"""', i + 3);
        tokens.push({ kind: 'string', value: src.slice(i + 3, end < 0 ? src.length : end) });
        i = end < 0 ? src.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\') {
          const esc = src[j + 1] ?? '';
          if (esc === 'n') out += '\n';
          else if (esc === 't') out += '\t';
          else if (esc === 'r') out += '\r';
          else if (esc === 'b') out += '\b';
          else if (esc === 'f') out += '\f';
          else if (esc === 'u') {
            out += String.fromCharCode(parseInt(src.slice(j + 2, j + 6), 16));
            j += 4;
          } else out += esc;
          j += 2;
        } else {
          out += src[j];
          j += 1;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j += 1;
      tokens.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      let isFloat = false;
      while (j < src.length && /[0-9.eE+-]/.test(src[j] as string)) {
        if (src[j] === '.' || src[j] === 'e' || src[j] === 'E') isFloat = true;
        j += 1;
      }
      tokens.push({ kind: isFloat ? 'float' : 'int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`GraphQL syntax error: unexpected character ${JSON.stringify(c)}`);
  }
  tokens.push({ kind: 'eof', value: '' });
  return tokens;
}

// ---- parser ----

type GqlValue =
  | { readonly kind: 'variable'; readonly name: string }
  | { readonly kind: 'int' | 'float' | 'string' | 'enum'; readonly value: string }
  | { readonly kind: 'boolean'; readonly value: boolean }
  | { readonly kind: 'null' }
  | { readonly kind: 'list'; readonly items: readonly GqlValue[] }
  | { readonly kind: 'object'; readonly fields: readonly { readonly name: string; readonly value: GqlValue }[] };

interface GqlFieldNode {
  readonly name: string;
  readonly alias?: string;
  readonly args: readonly { readonly name: string; readonly value: GqlValue }[];
  readonly selections?: readonly GqlSelection[];
}

type GqlSelection =
  | { readonly kind: 'field'; readonly field: GqlFieldNode }
  | { readonly kind: 'inline'; readonly typeCondition?: string; readonly selections: readonly GqlSelection[] }
  | { readonly kind: 'spread'; readonly name: string };

interface GqlOperation {
  readonly type: 'query' | 'mutation';
  readonly name?: string;
  readonly varDefaults: ReadonlyMap<string, GqlValue>;
  readonly selections: readonly GqlSelection[];
}

interface GqlDocument {
  readonly operations: readonly GqlOperation[];
  readonly fragments: ReadonlyMap<string, { readonly typeCondition: string; readonly selections: readonly GqlSelection[] }>;
}

/** A recursive-descent parser for the document shapes the suite sends. */
class GqlParser {
  private pos = 0;
  private readonly tokens: readonly GqlToken[];

  constructor(tokens: readonly GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken {
    return this.tokens[this.pos] as GqlToken;
  }

  private next(): GqlToken {
    const token = this.tokens[this.pos] as GqlToken;
    this.pos += 1;
    return token;
  }

  private atPunct(value: string): boolean {
    const token = this.peek();
    return token.kind === 'punct' && token.value === value;
  }

  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) {
      throw new Error(`GraphQL syntax error: expected ${value}, got ${token.value}`);
    }
  }

  private expectName(): string {
    const token = this.next();
    if (token.kind !== 'name') throw new Error(`GraphQL syntax error: expected a name, got ${token.value}`);
    return token.value;
  }

  /** Skip a type reference (Name, [Type], Type! in any nesting). */
  private skipType(): void {
    if (this.atPunct('[')) {
      this.next();
      this.skipType();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    if (this.atPunct('!')) this.next();
  }

  /** Skip directives (@name, optionally with an argument list). */
  private skipDirectives(): void {
    while (this.atPunct('@')) {
      this.next();
      this.expectName();
      if (this.atPunct('(')) this.parseArguments();
    }
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token.kind === 'punct' && token.value === '$') return { kind: 'variable', name: this.expectName() };
    if (token.kind === 'int') return { kind: 'int', value: token.value };
    if (token.kind === 'float') return { kind: 'float', value: token.value };
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'punct' && token.value === '[') {
      const items: GqlValue[] = [];
      while (!this.atPunct(']')) items.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'list', items };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields: { name: string; value: GqlValue }[] = [];
      while (!this.atPunct('}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    throw new Error(`GraphQL syntax error: unexpected value ${token.value}`);
  }

  private parseArguments(): { name: string; value: GqlValue }[] {
    const args: { name: string; value: GqlValue }[] = [];
    this.expectPunct('(');
    while (!this.atPunct(')')) {
      const name = this.expectName();
      this.expectPunct(':');
      args.push({ name, value: this.parseValue() });
    }
    this.expectPunct(')');
    return args;
  }

  private parseSelectionSet(): GqlSelection[] {
    const selections: GqlSelection[] = [];
    this.expectPunct('{');
    while (!this.atPunct('}')) {
      const token = this.peek();
      if (token.kind === 'spread') {
        this.next();
        if (this.peek().kind === 'name' && this.peek().value === 'on') {
          this.next();
          const typeCondition = this.expectName();
          this.skipDirectives();
          selections.push({ kind: 'inline', typeCondition, selections: this.parseSelectionSet() });
        } else {
          const name = this.expectName();
          this.skipDirectives();
          selections.push({ kind: 'spread', name });
        }
        continue;
      }
      let name = this.expectName();
      let alias: string | undefined;
      if (this.atPunct(':')) {
        this.next();
        alias = name;
        name = this.expectName();
      }
      const args = this.atPunct('(') ? this.parseArguments() : [];
      this.skipDirectives();
      const sub = this.atPunct('{') ? this.parseSelectionSet() : undefined;
      selections.push({ kind: 'field', field: { name, alias, args, selections: sub } });
    }
    this.expectPunct('}');
    return selections;
  }

  private parseVariableDefinitions(): Map<string, GqlValue> {
    const defaults = new Map<string, GqlValue>();
    if (!this.atPunct('(')) return defaults;
    this.next();
    while (!this.atPunct(')')) {
      this.expectPunct('$');
      const name = this.expectName();
      this.expectPunct(':');
      this.skipType();
      if (this.atPunct('=')) {
        this.next();
        defaults.set(name, this.parseValue());
      }
      this.skipDirectives();
    }
    this.expectPunct(')');
    return defaults;
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, { typeCondition: string; selections: readonly GqlSelection[] }>();
    while (this.peek().kind !== 'eof') {
      if (this.atPunct('{')) {
        operations.push({ type: 'query', varDefaults: new Map(), selections: this.parseSelectionSet() });
        continue;
      }
      const keyword = this.expectName();
      if (keyword === 'query' || keyword === 'mutation') {
        const name = this.peek().kind === 'name' ? this.next().value : undefined;
        const varDefaults = this.parseVariableDefinitions();
        this.skipDirectives();
        operations.push({ type: keyword, name, varDefaults, selections: this.parseSelectionSet() });
      } else if (keyword === 'fragment') {
        const fragName = this.expectName();
        const on = this.expectName();
        if (on !== 'on') throw new Error(`GraphQL syntax error: expected "on" in fragment ${fragName}`);
        const typeCondition = this.expectName();
        this.skipDirectives();
        fragments.set(fragName, { typeCondition, selections: this.parseSelectionSet() });
      } else {
        throw new Error(`GraphQL syntax error: unsupported definition ${keyword}`);
      }
    }
    return { operations, fragments };
  }
}

// ---- tagged domain values ----

/** A value the projector walks: a GraphQL type name plus its precomputed properties. */
type GqlObj = Record<string, unknown> & { readonly __typename: string };

function gqlUser(login: string): GqlObj {
  return { __typename: 'User', id: nodeId('User', 1000), login, name: login, url: '', avatarUrl: '' };
}

function gqlIssue(store: Store, repo: RepoRecord, issue: IssueRecord): GqlObj {
  const stamp = store.isoAt(issue.createdSeq);
  return {
    __typename: 'Issue',
    id: nodeId('Issue', restId(repo, issue.number)),
    number: issue.number,
    title: issue.title,
    state: issue.state.toUpperCase(),
    body: issue.body,
    author: gqlUser(repo.owner),
    createdAt: stamp,
    updatedAt: stamp,
    closedAt: issue.state === 'closed' ? stamp : null,
    labels: [],
    comments: null,
    repository: null,
    url: '',
  };
}

/** Whether the pull request's trees still merge cleanly (the mergeable enum, honestly computed). */
function gqlMergeable(repo: RepoRecord, pull: PullRecord): string {
  const baseTip = refTip(repo, branchRef(pull.baseRef));
  const headTip = refTip(repo, branchRef(pull.headRef));
  if (baseTip === undefined || headTip === undefined) return 'UNKNOWN';
  const ancestor = mergeBase(repo, baseTip, headTip);
  if (ancestor === undefined) return 'UNKNOWN';
  const flatAt = (sha: string): Map<string, string> => {
    const commit = getObject(repo, sha);
    return commit?.type === 'commit' ? flattenTree(repo, parseCommit(commit.data).tree) : new Map();
  };
  return mergeFlat(flatAt(ancestor), flatAt(baseTip), flatAt(headTip)) === null ? 'CONFLICTING' : 'MERGEABLE';
}

function gqlPull(store: Store, repo: RepoRecord, pull: PullRecord): GqlObj {
  const stamp = store.isoAt(pull.createdSeq);
  return {
    __typename: 'PullRequest',
    id: nodeId('PullRequest', restId(repo, pull.number)),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.merged ? 'MERGED' : pull.state === 'closed' ? 'CLOSED' : 'OPEN',
    merged: pull.merged,
    mergeable: gqlMergeable(repo, pull),
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    author: gqlUser(repo.owner),
    createdAt: stamp,
    updatedAt: stamp,
    closedAt: pull.state === 'closed' ? store.isoAt(pull.mergedSeq || pull.createdSeq) : null,
    url: '',
    rec: { repo, pull },
  };
}

function gqlRepository(store: Store, repo: RepoRecord): GqlObj {
  const stamp = store.isoAt(repo.createdSeq);
  const defaultSha = refTip(repo, branchRef(repo.defaultBranch));
  return {
    __typename: 'Repository',
    id: nodeId('Repository', repo.id),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    owner: gqlUser(repo.owner),
    defaultBranchRef:
      defaultSha === undefined
        ? null
        : ({ __typename: 'Ref', name: repo.defaultBranch, prefix: 'refs/heads/', target: null } as GqlObj),
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    description: repo.description,
    isPrivate: repo.isPrivate,
    createdAt: stamp,
    updatedAt: stamp,
    url: '',
    rec: { repo },
  };
}

/** A pageInfo object for a sliced connection. */
function gqlPageInfo(hasNextPage: boolean, endCursor: string | null): GqlObj {
  return {
    __typename: 'PageInfo',
    hasNextPage,
    hasPreviousPage: false,
    startCursor: null,
    endCursor,
  } as GqlObj;
}

/** A connection cursor: the base64 of the item's index in the filtered, ordered list. */
function gqlCursor(index: number): string {
  return Buffer.from(`cursor:${index}`, 'utf8').toString('base64');
}

function gqlCursorIndex(raw: unknown): number | null {
  if (typeof raw !== 'string' || raw === '') return null;
  try {
    const text = Buffer.from(raw, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match ? Number(match[1]) : null;
  } catch {
    return null;
  }
}

/** Slice one page out of a full list by the first/after arguments. */
function gqlPage<T>(items: readonly T[], args: Record<string, unknown>): { slice: readonly T[]; pageInfo: GqlObj } {
  const afterIndex = gqlCursorIndex(args.after);
  const start = afterIndex === null ? 0 : afterIndex + 1;
  const first = typeof args.first === 'number' && args.first >= 0 ? Math.trunc(args.first) : items.length;
  const slice = items.slice(start, start + first);
  const hasNextPage = start + slice.length < items.length;
  const endCursor = slice.length === 0 ? null : gqlCursor(start + slice.length - 1);
  return { slice, pageInfo: gqlPageInfo(hasNextPage, endCursor) };
}

/** The repository's issues as a connection: states filter, orderBy, then cursor paging. */
function gqlIssueConnection(store: Store, repo: RepoRecord, args: Record<string, unknown>): GqlObj {
  let issues = [...repo.issues.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toLowerCase()));
    issues = issues.filter((issue) => wanted.has(issue.state));
  }
  const orderBy = (typeof args.orderBy === 'object' && args.orderBy !== null ? args.orderBy : {}) as Record<string, unknown>;
  const direction = orderBy.direction === 'ASC' ? 1 : -1;
  const field = typeof orderBy.field === 'string' ? orderBy.field : 'CREATED_AT';
  issues.sort((a, b) => {
    const key =
      field === 'COMMENTS'
        ? (repo.comments.get(a.number) ?? []).length - (repo.comments.get(b.number) ?? []).length
        : a.createdSeq - b.createdSeq;
    return key * direction;
  });
  const { slice, pageInfo } = gqlPage(issues, args);
  return {
    __typename: 'IssueConnection',
    nodes: slice.map((issue) => gqlIssue(store, repo, issue)),
    pageInfo,
    totalCount: issues.length,
  } as GqlObj;
}

/** The repository's pull requests as a connection (open by default, as gh lists them). */
function gqlPullConnection(store: Store, repo: RepoRecord, args: Record<string, unknown>): GqlObj {
  let pulls = [...repo.pulls.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toLowerCase()));
    pulls = pulls.filter((pull) =>
      wanted.has(pull.merged ? 'merged' : pull.state),
    );
  } else {
    pulls = pulls.filter((pull) => pull.state === 'open');
  }
  pulls.sort((a, b) => b.createdSeq - a.createdSeq);
  const { slice, pageInfo } = gqlPage(pulls, args);
  return {
    __typename: 'PullRequestConnection',
    nodes: slice.map((pull) => gqlPull(store, repo, pull)),
    pageInfo,
    totalCount: pulls.length,
  } as GqlObj;
}

/** The changed files of a pull request as a connection (the same diff REST /files reads). */
function gqlFilesConnection(repo: RepoRecord, pull: PullRecord, args: Record<string, unknown>): GqlObj {
  const baseCommit = getObject(repo, pull.baseSha);
  const headCommit = getObject(repo, pull.headSha);
  let nodes: GqlObj[] = [];
  if (baseCommit?.type === 'commit' && headCommit?.type === 'commit') {
    const baseFlat = flattenTree(repo, parseCommit(baseCommit.data).tree);
    const headFlat = flattenTree(repo, parseCommit(headCommit.data).tree);
    nodes = diffFlat(baseFlat, headFlat).map(
      (change) =>
        ({
          __typename: 'PullRequestChangedFile',
          path: change.path,
          additions: 0,
          deletions: 0,
          changeType: change.status.toUpperCase(),
        }) as GqlObj,
    );
  }
  const { slice, pageInfo } = gqlPage(nodes, args);
  return {
    __typename: 'PullRequestChangedFileConnection',
    nodes: slice,
    pageInfo,
    totalCount: nodes.length,
  } as GqlObj;
}

/** Decode one of our global ids back to its repository + number, or null. */
function gqlRepoAndNumber(store: Store, type: 'Issue' | 'PullRequest', raw: string): { repo: RepoRecord; number: number } | null {
  const rest = idFromNodeId(type, raw);
  if (rest === undefined) return null;
  const repoId = Math.floor(rest / 100_000);
  const repo = [...store.repos.values()].find((entry) => entry.id === repoId);
  if (repo === undefined) return null;
  return { repo, number: rest % 100_000 };
}

/** Query.node(id:): a repository, issue or pull request by its global id. */
function gqlNode(store: Store, raw: unknown): GqlObj | null {
  if (typeof raw !== 'string') return null;
  const repoId = idFromNodeId('Repository', raw);
  if (repoId !== undefined) {
    const repo = [...store.repos.values()].find((entry) => entry.id === repoId);
    return repo === undefined ? null : gqlRepository(store, repo);
  }
  const asIssue = gqlRepoAndNumber(store, 'Issue', raw);
  if (asIssue !== null) {
    const issue = asIssue.repo.issues.get(asIssue.number);
    return issue === undefined ? null : gqlIssue(store, asIssue.repo, issue);
  }
  const asPull = gqlRepoAndNumber(store, 'PullRequest', raw);
  if (asPull !== null) {
    const pull = asPull.repo.pulls.get(asPull.number);
    return pull === undefined ? null : gqlPull(store, asPull.repo, pull);
  }
  return null;
}

/** __type(name:): the schema tables as an introspection object. */
function gqlType(name: unknown): GqlObj | null {
  if (typeof name !== 'string') return null;
  const fields = GQL_TYPE_FIELDS[name];
  if (fields !== undefined) {
    return { __typename: '__Type', name, kind: 'OBJECT', gqlFields: fields, gqlEnumValues: undefined } as GqlObj;
  }
  const enumValues = GQL_ENUM_VALUES[name];
  if (enumValues !== undefined) {
    return { __typename: '__Type', name, kind: 'ENUM', gqlFields: undefined, gqlEnumValues: enumValues } as GqlObj;
  }
  return null;
}

// ---- field resolution ----

interface GqlCtx {
  readonly store: Store;
  readonly vars: Record<string, unknown>;
  readonly fragments: GqlDocument['fragments'];
  readonly errors: { message: string }[];
}

/** An argument value AST resolved against the operation's variables. */
function gqlResolveValue(value: GqlValue, vars: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'variable':
      return vars[value.name];
    case 'int':
      return parseInt(value.value, 10);
    case 'float':
      return parseFloat(value.value);
    case 'string':
    case 'enum':
      return value.value;
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'list':
      return value.items.map((item) => gqlResolveValue(item, vars));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = gqlResolveValue(field.value, vars);
      return out;
    }
  }
}

/** A mutation input object, or an empty one when the argument is not an object. */
function gqlInput(args: Record<string, unknown>): Record<string, unknown> {
  const input = args.input;
  return typeof input === 'object' && input !== null ? (input as Record<string, unknown>) : {};
}

/** A repository addressed by a mutation's repositoryId, or a thrown field error. */
function gqlRepoById(store: Store, raw: unknown): RepoRecord {
  const id = typeof raw === 'string' ? idFromNodeId('Repository', raw) : undefined;
  const repo = id === undefined ? undefined : [...store.repos.values()].find((entry) => entry.id === id);
  if (repo === undefined) throw new Error(`Could not resolve repository id ${JSON.stringify(raw)}`);
  return repo;
}

/** Resolve one field on one tagged object (arguments already resolved to JS values). */
function gqlResolveField(ctx: GqlCtx, obj: GqlObj, field: string, args: Record<string, unknown>): unknown {
  const store = ctx.store;
  switch (obj.__typename) {
    case 'Query': {
      if (field === 'viewer') return gqlUser(OWNER_LOGIN);
      if (field === 'repository') {
        const repo = store.repoFor(String(args.owner ?? ''), String(args.name ?? ''));
        return repo === undefined ? null : gqlRepository(store, repo);
      }
      if (field === 'node') return gqlNode(store, args.id);
      if (field === '__type') return gqlType(args.name);
      return null;
    }
    case 'Mutation': {
      if (field === 'createIssue') {
        const input = gqlInput(args);
        const repo = gqlRepoById(store, input.repositoryId);
        const issue = store.createIssue(
          repo,
          typeof input.title === 'string' ? input.title : '',
          typeof input.body === 'string' ? input.body : '',
        );
        return { __typename: 'CreateIssuePayload', issue: gqlIssue(store, repo, issue), clientMutationId: null } as GqlObj;
      }
      if (field === 'closeIssue') {
        const input = gqlInput(args);
        const found = typeof input.issueId === 'string' ? gqlRepoAndNumber(store, 'Issue', input.issueId) : null;
        if (found === null) throw new Error(`Could not resolve issue id ${JSON.stringify(input.issueId)}`);
        const issue = found.repo.issues.get(found.number);
        if (issue === undefined) throw new Error(`Could not find issue #${found.number}`);
        issue.state = 'closed';
        return { __typename: 'CloseIssuePayload', issue: gqlIssue(store, found.repo, issue), clientMutationId: null } as GqlObj;
      }
      if (field === 'createPullRequest') {
        const input = gqlInput(args);
        const repo = gqlRepoById(store, input.repositoryId);
        const head = shortRef(typeof input.headRefName === 'string' ? input.headRefName : '');
        const base = shortRef(typeof input.baseRefName === 'string' ? input.baseRefName : '');
        const headSha = head === '' ? undefined : refTip(repo, branchRef(head));
        const baseSha = base === '' ? undefined : refTip(repo, branchRef(base));
        if (headSha === undefined || baseSha === undefined) {
          throw new Error('Validation Failed: head or base ref does not exist');
        }
        if (head === base) throw new Error('Validation Failed: head and base must differ');
        for (const pull of repo.pulls.values()) {
          if (pull.state === 'open' && pull.headRef === head && pull.baseRef === base) {
            throw new Error('Validation Failed: a pull request already exists for this branch');
          }
        }
        const pull = store.createPull(
          repo,
          typeof input.title === 'string' ? input.title : '',
          typeof input.body === 'string' ? input.body : '',
          head,
          headSha,
          base,
          baseSha,
        );
        return { __typename: 'CreatePullRequestPayload', pullRequest: gqlPull(store, repo, pull), clientMutationId: null } as GqlObj;
      }
      if (field === 'mergePullRequest') {
        const input = gqlInput(args);
        const found = typeof input.pullRequestId === 'string' ? gqlRepoAndNumber(store, 'PullRequest', input.pullRequestId) : null;
        if (found === null) throw new Error(`Could not resolve pull request id ${JSON.stringify(input.pullRequestId)}`);
        const pull = found.repo.pulls.get(found.number);
        if (pull === undefined) throw new Error(`Could not find pull request #${found.number}`);
        if (pull.state !== 'open') throw new Error('Pull Request is not mergeable');
        const mergeSha = mergePull(store, found.repo, pull, {
          merge_method: input.mergeMethod === 'MERGE' ? 'merge' : 'squash',
        });
        if (mergeSha === undefined) throw new Error('Pull Request is not mergeable');
        return { __typename: 'MergePullRequestPayload', pullRequest: gqlPull(store, found.repo, pull), clientMutationId: null } as GqlObj;
      }
      if (field === 'addComment') {
        const input = gqlInput(args);
        const subjectId = typeof input.subjectId === 'string' ? input.subjectId : '';
        const found = gqlRepoAndNumber(store, 'Issue', subjectId) ?? gqlRepoAndNumber(store, 'PullRequest', subjectId);
        if (found === null) throw new Error(`Could not resolve subject id ${JSON.stringify(input.subjectId)}`);
        if (found.repo.issues.get(found.number) === undefined && found.repo.pulls.get(found.number) === undefined) {
          throw new Error(`Could not find subject #${found.number}`);
        }
        const comment = store.addComment(
          found.repo,
          found.number,
          typeof input.body === 'string' ? input.body : '',
        );
        const stamp = store.isoAt(comment.createdSeq);
        return {
          __typename: 'AddCommentPayload',
          commentEdge: {
            __typename: 'CommentEdge',
            node: {
              __typename: 'IssueComment',
              id: nodeId('IssueComment', comment.id),
              body: comment.body,
              author: gqlUser(found.repo.owner),
              createdAt: stamp,
              updatedAt: stamp,
            } as GqlObj,
            cursor: null,
          } as GqlObj,
          clientMutationId: null,
        } as GqlObj;
      }
      return null;
    }
    case 'Repository': {
      const { repo } = obj.rec as { repo: RepoRecord };
      if (field === 'issue') {
        const issue = repo.issues.get(Number(args.number));
        return issue === undefined ? null : gqlIssue(store, repo, issue);
      }
      if (field === 'issues') return gqlIssueConnection(store, repo, args);
      if (field === 'pullRequest') {
        const pull = repo.pulls.get(Number(args.number));
        return pull === undefined ? null : gqlPull(store, repo, pull);
      }
      if (field === 'pullRequests') return gqlPullConnection(store, repo, args);
      return obj[field] ?? null;
    }
    case 'PullRequest': {
      if (field === 'files') {
        const { repo, pull } = obj.rec as { repo: RepoRecord; pull: PullRecord };
        return gqlFilesConnection(repo, pull, args);
      }
      return obj[field] ?? null;
    }
    case '__Type': {
      if (field === 'fields') {
        const names = (obj.gqlFields as readonly string[] | undefined) ?? [];
        return names.map((name) => ({ __typename: '__Field', name, description: null, isDeprecated: false, deprecationReason: null, args: [], type: null }) as GqlObj);
      }
      if (field === 'enumValues') {
        const names = (obj.gqlEnumValues as readonly string[] | undefined) ?? [];
        return names.map((name) => ({ __typename: '__EnumValue', name, description: null, isDeprecated: false, deprecationReason: null }) as GqlObj);
      }
      return obj[field] ?? null;
    }
    default:
      return obj[field] ?? null;
  }
}

// ---- projection ----

/** Flatten a selection set for one concrete type (fragments applied, spreads resolved). */
function gqlExpand(
  ctx: GqlCtx,
  selections: readonly GqlSelection[],
  typename: string,
  out: GqlFieldNode[],
): void {
  for (const selection of selections) {
    if (selection.kind === 'field') {
      out.push(selection.field);
    } else if (selection.kind === 'inline') {
      if (selection.typeCondition === undefined || selection.typeCondition === typename) {
        gqlExpand(ctx, selection.selections, typename, out);
      }
    } else {
      const fragment = ctx.fragments.get(selection.name);
      if (fragment !== undefined && fragment.typeCondition === typename) {
        gqlExpand(ctx, fragment.selections, typename, out);
      }
    }
  }
}

/** Shape a resolved value by the field's selection set. */
function gqlShape(ctx: GqlCtx, raw: unknown, selections: readonly GqlSelection[] | undefined): unknown {
  if (raw === null || raw === undefined) return null;
  if (Array.isArray(raw)) return raw.map((entry) => gqlShape(ctx, entry, selections));
  if (typeof raw === 'object' && '__typename' in raw) {
    if (selections === undefined) return null;
    return gqlProject(ctx, raw as GqlObj, selections);
  }
  return raw;
}

/** Project one tagged object: each selected field validated, resolved and shaped. */
function gqlProject(ctx: GqlCtx, obj: GqlObj, selections: readonly GqlSelection[]): Record<string, unknown> {
  const typename = obj.__typename;
  const fields: GqlFieldNode[] = [];
  gqlExpand(ctx, selections, typename, fields);
  const out: Record<string, unknown> = {};
  for (const fieldNode of fields) {
    const key = fieldNode.alias ?? fieldNode.name;
    if (fieldNode.name === '__typename') {
      out[key] = typename;
      continue;
    }
    const known = (GQL_TYPE_FIELDS[typename] ?? []).includes(fieldNode.name);
    if (!known) {
      ctx.errors.push({ message: `Field '${fieldNode.name}' doesn't exist on type '${typename}'` });
      out[key] = null;
      continue;
    }
    const args: Record<string, unknown> = {};
    for (const arg of fieldNode.args) args[arg.name] = gqlResolveValue(arg.value, ctx.vars);
    let raw: unknown;
    try {
      raw = gqlResolveField(ctx, obj, fieldNode.name, args);
    } catch (err) {
      ctx.errors.push({ message: err instanceof Error ? err.message : String(err) });
      raw = null;
    }
    out[key] = gqlShape(ctx, raw, fieldNode.selections);
  }
  return out;
}

// ---- the endpoint ----

interface GqlEnvelope {
  data?: unknown;
  errors?: { message: string }[];
}

/** Execute one operation document against the store. */
function executeGraphql(
  store: Store,
  query: string,
  variables: Record<string, unknown>,
  operationName?: string,
): GqlEnvelope {
  let document: GqlDocument;
  try {
    document = new GqlParser(gqlTokenize(query)).parseDocument();
  } catch (err) {
    return { errors: [{ message: err instanceof Error ? err.message : String(err) }] };
  }
  const operation =
    operationName === undefined
      ? document.operations[0]
      : document.operations.find((entry) => entry.name === operationName) ?? document.operations[0];
  if (operation === undefined) return { errors: [{ message: 'No operation in the document' }] };
  const vars: Record<string, unknown> = {};
  const resolveCtx: GqlCtx = { store, vars, fragments: document.fragments, errors: [] };
  for (const [name, fallback] of operation.varDefaults) vars[name] = gqlResolveValue(fallback, {});
  for (const [name, value] of Object.entries(variables)) vars[name] = value;
  const root: GqlObj = { __typename: operation.type === 'mutation' ? 'Mutation' : 'Query' };
  const data = gqlProject(resolveCtx, root, operation.selections);
  return resolveCtx.errors.length > 0 ? { data, errors: resolveCtx.errors } : { data };
}

/** The /api/graphql endpoint: one operation object, or an array of them (operation batching). */
async function handleGraphql(store: Store, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if ((req.method ?? 'GET') !== 'POST') {
    sendJson(res, 405, { errors: [{ message: 'Method not allowed: GraphQL answers POST only' }] });
    return;
  }
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
    return;
  }
  const runOne = (entry: unknown): GqlEnvelope => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      return { errors: [{ message: 'Each operation must be a JSON object' }] };
    }
    const operation = entry as Record<string, unknown>;
    if (typeof operation.query !== 'string') return { errors: [{ message: 'Each operation needs a query string' }] };
    const variables = (
      typeof operation.variables === 'object' && operation.variables !== null ? operation.variables : {}
    ) as Record<string, unknown>;
    return executeGraphql(
      store,
      operation.query,
      variables,
      typeof operation.operationName === 'string' ? operation.operationName : undefined,
    );
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(parsed));
}
