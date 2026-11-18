# Forge — a GitHub core clone for make.fun

[![make.fun bounty](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Badutitem/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Badutitem/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01)

An entry for the [github-core-clone-01](https://make.fun/bounty/github-core-clone-01) bounty on
[make.fun](https://make.fun/bounty/github-core-clone-01): a dependency-free reimplementation of
GitHub's core surface — git smart HTTP, the REST v3 API, GraphQL v4 and an MCP endpoint — in a
single Node process with an in-memory store. No packages, no `git` binary, no network at run time:
the packfile format, the pkt-line protocol and the GraphQL executor are all implemented here.

## Run it

```sh
node --experimental-strip-types main.ts
```

The platform runs `node /bot/main.ts` on Node 22.18 or later, which strips TypeScript types on its
own; the flag is harmless there and makes an older local Node work too. `main.ts` binds an ephemeral
port, registers it with the harness at `MAKEFUN_ENV_URL`, polls its `/done` endpoint and exits 0
when the suite has finished.

For local development, `node dev-serve.ts` serves the same app on a fixed port without the
harness lifecycle.

## The surface

| Route | What it is |
| --- | --- |
| `GET /healthz` | 200 `{"ok":true}`: the harness boot probe |
| `/api/v3/...` | GitHub REST v3: repositories, branches, commits, contents (read/write, base64), git trees/blobs/refs, issues, comments, labels, pull requests (files, reviews, merges) |
| `POST /api/graphql` | GitHub GraphQL v4: repository/issue/pullRequest queries, connections with cursor pagination, mutations, node ids, introspection |
| `POST /mcp` | Model Context Protocol over streamable HTTP (protocol 2026-07-28): server/discover, initialize, ping, tools/list, tools/call |
| `/<owner>/<repo>.git/...` | git smart HTTP: `info/refs`, `git-upload-pack` and `git-receive-pack`, protocol v0 and v2, shallow fetch, report-status |
| anything else | 404 `{"message":"Not Found"}` |

Every API call carries `Authorization: Bearer` with the harness token; a missing or wrong token is
refused with 401. State is deterministic: forge-authored timestamps come from a fixed base plus a
monotonic counter, and git objects the suite pushes round-trip byte-exactly. Fetch, advertisement
and ls-refs responses are cached per repository — store objects are append-only and
content-addressed, so a response is fully determined by its request inputs.

## Layout

- `main.ts`: the harness lifecycle (bind, register, wait for done, exit 0).
- `app.ts`: the HTTP server — REST v3, GraphQL v4 and the MCP endpoint over one store.
- `store.ts`: the in-memory data model (repos, issues, pulls, comments, labels, object store).
- `git.ts`: the git object model — packfiles (read with delta resolution, write), pkt-lines,
  reachability and shallow planning.
- `gitserver.ts`: git smart HTTP — ref advertisement, ls-refs, upload-pack, receive-pack.
- `dev-serve.ts`: a fixed-port development server (not used by the harness).

## License

MIT — see `LICENSE`.
