// The remote MCP server, run from upstream's own code (mcp/src): the same 15 tools, schemas,
// instructions and answers as the self-hosted `mcp` container (mcp/src/http.js). Like that
// container it holds no data: every read and write goes through the API's /api/token/* routes
// with the caller's scoped token, which hand it only its categories and stamp its writes
// (api/tokens.js, api/sync-stamps.js). The difference is the hop: here those requests never leave
// the Worker, they are handed straight to its own router (`selfFetch`).
//
// Imported statically, so its modules (the MCP SDK, zod, the tool definitions, the exercise library)
// are evaluated when Cloudflare starts the Worker, under the separate startup limit, instead of
// inside the first /mcp request a fresh instance serves, which used to cost that request 100 ms
// and more of CPU time.
// @ts-ignore node:async_hooks comes from nodejs_compat; the Worker has no Node type declarations
import { AsyncLocalStorage as NodeAls } from 'node:async_hooks';
const AsyncLocalStorage = NodeAls as new <T>() => { run<R>(store: T, fn: () => R): R; getStore(): T | undefined };
// @ts-ignore upstream JS without type declarations
import { buildServer } from '../../mcp/src/server.js';
// @ts-ignore upstream JS without type declarations
import { createRemoteProfile } from '../../mcp/src/remote.js';
// @ts-ignore upstream JS without type declarations
import { withProfile } from '../../mcp/src/state.js';
// The same file the SDK's exports map gives mcp/src/server.js, so the bundle holds one copy of the
// SDK (installed by `cd mcp && npm ci`).
// @ts-ignore upstream JS without type declarations
import { WebStandardStreamableHTTPServerTransport } from '../../mcp/node_modules/@modelcontextprotocol/sdk/dist/esm/server/webStandardStreamableHttp.js';

export type SelfFetch = (url: string, init?: RequestInit) => Promise<Response>;

interface RemoteProfile {
  me(opts?: { fresh?: boolean }): Promise<{ user: { id: string; name: string }; scopes: Record<string, string> | null }>;
  refresh(): Promise<void>;
  snapshot(): unknown;
}

// One cached profile per token, as mcp/src/http.js keeps one: a conversation of tool calls reads
// the document once, then only its revision, and reads it again only when it moved. Dropped after
// ten idle minutes. Keyed by a hash of the token, never the token. The cache lives as long as
// this Worker instance does; a fresh instance simply starts empty.
const IDLE_MS = 10 * 60_000;
const MAX_CACHED = 500;
const cache = new Map<string, { remote: RemoteProfile; at: number }>();

// A cached profile outlives the request that made it, so the in-process fetch it calls must be the
// current request's (its Cloudflare context), never the first one's: looked up per call.
const currentFetch = new AsyncLocalStorage<SelfFetch>();
const viaCurrentRequest: SelfFetch = (url, init) => {
  const f = currentFetch.getStore();
  if (!f) throw Object.assign(new Error('no request in progress'), { code: 'EAPI' });
  return f(url, init);
};

async function keyOf(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function profileFor(base: string, token: string): Promise<{ key: string; remote: RemoteProfile }> {
  const key = await keyOf(token);
  const now = Date.now();
  for (const [k, v] of cache) if (now - v.at > IDLE_MS) cache.delete(k);
  let hit = cache.get(key);
  if (!hit) {
    if (cache.size >= MAX_CACHED) cache.delete(cache.keys().next().value as string);
    // `fetchImpl` in the config reaches every tool: remote.js reads through it, and the write
    // tools take the same config back from the request's profile (mcp/src/api-client.js).
    const cfg = { base, token, fetchImpl: viaCurrentRequest };
    hit = { remote: createRemoteProfile(cfg, { fetchImpl: viaCurrentRequest }) as RemoteProfile, at: now };
    cache.set(key, hit);
  }
  hit.at = now;
  return { key, remote: hit.remote };
}

/** One MCP request, answered statelessly with JSON (no session, no SSE stream), as http.js does. */
export function handleMcp(
  req: Request,
  { base, token, selfFetch }: { base: string; token: string; selfFetch: SelfFetch }
): Promise<Response> {
  return currentFetch.run(selfFetch, async () => {
    const { key, remote } = await profileFor(base, token);
    let me;
    try {
      // Asked on every request, as http.js does: a revoked token is turned away at once.
      me = await remote.me({ fresh: true });
    } catch (e) {
      cache.delete(key);
      throw e;
    }
    const server = (buildServer as (opts: unknown) => any)({
      scopes: me.scopes || {},
      around: async (fn: () => unknown) => {
        await remote.refresh();
        return withProfile(remote.snapshot(), fn);
      },
    });
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    await server.connect(transport);
    try {
      return await transport.handleRequest(req);
    } finally {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    }
  });
}
