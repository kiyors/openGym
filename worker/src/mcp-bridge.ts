// The remote MCP server, run from upstream's own code (mcp/src): the same 15 tools, schemas,
// instructions and answers as the self-hosted `mcp` container (mcp/src/http.js). Like that
// container it holds no data: every read and write goes through the API's /api/token/* routes
// with the caller's scoped token, which hand it only its categories and stamp its writes
// (api/tokens.js, api/sync-stamps.js). The difference is the hop: here those requests never leave
// the Worker, they are handed straight to its own router (`selfFetch`).
//
// Imported lazily from routes/mcp.ts, so only /mcp requests pay for evaluating the exercise
// library the tools search.
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

/** One MCP request, answered statelessly with JSON (no session, no SSE stream), as http.js does. */
export async function handleMcp(
  req: Request,
  { base, token, selfFetch }: { base: string; token: string; selfFetch: SelfFetch }
): Promise<Response> {
  // `fetchImpl` in the config reaches every tool: remote.js reads through it, and the write tools
  // take the same config back from the request's profile (mcp/src/api-client.js apiConfig).
  const cfg = { base, token, fetchImpl: selfFetch };
  const remote = createRemoteProfile(cfg, { fetchImpl: selfFetch }) as RemoteProfile;
  const me = await remote.me({ fresh: true });
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
}
