import { Hono } from 'hono';
import { Env, resolveOrigin } from '../env';
import { randomHex } from '../crypto';
import {
  DEFAULT_OAUTH_SCOPE,
  TokenCategoryId,
  TokenLevel,
  TokenScopes,
  allows,
} from '../scopes';
import { AuthenticatedApiToken, authenticateApiToken } from './tokens';
import { commitUserState, readUserState } from './data';

export const mcpRoutes = new Hono<{ Bindings: Env }>();

const MCP_VERSION = '0.2.0';
const PROTOCOL_VERSION = '2025-03-26';

const MCP_INSTRUCTIONS = [
  "openGym is the user's own gym tracker: their routines, weekly plan, logged workouts and body weight.",
  'Read before you advise: list_routines and get_week_plan for the plan, list_workouts and estimate_1rm for how training went, muscle_balance for what is under- or over-trained.',
  'To build or change a plan, call create_routine or update_routine with dry_run: true, show the user the preview and save only after they agree.',
  'To log a session the user describes, use log_workout (dry_run first if you had to guess anything).',
  "Weights are in the profile's unit (kg or lb) unless you say otherwise. Deleting needs the user's explicit yes.",
].join(' ');

type NeedRule = [TokenCategoryId, TokenLevel] | Array<[TokenCategoryId, TokenLevel]>;

interface McpToolDef {
  name: string;
  description: string;
  need: NeedRule;
  inputSchema: Record<string, unknown>;
  annotations: Record<string, boolean>;
}

const TOOL_DEFS: McpToolDef[] = [
  {
    name: 'list_routines',
    description: 'List all workout routines in the user profile.',
    need: ['plans', 'view'],
    inputSchema: { type: 'object', properties: {} },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'get_routine',
    description: 'Get full details and exercises for a specific routine by id or name.',
    need: ['plans', 'view'],
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Routine ID' },
        name: { type: 'string', description: 'Routine name (case-insensitive match)' },
      },
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'get_week_plan',
    description: 'Get the weekly schedule, day plan, queue, and rotation settings.',
    need: ['plans', 'view'],
    inputSchema: { type: 'object', properties: {} },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'get_programme',
    description: 'Get the active multi-week training programme if configured.',
    need: ['plans', 'view'],
    inputSchema: { type: 'object', properties: {} },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'list_workouts',
    description: 'List recent logged workouts (newest first) with optional limit and date filter.',
    need: ['workouts', 'view'],
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Max workouts to return (default 20, max 100)' },
        since: { type: 'string', description: 'Filter workouts on or after YYYY-MM-DD' },
      },
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'get_workout',
    description: 'Get full set-by-set details for a logged workout by id or date (YYYY-MM-DD).',
    need: ['workouts', 'view'],
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Workout ID' },
        date: { type: 'string', description: 'Workout date YYYY-MM-DD' },
      },
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'estimate_1rm',
    description: 'Estimate Epley 1RM progression for an exercise across logged workouts.',
    need: ['workouts', 'view'],
    inputSchema: {
      type: 'object',
      properties: {
        exercise: { type: 'string', description: 'Exercise ID or partial name' },
      },
      required: ['exercise'],
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'muscle_balance',
    description: 'Summarize completed set volume by exercise over the last N days (default 28).',
    need: ['workouts', 'view'],
    inputSchema: {
      type: 'object',
      properties: {
        days: { type: 'number', description: 'Lookback window in days (default 28)' },
      },
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'get_bodyweight',
    description: 'Get logged bodyweight entries and target weight.',
    need: ['bodyweight', 'view'],
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Max recent entries (default 30)' },
      },
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'search_exercises',
    description: 'Search exercises used in routines, workouts, and custom exercises.',
    need: [
      ['workouts', 'view'],
      ['plans', 'view'],
    ],
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search text' },
      },
      required: ['query'],
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: 'log_workout',
    description: 'Log a completed workout session to the user profile (supports dry_run preview).',
    need: ['workouts', 'apply'],
    inputSchema: {
      type: 'object',
      properties: {
        date: { type: 'string', description: 'YYYY-MM-DD (defaults to today UTC)' },
        name: { type: 'string', description: 'Workout name' },
        durationMin: { type: 'number', description: 'Duration in minutes' },
        notes: { type: 'string', description: 'Session notes' },
        exercises: {
          type: 'array',
          description: 'List of exercises performed',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              name: { type: 'string' },
              sets: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    w: { type: 'number', description: 'Weight' },
                    r: { type: 'number', description: 'Reps' },
                    done: { type: 'boolean' },
                  },
                },
              },
            },
          },
        },
        dry_run: { type: 'boolean', description: 'If true, preview without saving' },
      },
      required: ['name', 'exercises'],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'create_routine',
    description: 'Create a new workout routine in the user profile (supports dry_run preview).',
    need: ['plans', 'apply'],
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Routine name' },
        emoji: { type: 'string', description: 'Optional emoji icon' },
        exercises: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              name: { type: 'string' },
              sets: { type: 'number' },
              reps: { type: 'string' },
            },
          },
        },
        dry_run: { type: 'boolean', description: 'If true, preview without saving' },
      },
      required: ['name', 'exercises'],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: 'update_routine',
    description: 'Update an existing routine by id (supports dry_run preview).',
    need: ['plans', 'apply'],
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Routine ID to update' },
        name: { type: 'string' },
        emoji: { type: 'string' },
        exercises: { type: 'array', items: { type: 'object' } },
        dry_run: { type: 'boolean' },
      },
      required: ['id'],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: 'delete_routine',
    description: 'Delete a routine by id (requires confirm: true; otherwise returns a dry-run preview).',
    need: ['plans', 'apply'],
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Routine ID to delete' },
        confirm: { type: 'boolean', description: 'Must be true to actually delete' },
      },
      required: ['id'],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  },
];

function toolAllowed(def: McpToolDef, scopes: TokenScopes): boolean {
  const alts = Array.isArray(def.need[0])
    ? (def.need as Array<[TokenCategoryId, TokenLevel]>)
    : [def.need as [TokenCategoryId, TokenLevel]];
  return alts.some(([cat, lv]) => allows(scopes, cat, lv));
}

async function runTool(
  env: Env,
  ctx: ExecutionContext,
  auth: AuthenticatedApiToken,
  name: string,
  args: Record<string, unknown>
): Promise<unknown> {
  const def = TOOL_DEFS.find((t) => t.name === name);
  if (!def) throw new Error(`Unknown tool: ${name}`);
  if (!toolAllowed(def, auth.scopes)) {
    throw new Error(`Scope denied: this API token is not allowed to run ${name}`);
  }

  const cur = await readUserState(env, auth.user.uid);
  const st = (cur.state || {}) as Record<string, unknown>;
  const unit = (st.unit as string) || 'kg';
  const routines = Array.isArray(st.routines) ? (st.routines as Array<Record<string, unknown>>) : [];
  const workouts = Array.isArray(st.workouts) ? (st.workouts as Array<Record<string, unknown>>) : [];
  const bodyweight = Array.isArray(st.bodyweight) ? (st.bodyweight as Array<Record<string, unknown>>) : [];
  const customEx = Array.isArray(st.customEx) ? (st.customEx as Array<Record<string, unknown>>) : [];

  switch (name) {
    case 'list_routines':
      return {
        unit,
        count: routines.length,
        routines: routines.map((r) => ({
          id: r.id,
          name: r.name,
          emoji: r.emoji || null,
          exercises: Array.isArray(r.ex) ? r.ex.length : 0,
        })),
      };

    case 'get_routine': {
      const id = String(args.id || '');
      const qName = String(args.name || '').toLowerCase();
      const hit = routines.find(
        (r) => (id && r.id === id) || (qName && String(r.name || '').toLowerCase().includes(qName))
      );
      if (!hit) throw new Error('Routine not found');
      return { unit, routine: hit };
    }

    case 'get_week_plan':
      return {
        scheduleMode: st.scheduleMode || 'week',
        week: st.week || {},
        dayPlan: st.dayPlan || {},
        queue: st.queue || [],
        rotation: st.rotation || null,
      };

    case 'get_programme':
      return {
        programme: st.programme || null,
        programmes: st.programmes || [],
      };

    case 'list_workouts': {
      const limit = Math.max(1, Math.min(100, Number(args.limit) || 20));
      const since = typeof args.since === 'string' ? args.since : null;
      const filtered = workouts
        .filter((w) => !since || String(w.d || '') >= since)
        .slice()
        .sort((a, b) => String(b.d || '').localeCompare(String(a.d || '')))
        .slice(0, limit);
      return {
        unit,
        total: workouts.length,
        workouts: filtered.map((w) => ({
          id: w.id,
          date: w.d,
          name: w.name,
          duration: w.dur || null,
          exercises: Array.isArray(w.ex) ? w.ex.length : 0,
        })),
      };
    }

    case 'get_workout': {
      const id = String(args.id || '');
      const date = String(args.date || '');
      const hit = workouts.find((w) => (id && w.id === id) || (date && w.d === date));
      if (!hit) throw new Error('Workout not found');
      return { unit, workout: hit };
    }

    case 'estimate_1rm': {
      const q = String(args.exercise || '').toLowerCase();
      const history: Array<{ date: string; weight: number; reps: number; e1rm: number; exercise: string }> = [];
      for (const w of workouts) {
        const exList = Array.isArray(w.ex) ? (w.ex as Array<Record<string, unknown>>) : [];
        for (const ex of exList) {
          const exId = String(ex.id || ex.exId || '').toLowerCase();
          const exName = String(ex.name || exId).toLowerCase();
          if (!exId.includes(q) && !exName.includes(q)) continue;
          const sets = Array.isArray(ex.sets) ? (ex.sets as Array<Record<string, unknown>>) : [];
          for (const s of sets) {
            const wt = Number(s.w ?? s.weight ?? 0);
            const reps = Number(s.r ?? s.reps ?? 0);
            if (wt > 0 && reps > 0) {
              const e1rm = Math.round(wt * (1 + reps / 30) * 10) / 10;
              history.push({ date: String(w.d || ''), weight: wt, reps, e1rm, exercise: String(ex.name || ex.id) });
            }
          }
        }
      }
      history.sort((a, b) => b.e1rm - a.e1rm);
      return { unit, query: args.exercise, best: history[0] || null, topSets: history.slice(0, 15) };
    }

    case 'muscle_balance': {
      const days = Math.max(1, Math.min(365, Number(args.days) || 28));
      const cut = new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
      const byExercise: Record<string, { sets: number; volume: number }> = {};
      let sessionCount = 0;
      for (const w of workouts) {
        if (String(w.d || '') < cut) continue;
        sessionCount++;
        const exList = Array.isArray(w.ex) ? (w.ex as Array<Record<string, unknown>>) : [];
        for (const ex of exList) {
          const key = String(ex.name || ex.id || 'unknown');
          const sets = Array.isArray(ex.sets) ? (ex.sets as Array<Record<string, unknown>>) : [];
          if (!byExercise[key]) byExercise[key] = { sets: 0, volume: 0 };
          for (const s of sets) {
            byExercise[key].sets += 1;
            byExercise[key].volume += (Number(s.w ?? 0) || 0) * (Number(s.r ?? 0) || 0);
          }
        }
      }
      return { unit, days, since: cut, sessions: sessionCount, byExercise };
    }

    case 'get_bodyweight': {
      const limit = Math.max(1, Math.min(200, Number(args.limit) || 30));
      const sorted = bodyweight
        .slice()
        .sort((a, b) => String(b.d || '').localeCompare(String(a.d || '')))
        .slice(0, limit);
      return { unit, targetW: st.targetW ?? null, entries: sorted };
    }

    case 'search_exercises': {
      const q = String(args.query || '').toLowerCase();
      const seen = new Map<string, { id: string; name: string; source: string }>();
      for (const ex of customEx) {
        const id = String(ex.id || '');
        const n = String(ex.name || id);
        if (id.toLowerCase().includes(q) || n.toLowerCase().includes(q)) {
          seen.set(id || n, { id, name: n, source: 'custom' });
        }
      }
      for (const r of routines) {
        for (const ex of (Array.isArray(r.ex) ? r.ex : []) as Array<Record<string, unknown>>) {
          const id = String(ex.id || ex.exId || '');
          const n = String(ex.name || id);
          if (id.toLowerCase().includes(q) || n.toLowerCase().includes(q)) {
            if (!seen.has(id || n)) seen.set(id || n, { id, name: n, source: 'routine' });
          }
        }
      }
      return { query: args.query, matches: [...seen.values()].slice(0, 30) };
    }

    case 'log_workout': {
      const entry = {
        id: 'w_' + randomHex(6),
        d: typeof args.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(args.date)
          ? args.date
          : new Date().toISOString().slice(0, 10),
        name: String(args.name || 'Workout').slice(0, 80),
        ...(typeof args.durationMin === 'number' ? { dur: args.durationMin * 60 } : {}),
        ...(typeof args.notes === 'string' ? { note: args.notes.slice(0, 500) } : {}),
        ex: Array.isArray(args.exercises) ? args.exercises : [],
      };
      if (args.dry_run) return { dry_run: true, preview: entry };
      const next = { ...st, workouts: [...workouts, entry] };
      const saved = await commitUserState(env, ctx, auth.user.uid, cur, next, { baseRev: cur.rev });
      if (saved.status !== 200) throw new Error('Sync conflict while saving workout; please retry');
      return { saved: true, rev: saved.body.rev, workout: entry };
    }

    case 'create_routine': {
      const routine = {
        id: 'r_' + randomHex(6),
        name: String(args.name || 'New Routine').slice(0, 80),
        emoji: typeof args.emoji === 'string' ? args.emoji.slice(0, 8) : '🏋️',
        ex: Array.isArray(args.exercises) ? args.exercises : [],
      };
      if (args.dry_run) return { dry_run: true, preview: routine };
      const next = { ...st, routines: [...routines, routine] };
      const saved = await commitUserState(env, ctx, auth.user.uid, cur, next, { baseRev: cur.rev });
      if (saved.status !== 200) throw new Error('Sync conflict while creating routine; please retry');
      return { saved: true, rev: saved.body.rev, routine };
    }

    case 'update_routine': {
      const id = String(args.id || '');
      const idx = routines.findIndex((r) => r.id === id);
      if (idx < 0) throw new Error(`Routine ${id} not found`);
      const updated = {
        ...routines[idx],
        ...(typeof args.name === 'string' ? { name: args.name.slice(0, 80) } : {}),
        ...(typeof args.emoji === 'string' ? { emoji: args.emoji.slice(0, 8) } : {}),
        ...(Array.isArray(args.exercises) ? { ex: args.exercises } : {}),
      };
      if (args.dry_run) return { dry_run: true, preview: updated };
      const nextRoutines = routines.slice();
      nextRoutines[idx] = updated;
      const next = { ...st, routines: nextRoutines };
      const saved = await commitUserState(env, ctx, auth.user.uid, cur, next, { baseRev: cur.rev });
      if (saved.status !== 200) throw new Error('Sync conflict while updating routine; please retry');
      return { saved: true, rev: saved.body.rev, routine: updated };
    }

    case 'delete_routine': {
      const id = String(args.id || '');
      const target = routines.find((r) => r.id === id);
      if (!target) throw new Error(`Routine ${id} not found`);
      if (args.confirm !== true) {
        return { dry_run: true, message: 'Pass confirm: true to delete this routine', routine: target };
      }
      const next = { ...st, routines: routines.filter((r) => r.id !== id) };
      const saved = await commitUserState(env, ctx, auth.user.uid, cur, next, { baseRev: cur.rev });
      if (saved.status !== 200) throw new Error('Sync conflict while deleting routine; please retry');
      return { deleted: true, rev: saved.body.rev, id };
    }

    default:
      throw new Error(`Unsupported tool: ${name}`);
  }
}

mcpRoutes.get('/mcp/health', (c) => c.json({ ok: true, version: MCP_VERSION }));

mcpRoutes.all('/mcp', async (c) => {
  const origin = resolveOrigin(c.env, c.req.raw);
  const reqOrigin = c.req.header('origin');
  if (reqOrigin && reqOrigin.replace(/\/+$/, '') !== origin.replace(/\/+$/, '')) {
    return c.json({ jsonrpc: '2.0', error: { code: -32000, message: 'origin not allowed' }, id: null }, 403);
  }
  if (c.req.method !== 'POST') {
    return c.json(
      {
        jsonrpc: '2.0',
        error: { code: -32000, message: 'POST only: this MCP endpoint is stateless Streamable HTTP' },
        id: null,
      },
      405,
      { Allow: 'POST' }
    );
  }

  const authHeader = c.req.header('authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const auth = await authenticateApiToken(c.env, c.executionCtx, token);
  if (!auth) {
    return c.json(
      {
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'an openGym API token is required (Authorization: Bearer ogt_…)',
        },
        id: null,
      },
      401,
      {
        'WWW-Authenticate': `Bearer realm="openGym", error="invalid_token", resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp", scope="${DEFAULT_OAUTH_SCOPE}"`,
      }
    );
  }

  const rpc = (await c.req.json().catch(() => null)) as {
    jsonrpc?: string;
    id?: string | number | null;
    method?: string;
    params?: Record<string, unknown>;
  } | null;

  if (!rpc || rpc.jsonrpc !== '2.0' || typeof rpc.method !== 'string') {
    return c.json({ jsonrpc: '2.0', error: { code: -32600, message: 'Invalid Request' }, id: null }, 400);
  }

  const id = rpc.id ?? null;

  if (rpc.method === 'notifications/initialized') {
    return c.body(null, 202);
  }
  if (rpc.method === 'ping') {
    return c.json({ jsonrpc: '2.0', id, result: {} });
  }
  if (rpc.method === 'initialize') {
    return c.json({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: 'opengym', title: 'openGym', version: MCP_VERSION },
        instructions: MCP_INSTRUCTIONS,
      },
    });
  }
  if (rpc.method === 'tools/list') {
    const tools = TOOL_DEFS.filter((t) => toolAllowed(t, auth.scopes)).map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      annotations: t.annotations,
    }));
    return c.json({ jsonrpc: '2.0', id, result: { tools } });
  }
  if (rpc.method === 'tools/call') {
    const params = rpc.params || {};
    const toolName = String(params.name || '');
    const toolArgs = (params.arguments && typeof params.arguments === 'object'
      ? params.arguments
      : {}) as Record<string, unknown>;
    try {
      const result = await runTool(c.env, c.executionCtx, auth, toolName, toolArgs);
      return c.json({
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        },
      });
    } catch (e) {
      return c.json({
        jsonrpc: '2.0',
        id,
        result: {
          isError: true,
          content: [{ type: 'text', text: (e as Error).message || 'Tool execution failed' }],
        },
      });
    }
  }

  return c.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${rpc.method}` } }, 200);
});
