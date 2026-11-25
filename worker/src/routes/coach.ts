import { Hono } from 'hono';
import { Env } from '../env';
import { openSecret, sealSecret } from '../crypto';
import { getSessionFromRequest, isAdmin, textField } from '../db';
import { readUserState } from './data';

export const coachRoutes = new Hono<{ Bindings: Env }>();

interface ProviderMeta {
  id: string;
  label: string;
  defaultBase: string;
  defaultModel: string;
  apiStyle: 'openai' | 'anthropic' | 'gemini';
}

const PROVIDERS: Record<string, ProviderMeta> = {
  gemini: {
    id: 'gemini',
    label: 'Google Gemini',
    defaultBase: 'https://generativelanguage.googleapis.com/v1beta',
    defaultModel: 'gemini-2.5-flash',
    apiStyle: 'gemini',
  },
  openai: {
    id: 'openai',
    label: 'OpenAI',
    defaultBase: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4o-mini',
    apiStyle: 'openai',
  },
  anthropic: {
    id: 'anthropic',
    label: 'Anthropic Claude',
    defaultBase: 'https://api.anthropic.com/v1',
    defaultModel: 'claude-3-5-sonnet-latest',
    apiStyle: 'anthropic',
  },
  openrouter: {
    id: 'openrouter',
    label: 'OpenRouter',
    defaultBase: 'https://openrouter.ai/api/v1',
    defaultModel: 'google/gemini-2.5-flash',
    apiStyle: 'openai',
  },
  compatible: {
    id: 'compatible',
    label: 'OpenAI-Compatible',
    defaultBase: '',
    defaultModel: '',
    apiStyle: 'openai',
  },
};

function sealKey(env: Env): string {
  return env.ENC_KEY || env.SESSION_SECRET;
}

interface CoachSettingsRow {
  enabled: number;
  active_provider: string;
  config_json: string;
  providers_enc_json: string;
  updated_at: number;
}

async function loadCoachSettings(env: Env): Promise<{
  enabled: boolean;
  provider: string;
  config: { models: Record<string, string>; baseUrls: Record<string, string>; maxMessageLen: number };
  providersEnc: Record<string, { data: string; connectedAt: string }>;
}> {
  const row = await env.DB.prepare('SELECT * FROM coach_settings WHERE id = 1').first<CoachSettingsRow>();
  if (!row) {
    return {
      enabled: false,
      provider: 'gemini',
      config: { models: {}, baseUrls: {}, maxMessageLen: 1000 },
      providersEnc: {},
    };
  }
  const parsed = JSON.parse(row.config_json || '{}') as Record<string, unknown>;
  return {
    enabled: row.enabled === 1,
    provider: PROVIDERS[row.active_provider] ? row.active_provider : 'gemini',
    config: {
      models: (parsed.models as Record<string, string>) || {},
      baseUrls: (parsed.baseUrls as Record<string, string>) || {},
      maxMessageLen: Number(parsed.maxMessageLen) || 1000,
    },
    providersEnc: JSON.parse(row.providers_enc_json || '{}') as Record<
      string,
      { data: string; connectedAt: string }
    >,
  };
}

async function saveCoachSettings(
  env: Env,
  next: {
    enabled: boolean;
    provider: string;
    config: Record<string, unknown>;
    providersEnc: Record<string, unknown>;
  }
) {
  await env.DB.prepare(
    `INSERT OR REPLACE INTO coach_settings (id, enabled, active_provider, config_json, providers_enc_json, updated_at)
     VALUES (1, ?, ?, ?, ?, ?)`
  )
    .bind(
      next.enabled ? 1 : 0,
      next.provider,
      JSON.stringify(next.config),
      JSON.stringify(next.providersEnc),
      Date.now()
    )
    .run();
}

async function callCoachLlm(
  env: Env,
  providerId: string,
  apiKey: string,
  model: string,
  baseUrl: string,
  systemPrompt: string,
  userPrompt: string
): Promise<string> {
  const meta = PROVIDERS[providerId];
  if (!meta) throw new Error('Unknown AI Coach provider');
  const base = (baseUrl || meta.defaultBase).replace(/\/+$/, '');
  const mdl = model || meta.defaultModel;

  if (meta.apiStyle === 'gemini') {
    const res = await fetch(`${base}/models/${encodeURIComponent(mdl)}:generateContent?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
      }),
    });
    const data = (await res.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
      error?: { message?: string };
    };
    if (!res.ok) throw new Error(data.error?.message || `Gemini HTTP ${res.status}`);
    return data.candidates?.[0]?.content?.parts?.map((p) => p.text || '').join('') || '';
  }

  if (meta.apiStyle === 'anthropic') {
    const res = await fetch(`${base}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: mdl,
        max_tokens: 1024,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });
    const data = (await res.json()) as {
      content?: Array<{ text?: string }>;
      error?: { message?: string };
    };
    if (!res.ok) throw new Error(data.error?.message || `Anthropic HTTP ${res.status}`);
    return data.content?.map((c) => c.text || '').join('') || '';
  }

  // OpenAI / OpenRouter / OpenAI-compatible
  const res = await fetch(`${base}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: mdl,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
    }),
  });
  const data = (await res.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
    error?: { message?: string };
  };
  if (!res.ok) throw new Error(data.error?.message || `Provider HTTP ${res.status}`);
  return data.choices?.[0]?.message?.content || '';
}

/* ---------- User Coach Routes ---------- */

coachRoutes.get('/api/coach/disclosure', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const cfg = await loadCoachSettings(c.env);
  const meta = PROVIDERS[cfg.provider];
  const base = cfg.config.baseUrls[cfg.provider] || meta.defaultBase;
  let host: string | null = null;
  try {
    host = base ? new URL(base).host : null;
  } catch {
    host = null;
  }
  return c.json({
    provider: cfg.provider,
    providerLabel: meta.label,
    host,
    categories: ['workouts', 'routines', 'bodyweight'],
    version: 1,
  });
});

coachRoutes.get('/api/coach/status', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const cfg = await loadCoachSettings(c.env);
  if (!cfg.enabled || !cfg.providersEnc[cfg.provider]) {
    return c.json({ error: 'the Coach is not set up on this instance', code: 'off' }, 503);
  }
  const thread = await c.env.DB.prepare('SELECT messages_json, pending_json FROM coach_threads WHERE uid = ?')
    .bind(s.user.uid)
    .first<{ messages_json: string; pending_json: string | null }>();
  return c.json({
    running: false,
    pending: thread?.pending_json ? JSON.parse(thread.pending_json) : null,
    messages: thread?.messages_json ? JSON.parse(thread.messages_json) : [],
    maxMessageLen: cfg.config.maxMessageLen,
  });
});

coachRoutes.post('/api/coach/ask', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const cfg = await loadCoachSettings(c.env);
  const enc = cfg.providersEnc[cfg.provider];
  if (!cfg.enabled || !enc) {
    return c.json({ error: 'the Coach is not set up on this instance', code: 'off' }, 503);
  }
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const question = textField(body.text).trim().slice(0, cfg.config.maxMessageLen);
  if (!question) return c.json({ error: 'a question is required', code: 'invalid' }, 400);

  const apiKey = await openSecret(sealKey(c.env), enc.data, `coach:${cfg.provider}`);
  if (!apiKey) return c.json({ error: 'stored provider key could not be decrypted' }, 500);

  const cur = await readUserState(c.env, s.user.uid);
  const st = cur.state || {};
  const summary = {
    unit: st.unit || 'kg',
    routinesCount: Array.isArray(st.routines) ? st.routines.length : 0,
    recentWorkouts: Array.isArray(st.workouts) ? (st.workouts as unknown[]).slice(-5) : [],
  };

  try {
    const answer = await callCoachLlm(
      c.env,
      cfg.provider,
      apiKey,
      cfg.config.models[cfg.provider] || '',
      cfg.config.baseUrls[cfg.provider] || '',
      'You are openGym Coach, a concise, evidence-based strength and hypertrophy coach. Answer based on the user profile summary.',
      `Profile context:\n${JSON.stringify(summary)}\n\nQuestion: ${question}`
    );

    const prev = await c.env.DB.prepare('SELECT messages_json FROM coach_threads WHERE uid = ?')
      .bind(s.user.uid)
      .first<{ messages_json: string }>();
    const msgs = prev?.messages_json ? (JSON.parse(prev.messages_json) as unknown[]) : [];
    msgs.push({ role: 'user', text: question, at: Date.now() });
    msgs.push({ role: 'assistant', text: answer, at: Date.now() });
    const trimmed = msgs.slice(-40);

    await c.env.DB.prepare(
      `INSERT OR REPLACE INTO coach_threads (uid, messages_json, updated_at)
       VALUES (?, ?, ?)`
    )
      .bind(s.user.uid, JSON.stringify(trimmed), Date.now())
      .run();

    return c.json({ ok: true, answer, messages: trimmed });
  } catch (e) {
    return c.json({ error: (e as Error).message || 'Coach request failed' }, 502);
  }
});

coachRoutes.post('/api/coach/forget', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  await c.env.DB.prepare('DELETE FROM coach_threads WHERE uid = ?').bind(s.user.uid).run();
  return c.json({ ok: true });
});

/* ---------- Admin Coach Routes ---------- */

coachRoutes.get('/api/admin/coach', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  if (!isAdmin(c.env, s.user)) return c.json({ error: 'forbidden' }, 403);

  const cfg = await loadCoachSettings(c.env);
  const enc = cfg.providersEnc[cfg.provider];
  return c.json({
    disabledByEnv: false,
    enabled: cfg.enabled,
    provider: cfg.provider,
    providers: Object.values(PROVIDERS).map((p) => ({
      id: p.id,
      label: p.label,
      http: true,
      apiKey: true,
      baseUrl: p.id === 'compatible' || p.id === 'openrouter',
      defaultModel: p.defaultModel || null,
      connected: !!cfg.providersEnc[p.id],
    })),
    model: cfg.config.models[cfg.provider] || PROVIDERS[cfg.provider].defaultModel,
    models: cfg.config.models,
    baseUrl: cfg.config.baseUrls[cfg.provider] || PROVIDERS[cfg.provider].defaultBase,
    maxMessageLen: cfg.config.maxMessageLen,
    auth: enc
      ? { state: 'connected', type: 'apikey', connectedAt: enc.connectedAt }
      : { state: 'none' },
    unprivileged: { ok: true, dropped: false, why: 'Cloudflare Workers runs HTTPS providers only' },
  });
});

coachRoutes.post('/api/admin/coach/config', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  if (!isAdmin(c.env, s.user)) return c.json({ error: 'forbidden' }, 403);

  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const cfg = await loadCoachSettings(c.env);

  if (body.enabled !== undefined) cfg.enabled = !!body.enabled;
  if (typeof body.provider === 'string' && PROVIDERS[body.provider]) {
    cfg.provider = body.provider;
  }
  if (typeof body.model === 'string') {
    cfg.config.models[cfg.provider] = body.model.trim().slice(0, 80);
  }
  if (typeof body.baseUrl === 'string') {
    cfg.config.baseUrls[cfg.provider] = body.baseUrl.trim().slice(0, 200);
  }
  if (body.maxMessageLen !== undefined) {
    cfg.config.maxMessageLen = Math.max(100, Math.min(4000, Number(body.maxMessageLen) || 1000));
  }

  await saveCoachSettings(c.env, cfg);
  return c.json({ ok: true });
});

coachRoutes.post('/api/admin/coach/connect', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  if (!isAdmin(c.env, s.user)) return c.json({ error: 'forbidden' }, 403);

  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const cfg = await loadCoachSettings(c.env);
  const provider = typeof body.provider === 'string' && PROVIDERS[body.provider] ? body.provider : cfg.provider;
  const token = textField(body.token).trim();
  if (!token) return c.json({ error: 'no token supplied' }, 400);

  cfg.providersEnc[provider] = {
    data: await sealSecret(sealKey(c.env), token, `coach:${provider}`),
    connectedAt: new Date().toISOString(),
  };
  await saveCoachSettings(c.env, cfg);
  return c.json({ ok: true });
});

coachRoutes.post('/api/admin/coach/disconnect', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  if (!isAdmin(c.env, s.user)) return c.json({ error: 'forbidden' }, 403);

  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const cfg = await loadCoachSettings(c.env);
  const provider = typeof body.provider === 'string' && PROVIDERS[body.provider] ? body.provider : cfg.provider;
  delete cfg.providersEnc[provider];
  await saveCoachSettings(c.env, cfg);
  return c.json({ ok: true });
});

coachRoutes.post('/api/admin/coach/test', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  if (!isAdmin(c.env, s.user)) return c.json({ error: 'forbidden' }, 403);

  const cfg = await loadCoachSettings(c.env);
  const enc = cfg.providersEnc[cfg.provider];
  if (!enc) return c.json({ ok: false, error: 'provider not connected' });
  const apiKey = await openSecret(sealKey(c.env), enc.data, `coach:${cfg.provider}`);
  if (!apiKey) return c.json({ ok: false, error: 'key unreadable' });

  try {
    const reply = await callCoachLlm(
      c.env,
      cfg.provider,
      apiKey,
      cfg.config.models[cfg.provider] || '',
      cfg.config.baseUrls[cfg.provider] || '',
      'Reply with OK.',
      'Health check'
    );
    return c.json({ ok: true, reply: reply.slice(0, 80) });
  } catch (e) {
    return c.json({ ok: false, error: (e as Error).message });
  }
});
