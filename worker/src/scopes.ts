/**
 * Upstream-compatible scoped API token rules (mirrors api/tokens.js).
 */

export const TOKEN_PREFIX = 'ogt_';
export const TOKEN_LEVELS = ['off', 'view', 'apply'] as const;
export type TokenLevel = (typeof TOKEN_LEVELS)[number];

export const TOKEN_CATEGORIES = [
  { id: 'workouts', max: 'apply' as TokenLevel },
  { id: 'plans', max: 'apply' as TokenLevel },
  { id: 'bodyweight', max: 'apply' as TokenLevel },
  { id: 'measurements', max: 'apply' as TokenLevel },
  { id: 'notes', max: 'view' as TokenLevel },
] as const;

export type TokenCategoryId = (typeof TOKEN_CATEGORIES)[number]['id'];
export const TOKEN_CATEGORY_IDS: TokenCategoryId[] = TOKEN_CATEGORIES.map((c) => c.id);
export const TOKENS_MAX = 10;
export const TOKEN_DAYS = [7, 30, 90, 365, 0] as const;
export const DEFAULT_DAYS = 90;

export type TokenScopes = Record<TokenCategoryId, TokenLevel>;

const rank = (lv: string | undefined): number => {
  const idx = TOKEN_LEVELS.indexOf((lv || 'off') as TokenLevel);
  return idx < 0 ? 0 : idx;
};

export const KEY_CATEGORY: Record<string, TokenCategoryId[]> = {
  workouts: ['workouts'],
  exWeights: ['workouts'],
  sessionTargets: ['plans'],
  customEx: ['workouts', 'plans'],
  routines: ['plans'],
  week: ['plans'],
  dayPlan: ['plans'],
  queue: ['plans'],
  rotation: ['plans'],
  scheduleMode: ['plans'],
  programmes: ['plans'],
  programme: ['plans'],
  bodyweight: ['bodyweight'],
  targetW: ['bodyweight'],
  rateGoal: ['bodyweight'],
  measurements: ['measurements'],
  customMeasurements: ['measurements'],
  measurementEnabled: ['measurements'],
  dayNotes: ['notes'],
  exNotes: ['notes'],
  gymNotes: ['notes'],
  journalFolders: ['notes'],
  recoverySessions: ['workouts'],
  activities: ['workouts'],
  heightCm: ['bodyweight', 'measurements'],
  birthYear: ['bodyweight', 'measurements'],
  sex: ['bodyweight', 'measurements'],
};

const NEVER = new Set([
  'dayPhotos',
  'exMedia',
  'dayForm',
  'avatar',
  'sounds',
  'active',
  'coach',
  'integrations',
  '_unstamped',
  '_prior',
  'deleted',
  'edited',
  'undone',
]);
const NEVER_RE = /photo|avatar|video|secret|token|password|integration/i;
const BOOK = new Set(['_rev', '_wid', '_wids', '_ts']);

export class ScopeError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function cleanTokenScopes(input: unknown): TokenScopes {
  const src = input && typeof input === 'object' ? (input as Record<string, unknown>) : {};
  const out = {} as TokenScopes;
  for (const c of TOKEN_CATEGORIES) {
    const raw = typeof src[c.id] === 'string' ? (src[c.id] as string) : 'off';
    const want = TOKEN_LEVELS.includes(raw as TokenLevel) ? raw : 'off';
    out[c.id] = TOKEN_LEVELS[Math.min(rank(want), rank(c.max))];
  }
  return out;
}

export function grantsNothing(scopes: Partial<TokenScopes> | null | undefined): boolean {
  return TOKEN_CATEGORY_IDS.every((id) => rank(scopes?.[id]) === 0);
}

export function allows(
  scopes: Partial<TokenScopes> | null | undefined,
  category: TokenCategoryId,
  level: TokenLevel
): boolean {
  return TOKEN_CATEGORY_IDS.includes(category) && rank(scopes?.[category]) >= rank(level);
}

function keyClass(k: string): TokenCategoryId[] | 'book' | null | false {
  if (NEVER.has(k) || NEVER_RE.test(k)) return false;
  if (BOOK.has(k)) return 'book';
  return Object.prototype.hasOwnProperty.call(KEY_CATEGORY, k) ? KEY_CATEGORY[k] : null;
}

function readable(k: string, scopes: TokenScopes): boolean {
  const c = keyClass(k);
  if (c === false) return false;
  if (c === 'book' || c === null) {
    return TOKEN_CATEGORY_IDS.some((id) => allows(scopes, id, 'view'));
  }
  return c.some((id) => allows(scopes, id, 'view'));
}

function writable(k: string, scopes: TokenScopes): boolean {
  const c = keyClass(k);
  return Array.isArray(c) && c.some((id) => allows(scopes, id, 'apply'));
}

export function scopedState(
  state: Record<string, unknown> | null | undefined,
  scopes: TokenScopes
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!state || typeof state !== 'object' || Array.isArray(state)) return out;
  for (const [k, v] of Object.entries(state)) {
    if (readable(k, scopes)) out[k] = v;
  }
  return out;
}

const sameJson = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export function mergeScoped(
  cur: Record<string, unknown> | null | undefined,
  sent: Record<string, unknown>,
  scopes: TokenScopes
): { next: Record<string, unknown>; touched: TokenCategoryId[] } {
  if (!sent || typeof sent !== 'object' || Array.isArray(sent)) {
    throw new ScopeError(400, 'bad-state', 'state must be an object');
  }
  const base = cur && typeof cur === 'object' ? cur : {};
  const next = JSON.parse(JSON.stringify(base)) as Record<string, unknown>;
  const touched = new Set<TokenCategoryId>();

  for (const [k, v] of Object.entries(sent)) {
    if (BOOK.has(k)) continue;
    if (writable(k, scopes)) {
      if (!sameJson(base[k], v)) {
        if (v === undefined) delete next[k];
        else next[k] = JSON.parse(JSON.stringify(v));
        for (const c of KEY_CATEGORY[k]) {
          if (allows(scopes, c, 'apply')) touched.add(c);
        }
      }
      continue;
    }
    if (readable(k, scopes) && sameJson(base[k], v)) continue;
    throw new ScopeError(403, 'scope', `this token may not change ${JSON.stringify(k).slice(0, 60)}`);
  }

  return { next, touched: [...touched] };
}

export const OAUTH_SCOPES: string[] = TOKEN_CATEGORIES.flatMap((c) =>
  c.max === 'apply' ? [`${c.id}:view`, `${c.id}:apply`] : [`${c.id}:view`]
);
export const DEFAULT_OAUTH_SCOPE = 'workouts:view plans:apply bodyweight:view offline_access';

export function scopesFromString(str: string | null | undefined): TokenScopes {
  const out: Partial<TokenScopes> = {};
  for (const word of String(str || '').split(/\s+/)) {
    const [cat, lv] = word.split(':');
    if (!TOKEN_CATEGORY_IDS.includes(cat as TokenCategoryId)) continue;
    if (!TOKEN_LEVELS.includes(lv as TokenLevel)) continue;
    const cid = cat as TokenCategoryId;
    if (rank(lv) > rank(out[cid])) out[cid] = lv as TokenLevel;
  }
  return cleanTokenScopes(out);
}

export function scopeString(scopes: Partial<TokenScopes> | null | undefined): string {
  return Object.entries(scopes || {})
    .filter(([, v]) => v && v !== 'off')
    .map(([k, v]) => `${k}:${v}`)
    .join(' ');
}
