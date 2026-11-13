/*
 * Credential and secret-material rules for the `redact` plugin.
 *
 * Most rules, their helper predicates and the intended matches in the test
 * suite are ported from magpie's `internal/redact` package
 * (https://github.com/yetone/magpie, files rules.go, redact.go, fieldvalue.go,
 * crypto.go), translated from Go/RE2 to JavaScript regular expressions:
 *
 *   MIT License
 *   Copyright (c) 2026 yetone
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a
 *   copy of this software and associated documentation files (the
 *   "Software"), to deal in the Software without restriction, including
 *   without limitation the rights to use, copy, modify, merge, publish,
 *   distribute, sublicense, and/or sell copies of the Software, and to permit
 *   persons to whom the Software is furnished to do so, subject to the
 *   following conditions:
 *
 *   The above copyright notice and this permission notice shall be included
 *   in all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 *   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 *   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Only credentials and secret material are covered: names, ids, emails,
 * phones, IPs, hashes and UUIDs are deliberately NOT rules here (magpie masks
 * them; LuckyBot needs them to tell group members apart, issue #27).
 *
 * Differences from magpie, all deliberate:
 * - The output is irreversible `[redacted:<kind>]`; there is no placeholder
 *   map, no "known value" memory and no model-assisted pass.
 * - Go's RE2 guarantees linear time; V8 backtracks. Every pattern here is
 *   anchored on a literal or a lookbehind, has bounded quantifiers wherever
 *   the surrounding class could repeat, and leading `[A-Za-z0-9_.-]*` name
 *   prefixes were dropped in favour of matching the keyword itself.
 * - Bank cards are checked for 13-19 digits (magpie: 15-19) and must start
 *   with 3-6 (a card network's major industry digit), which also keeps
 *   13-digit epoch-millisecond timestamps out.
 * - Seed phrases need no cue word: 12/15/18/21/24 consecutive English BIP-0039
 *   words are enough (magpie wants a "seed"/"mnemonic" cue and also accepts
 *   Algorand's 25).
 * - Not ported: Solana, NEAR, Stellar keys, Cloudflare `key` header rules and
 *   the bare `"key": "…"` rule (low value here, high false-positive risk).
 */

import { createHash } from 'node:crypto';

import { wordlist } from '@scure/bip39/wordlists/english.js';

export type RedactKind =
  | 'api-key'
  | 'token'
  | 'private-key'
  | 'password'
  | 'secret'
  | 'seed-phrase'
  | 'bank-card'
  | 'cn-id';

export const REDACT_KINDS: readonly RedactKind[] = [
  'api-key',
  'token',
  'private-key',
  'password',
  'secret',
  'seed-phrase',
  'bank-card',
  'cn-id',
];

export interface RedactSpan {
  start: number;
  end: number;
  kind: RedactKind;
}

export const marker = (kind: RedactKind): string => `[redacted:${kind}]`;

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const isLetter = (c: string | undefined): boolean => c !== undefined && /^[A-Za-z]$/.test(c);

// ---------------------------------------------------------------------------
// Value predicates (magpie: notAVariable, secretValue, notASlug, headerValue,
// hiddenInURL, luhn, chineseID and fieldvalue.go).
// ---------------------------------------------------------------------------

/** Turns away what stands in for a value: ${PASS}, <password>, ****. */
const notAVariable = (v: string): boolean => {
  if (v === '' || '$%{<[*'.includes(v[0]!)) return false;
  return !/^[*xX.]*$/.test(v);
};

/** Letters and digits both, and not a call, a reference or a placeholder. */
const secretValue = (v: string): boolean => {
  if (!notAVariable(v) || v.startsWith('process.env') || v.startsWith('os.')) return false;
  return /\d/.test(v) && /[A-Za-z]/.test(v);
};

/**
 * Words in lower case joined by hyphens are a page address, not a key. A key's
 * characters are random: a capital, a 16+ run, or hex digits only.
 */
const notASlug = (v: string): boolean => {
  if (/[A-Z]/.test(v)) return true;
  const rest = v.startsWith('sk-') ? v.slice(3) : v;
  if (!/[^-_0-9a-f]/.test(rest)) return true;
  return v.split(/[-_]/).some(w => w.length >= 16);
};

const stampRe = /^\d{4}-\d{1,2}-\d{1,2}[Tt]\d{1,2}(?::\d{1,2}){0,2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?$/;
const versionRangeRe = new RegExp(
  '^(?:[~^]|[<>=!~]=?|==)?[vV]?\\d+(?:\\.\\d+)+'
  + '(?:[-+._]?(?:(?:alpha|beta|rc|pre|preview|post|dev|canary|next|nightly|snapshot|release|final|ga|stable|build|incubating)\\d*|[abcmABCM]\\d+|\\d+))*$',
  'i',
);
const lineRefRe = /^L?\d+(?:[-–:]L?\d+)*[.,;:]?$/;
const identRe = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;
const identPathRe = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$/;
const skillSlugRe = /^[a-z0-9]+(?:-[a-z0-9]+)+$/;
const nextFieldRe = /^(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_-]*|--?[A-Za-z][A-Za-z0-9_-]*)=[^=]/;

const versionValue = (v: string): boolean => /^(?:[~^]|[<>=!~]=?|==)?[vV]?\d/.test(v) && versionRangeRe.test(v);
const timestampValue = (v: string): boolean => stampRe.test(v);
const lineRef = (v: string): boolean => lineRefRe.test(v);

const PATH_ROOTS = new Set([
  'Users', 'home', 'tmp', 'private', 'var', 'etc', 'run', 'opt', 'usr', 'mnt', 'Volumes', 'root', 'srv',
  'data', 'workspace', 'workspaces', 'app', 'Applications', 'Library', 'System', 'proc', 'dev', 'sys', 'nix',
]);

const pathValue = (v: string): boolean => {
  if (/[+=]/.test(v)) return false;
  for (const p of ['~/', './', '../']) {
    if (v.startsWith(p) && v.length > p.length) return true;
  }
  if (!v.startsWith('/')) return false;
  const slash = v.indexOf('/', 1);
  if (slash < 0 || slash === v.length - 1) return false;
  return PATH_ROOTS.has(v.slice(1, slash));
};

const SECRET_WORDS = new Set([
  'token', 'tokens', 'secret', 'secrets', 'password', 'passwords', 'passwd', 'pwd', 'key', 'keys', 'apikey',
  'credential', 'credentials',
]);

const identWords = (v: string): string[] => {
  const out: string[] = [];
  for (const part of v.split(/[_.]/)) {
    if (part === '') continue;
    let start = 0;
    for (let i = 1; i < part.length; i++) {
      if (/[A-Z]/.test(part[i]!) && /[a-z]/.test(part[i - 1]!)) {
        out.push(part.slice(start, i));
        start = i;
      }
    }
    out.push(part.slice(start));
  }
  return out;
};

/** A name in code for a secret (refreshToken2, env.SECRET_V2), not a secret. */
const namesASecret = (v: string): boolean => {
  if (!identRe.test(v)) return false;
  if (!/[a-z]/.test(v[0]!) && !/[_.]/.test(v)) return false;
  let words = 0;
  let named = false;
  for (let w of identWords(v)) {
    if (!/[A-Za-z]/.test(w)) continue;
    words++;
    const digit = w.search(/\d/);
    if (digit >= 0) w = w.slice(0, digit);
    if (SECRET_WORDS.has(w.toLowerCase())) named = true;
  }
  return words >= 2 && named;
};

const SOURCE_EXT = new Set([
  'go', 'ts', 'tsx', 'mts', 'cts', 'js', 'jsx', 'mjs', 'cjs', 'py', 'pyi', 'rb', 'rs', 'java', 'kt', 'kts', 'swift',
  'c', 'h', 'cc', 'cpp', 'cxx', 'hpp', 'hh', 'm', 'mm', 'cs', 'fs', 'php', 'scala', 'dart', 'lua', 'zig', 'nim',
  'ex', 'exs', 'erl', 'hs', 'ml', 'clj', 'r', 'jl', 'sh', 'bash', 'zsh', 'fish', 'ps1', 'vue', 'svelte', 'astro',
  'md', 'mdx', 'rst', 'sql', 'proto', 'graphql', 'gradle', 'html', 'css', 'scss', 'less', 'json', 'jsonc', 'yaml',
  'yml', 'toml', 'xml', 'tf', 'ipynb',
]);

const NAME_CH = `${ALNUM}_.-`;

/** The name before the value at text[a] is a file's, not a field's (token.go:L643). */
const fileField = (text: string, a: number): boolean => {
  let i = a;
  while (i > 0 && ' \t"\'\\'.includes(text[i - 1]!)) i--;
  if (i === 0 || (text[i - 1] !== ':' && text[i - 1] !== '=')) return false;
  i--;
  while (i > 0 && ' \t"\'\\'.includes(text[i - 1]!)) i--;
  const end = i;
  while (i > 0 && end - i < 128 && NAME_CH.includes(text[i - 1]!)) i--;
  const name = text.slice(i, end);
  if (name === '') return false;
  if (i > 0 && (text[i - 1] === '/' || text[i - 1] === '\\')) return true;
  const dot = name.lastIndexOf('.');
  return dot > 0 && SOURCE_EXT.has(name.slice(dot + 1).toLowerCase());
};

/** The second half of plugin:skill, as Claude Code names a skill. */
const skillName = (text: string, a: number, b: number): boolean => {
  const v = text.slice(a, b);
  if (a < 2 || text[a - 1] !== ':' || !skillSlugRe.test(v) || notASlug(v)) return false;
  let i = a - 1;
  while (i > 0 && a - 1 - i < 128 && 'abcdefghijklmnopqrstuvwxyz0123456789-'.includes(text[i - 1]!)) i--;
  return i < a - 1
    && (i === 0 || !`${ALNUM}_.`.includes(text[i - 1]!))
    && skillSlugRe.test(text.slice(i, a - 1));
};

const skipBlanksBack = (text: string, from: number): number => {
  let i = from;
  while (i > 0 && (text[i - 1] === ' ' || text[i - 1] === '\t')) i--;
  return i;
};

const skipBlanksFwd = (text: string, from: number): number => {
  let i = from;
  while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i++;
  return i;
};

/**
 * Code naming a secret, not the secret: a call (secretKey = fromBase64(…)),
 * or, unquoted after a colon, a type or a read that code goes on from.
 */
const notCode = (text: string, a: number, b: number): boolean => {
  if (!identPathRe.test(text.slice(a, b))) return true;
  const rest = skipBlanksFwd(text, b);
  if (text[rest] === '(') return false;
  const quoted = a > 0 && (text[a - 1] === '"' || text[a - 1] === '\'');
  const colon = text[skipBlanksBack(text, a) - 1] === ':';
  if (quoted || !colon) return true;
  return rest >= text.length || !';,)}]|?&<>'.includes(text[rest]!);
};

const fieldAt = (text: string, a: number, b: number): boolean => {
  if (!notCode(text, a, b)) return false;
  const v = text.slice(a, b);
  if (v.startsWith('=')) return false;
  return !fileField(text, a) && !lineRef(v) && !pathValue(v) && !namesASecret(v)
    && !skillName(text, a, b) && !versionValue(v) && !timestampValue(v);
};

/** The upper-case name before the value only ends in key and holds no secret. */
const notAPlainKey = (text: string, a: number): boolean => {
  let i = a;
  while (i > 0 && '"\' \t:='.includes(text[i - 1]!)) i--;
  const end = i;
  while (i > 0 && end - i < 128 && NAME_CH.includes(text[i - 1]!)) i--;
  const name = text.slice(i, end).toLowerCase();
  return !name.endsWith('sort_key') && !name.endsWith('cache_key') && !name.endsWith('public_key');
};

const namedSecretAt = (text: string, a: number, b: number): boolean =>
  notAPlainKey(text, a) && notCode(text, a, b) && fieldAt(text, a, b);

/** An Authorization or Cookie line's rest is a header's value, not prose. */
const headerValue = (raw: string): boolean => {
  const v = raw.trim();
  if (v === '' || !notAVariable(v)) return false;
  const notLetter = (s: string): boolean => /[^A-Za-z]/.test(s);
  const f = v.split(/\s+/);
  if (f.length === 1 || (f.length === 2 && !notLetter(f[0]!))) {
    const cred = f[f.length - 1]!;
    return cred.length >= 8 && notAVariable(cred) && notLetter(cred);
  }
  for (let kv of v.split(';')) {
    kv = kv.trim();
    if (kv === '') continue;
    const eq = kv.indexOf('=');
    if (eq <= 0 || /[ \t]/.test(kv.slice(0, eq))) return false;
  }
  return v.includes('=');
};

/**
 * A URL password that is also written elsewhere in the URL (its user, a host
 * label, the database) is not hidden by masking it: postgres:postgres@…
 */
const hiddenInURL = (text: string, a: number, b: number): boolean => {
  const pw = text.slice(a, b);
  const i = text.lastIndexOf('//', a);
  if (i < 0 || text[a - 1] !== ':') return true;
  if (text.slice(i + 2, a - 1) === pw) return false;
  let end = b + 1;
  while (end < text.length && !' \t\r\n"\'<>`\\)]}'.includes(text[end]!)) end++;
  if (b + 1 > end) return true;
  for (const part of text.slice(b + 1, end).split(/[/:.?#&=;,@]/)) {
    if (part === pw) return false;
  }
  return true;
};

const luhn = (digits: string): boolean => {
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
};

const CN_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const CN_ID_CHECK = '10X98765432';

const chineseID = (v: string): boolean => {
  if (v.length !== 18) return false;
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += (v.charCodeAt(i) - 48) * CN_ID_WEIGHTS[i]!;
  return v[17]!.toUpperCase() === CN_ID_CHECK[sum % 11];
};

// ---------------------------------------------------------------------------
// base58check (WIF, BIP-0032), for keys that carry a checksum.
// ---------------------------------------------------------------------------

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const base58Decode = (s: string): Uint8Array | undefined => {
  let n = 0n;
  for (const ch of s) {
    const d = B58.indexOf(ch);
    if (d < 0) return undefined;
    n = n * 58n + BigInt(d);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  bytes.reverse();
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes]);
};

const base58Check = (s: string): Uint8Array | undefined => {
  const b = base58Decode(s);
  if (!b || b.length < 5) return undefined;
  const payload = b.subarray(0, b.length - 4);
  const sum = b.subarray(b.length - 4);
  const h = createHash('sha256').update(createHash('sha256').update(payload).digest()).digest();
  for (let i = 0; i < 4; i++) {
    if (h[i] !== sum[i]) return undefined;
  }
  return payload;
};

const wifKey = (v: string): boolean => {
  if (v.length !== 51 && v.length !== 52) return false;
  const p = base58Check(v);
  return p !== undefined && (p.length === 33 || (p.length === 34 && p[33] === 1));
};

const bip32Key = (v: string): boolean => base58Check(v)?.length === 78;

// ---------------------------------------------------------------------------
// Wallet hex keys: only after a name that says it is a key.
// ---------------------------------------------------------------------------

const WALLET_KEY_CUES = ['priv', 'secret', 'signer', 'signing', 'deployer', 'wallet', 'pk', '私钥', '私鑰', '秘密鍵', '개인키', '비밀키'];
const NOT_KEY_WORDS = ['hash', 'sha', 'digest', 'sum', 'pub', 'addr', 'tx', 'fingerprint'];

const walletKeyAt = (text: string, a: number): boolean => {
  let start = Math.max(0, a - 48);
  const nl = text.lastIndexOf('\n', a - 1);
  if (nl >= start) start = nl + 1;
  const before = text.slice(start, a).toLowerCase();
  let cue = -1;
  let cueEnd = 0;
  for (const c of WALLET_KEY_CUES) {
    for (let i = 0; ;) {
      const at = before.indexOf(c, i);
      if (at < 0) break;
      i = at + c.length;
      if (c === 'pk' && ((at > 0 && isLetter(before[at - 1])) || (i < before.length && isLetter(before[i])))) continue;
      if (at > cue) {
        cue = at;
        cueEnd = i;
      }
    }
  }
  if (cue < 0) return false;
  const between = before.slice(cueEnd);
  if (NOT_KEY_WORDS.some(w => between.includes(w))) return false;
  const t = between.replace(/^[_\- ]+/, '');
  return !(t.startsWith('id') && (t.length === 2 || !isLetter(t[2])));
};

// ---------------------------------------------------------------------------
// Rules.
// ---------------------------------------------------------------------------

interface PatternRule {
  kind: RedactKind;
  re: RegExp;
  /** Capture group holding the secret; 0 = whole match. */
  group?: number;
  /** Cheap final check on the value, with its position in the text. */
  check?: (value: string, text: string, start: number, end: number) => boolean;
  /** A match whose value is the next field's assignment is skipped, scanning on from it. */
  skipNextField?: boolean;
}

// Characters that may not touch a prefixed token on either side.
const TOKEN_BEFORE = '(?<![A-Za-z0-9_-])';
const TOKEN_AFTER = '(?![A-Za-z0-9_-])';

const QUOTE = '(?:\\\\?["\'])?';
const SECRET_CH = '[A-Za-z0-9_\\-./+=~!@#%^&*]';

// What a field that holds a secret has in its name. `pwd` is a word of its own
// so that `cwd`-style shell vocabulary around "pwd" does not count.
const PASSWORD_NAMES = 'password|passwd|passphrase|(?<![A-Za-z])pwd';
const SECRET_NAMES = `${PASSWORD_NAMES}|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|priv[_-]?key|credential`;
// A name's characters after the keyword (DB_PASSWORD_PROD, tokenValue, secrets).
const NAME_TAIL = '[A-Za-z0-9_.-]{0,64}';

const CJK_PASSWORD_NAMES = ['密码', '密碼', '口令', 'PIN码', 'PIN碼', 'PIN 码', '安全码', '安全碼', 'パスワード', '暗証番号', '비밀번호', '암호', '비번'];
const CJK_KEY_NAMES = [
  '密钥', '密鑰', '秘钥', '秘鑰', '私钥', '私鑰', '金钥', '金鑰', '令牌', '权杖', '權杖', '授权码', '授權碼',
  '秘密鍵', 'トークン', 'シークレット', 'APIキー', 'アクセスキー', '토큰', '비밀키', 'API 키', 'API키',
];

const cjkNamed = (names: readonly string[]): RegExp =>
  new RegExp(
    `(?:${names.join('|')})[ \\t]*(?:[:：=][ \\t]*|[为為是][ \\t]*[:：]?[ \\t]*|は[ \\t]*|는[ \\t]*)?`
    + `(?:\\\\?["'“「])?(${SECRET_CH}{3,63}[A-Za-z0-9_\\-/+=~!@#%^&*])`,
    'gid',
  );

const KEY_SEPARATORS = ['为', '為', '是', '：', ':', '=', 'は', '는'];
const QUANTITY_UNITS = [
  '位', '比特', '字节', '字節', '个', '個', '次', '秒', '毫秒', '分钟', '分鐘', '小时', '小時', '天', '年',
  'bit', 'byte', 'ms', 'sec', 'min', 'ビット', 'バイト', '비트', '바이트',
];

/** A key's value: letters and digits both, or 16+ characters that are not all digits. */
const keyValue = (v: string): boolean => {
  if (!notAVariable(v)) return false;
  return /[A-Za-z]/.test(v) && (/\d/.test(v) || v.length >= 16);
};

/** keyValue, or six digits or more right after a separator that count nothing (密钥为12231241). */
const keyAt = (text: string, a: number, b: number): boolean => {
  const v = text.slice(a, b);
  if (pathValue(v) || versionValue(v) || timestampValue(v)) return false;
  if (keyValue(v)) return true;
  if (v.length < 6 || !/^\d+$/.test(v)) return false;
  const before = text.slice(Math.max(0, a - 16), a).replace(/[ \t"'“「\\]+$/, '');
  const after = text.slice(b, b + 16).replace(/^[ \t]+/, '');
  return KEY_SEPARATORS.some(c => before.endsWith(c)) && !QUANTITY_UNITS.some(u => after.startsWith(u));
};

const PATTERN_RULES: readonly PatternRule[] = [
  // --- vendor keys with a recognisable shape --------------------------------
  {
    kind: 'api-key',
    re: new RegExp(`${TOKEN_BEFORE}sk-(?:ant-|proj-|or-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`, 'g'),
    check: notASlug,
  },
  // a gateway's or a relay's own: oc_sk_…, or_sk_…
  {
    kind: 'api-key',
    re: new RegExp(`${TOKEN_BEFORE}[a-z]{2,4}_sk_[A-Za-z0-9_-]{20,}`, 'g'),
    check: secretValue,
  },
  // Volcano Ark and the relays in front of it
  {
    kind: 'api-key',
    re: new RegExp(`${TOKEN_BEFORE}ark-[A-Za-z0-9][A-Za-z0-9_-]{15,}`, 'g'),
    check: secretValue,
  },
  // GitHub ghp_/gho_/ghu_/ghs_/ghr_, fine-grained github_pat_, GitLab glpat-
  {
    kind: 'api-key',
    re: new RegExp(
      `${TOKEN_BEFORE}(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,})`,
      'g',
    ),
  },
  // Google
  { kind: 'api-key', re: new RegExp(`${TOKEN_BEFORE}AIza[0-9A-Za-z_-]{35}${TOKEN_AFTER}`, 'g') },
  // Slack
  { kind: 'api-key', re: new RegExp(`${TOKEN_BEFORE}xox[abposr]-[0-9A-Za-z-]{10,}`, 'g') },
  // Stripe
  { kind: 'api-key', re: new RegExp(`${TOKEN_BEFORE}(?:sk|rk)_live_[0-9A-Za-z]{20,}`, 'g') },
  // AWS access key id
  { kind: 'api-key', re: /(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])/g },
  // Hugging Face, Groq, xAI, npm, PyPI, DigitalOcean, SendGrid
  {
    kind: 'api-key',
    re: new RegExp(
      `${TOKEN_BEFORE}(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|npm_[A-Za-z0-9]{36}${TOKEN_AFTER}`
      + '|pypi-[A-Za-z0-9_-]{50,}|dop_v1_[a-f0-9]{64}|SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43})',
      'g',
    ),
  },
  // Cloudflare: user/account/global/OAuth tokens and the Origin CA key
  { kind: 'api-key', re: new RegExp(`${TOKEN_BEFORE}cf(?:ut|at|k|oat)_[A-Za-z0-9_-]{40,}`, 'g') },
  { kind: 'api-key', re: new RegExp(`${TOKEN_BEFORE}v1\\.0-[A-Za-z0-9]{16,}-[A-Za-z0-9]{40,}`, 'g') },
  // Telegram bot token: 8-10 digits, a colon, 35 characters
  { kind: 'api-key', re: /(?<![0-9A-Za-z_-])\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g },
  // a Cloudflare tunnel token is base64 of {"a":…}; a JWT is three dotted segments
  { kind: 'token', re: new RegExp(`${TOKEN_BEFORE}eyJhIjoi[A-Za-z0-9+/_-]{40,}={0,2}`, 'g') },
  {
    kind: 'token',
    re: new RegExp(`${TOKEN_BEFORE}eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}`, 'g'),
  },

  // --- URL credentials ------------------------------------------------------
  // scheme://user:PASSWORD@host (or ://:PASSWORD@host as Redis has it). The
  // scheme is checked backwards from `://` so the pattern needs no unbounded
  // leading class.
  {
    kind: 'password',
    re: /:\/\/[^\s:@/?#"'<>]*:([^\s@/?#"'<>]{3,})@/gd,
    group: 1,
    check: (v, text, start, end) => notAVariable(v) && hiddenInURL(text, start, end),
  },

  // --- secret assignments ---------------------------------------------------
  // password = …, API_KEY: "…", "token": "…" — the value only
  {
    kind: 'secret',
    re: new RegExp(
      `(?:${SECRET_NAMES})${NAME_TAIL}${QUOTE}[ \\t]*[:=][ \\t]*${QUOTE}(${SECRET_CH}{8,})`,
      'gid',
    ),
    group: 1,
    check: (v, text, start, end) => secretValue(v) && fieldAt(text, start, end),
    skipNextField: true,
  },
  // an env var's name says what it holds in the upper case: SERVICE_X_KEY, DB_PASS
  {
    kind: 'secret',
    re: new RegExp(
      `_(?:KEY|PASS)${QUOTE}[ \\t]*[:=][ \\t]*${QUOTE}(${SECRET_CH}{8,})`,
      'gid',
    ),
    group: 1,
    check: (v, text, start, end) => secretValue(v) && namedSecretAt(text, start, end),
    skipNextField: true,
  },
  // Authorization / Cookie header lines
  {
    kind: 'secret',
    re: /^[ \t]*(?:authorization|cookie)[ \t]*:[ \t]*(\S[^\r\n]{7,})/gimd,
    group: 1,
    check: headerValue,
  },
  // a password after its name in Chinese, Japanese or Korean (密码：786kih)
  {
    kind: 'password',
    re: cjkNamed(CJK_PASSWORD_NAMES),
    group: 1,
    check: notAVariable,
  },
  // a key, secret or token after its name (密钥为 …, 令牌是 …)
  {
    kind: 'secret',
    re: cjkNamed(CJK_KEY_NAMES),
    group: 1,
    check: (_v, text, start, end) => keyAt(text, start, end),
  },

  // --- crypto wallet keys ---------------------------------------------------
  // 0x + 64 hex (or 64 hex alone), only after a name that says it is a key
  {
    kind: 'private-key',
    re: /(?<![A-Za-z0-9])(?:0x[0-9a-fA-F]{56,64}|[0-9a-fA-F]{64})(?![A-Za-z0-9])/g,
    check: (_v, text, start) => walletKeyAt(text, start),
  },
  // WIF: base58check, 51 or 52 characters
  {
    kind: 'private-key',
    re: /(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{51,52}(?![A-Za-z0-9])/g,
    check: wifKey,
  },
  // BIP-0032 extended private key (an xpub is public and stays)
  {
    kind: 'private-key',
    re: /(?<![A-Za-z0-9])[xyztuvYZUV]prv[1-9A-HJ-NP-Za-km-z]{107}(?![A-Za-z0-9])/g,
    check: bip32Key,
  },
  // prefixes no other value has
  { kind: 'private-key', re: /(?<![A-Za-z0-9])suiprivkey1[0-9a-z]{58}(?![A-Za-z0-9])/g },
  { kind: 'private-key', re: /(?<![A-Za-z0-9])(?:ed25519|secp256k1)-priv-0x[0-9a-fA-F]{64}(?![A-Za-z0-9])/g },
  { kind: 'private-key', re: /(?<![A-Za-z0-9])nsec1[02-9ac-hj-np-z]{58}(?![A-Za-z0-9])/g },
  { kind: 'private-key', re: /(?<![A-Za-z0-9])AGE-SECRET-KEY-1[0-9A-Z]{58}(?![A-Za-z0-9])/g },
  { kind: 'private-key', re: /(?<![A-Za-z0-9])secret-extended-key-(?:main|test)1[0-9a-z]{150,320}(?![A-Za-z0-9])/g },

  // --- personal financial identifiers (checksummed) -------------------------
  // 13-19 digits starting with 3-6, Luhn-valid: either contiguous, or grouped in
  // fours (or an Amex 4-6-5) with one consistent separator. Mixed grouping is
  // rejected: the production audit (2026-11-13) hit "39088169 63245986", two
  // Fibonacci numbers that happen to pass Luhn once the space is dropped.
  {
    kind: 'bank-card',
    re: /(?<![0-9A-Za-z])(?:3[47]\d{2}([ -])\d{6}\1\d{5}|[3-6]\d{3}([ -])\d{4}(?:\2\d{4}){1,2}(?:\2\d{1,3})?|[3-6]\d{12,18})(?![0-9A-Za-z])/g,
    check: v => luhn(v.replace(/[ -]/g, '')),
  },
  // 18-character Chinese resident ID, region + date + sequence + check digit
  {
    kind: 'cn-id',
    re: /(?<![0-9A-Za-z])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![0-9A-Za-z])/g,
    check: chineseID,
  },
];

/** The scheme before `://` must be a URL scheme: letters, digits, + . - and a leading letter. */
const hasSchemeBefore = (text: string, at: number): boolean => {
  let i = at;
  while (i > 0 && at - i < 32 && /[A-Za-z0-9+.-]/.test(text[i - 1]!)) i--;
  return i < at && /[A-Za-z]/.test(text.slice(i, at));
};

// ---------------------------------------------------------------------------
// PEM / SSH private keys, scanned without a lazy `[\s\S]+?` so a text with
// many BEGIN lines and no END cannot go quadratic.
// ---------------------------------------------------------------------------

const PEM_BEGIN = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_END = /-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;
// A BEGIN with no END (a truncated paste) still leaks the base64 body that follows.
const PEM_BODY_LINE = /^(?:[A-Za-z0-9+/=]{16,}|[A-Za-z-]+:[^\r\n]*)$/;

const truncatedPemEnd = (text: string, bodyStart: number): number => {
  let stop = bodyStart;
  let p = bodyStart;
  while (p < text.length) {
    const nl = text.indexOf('\n', p);
    if (nl < 0) break;
    const lineStart = nl + 1;
    const lineEndRaw = text.indexOf('\n', lineStart);
    const lineEnd = lineEndRaw < 0 ? text.length : lineEndRaw;
    const line = text.slice(lineStart, lineEnd).trim();
    if (line === '' || !PEM_BODY_LINE.test(line)) break;
    stop = lineStart + text.slice(lineStart, lineEnd).trimEnd().length;
    p = lineEnd;
  }
  return stop;
};

const collectPrivateKeyBlocks = (text: string, spans: RedactSpan[]): void => {
  if (!text.includes('PRIVATE KEY')) return;
  const ends: Array<[number, number]> = [];
  PEM_END.lastIndex = 0;
  for (let m = PEM_END.exec(text); m; m = PEM_END.exec(text)) ends.push([m.index, m.index + m[0].length]);

  let cursor = 0;
  let endIdx = 0;
  PEM_BEGIN.lastIndex = 0;
  for (let m = PEM_BEGIN.exec(text); m; m = PEM_BEGIN.exec(text)) {
    if (m.index < cursor) continue;
    const bodyStart = m.index + m[0].length;
    while (endIdx < ends.length && ends[endIdx]![0] < bodyStart) endIdx++;
    let stop: number;
    if (endIdx < ends.length) {
      stop = ends[endIdx]![1];
    } else {
      stop = truncatedPemEnd(text, bodyStart);
    }
    spans.push({ start: m.index, end: stop, kind: 'private-key' });
    cursor = stop;
    PEM_BEGIN.lastIndex = stop;
  }
};

// ---------------------------------------------------------------------------
// BIP-0039 seed phrases: 12/15/18/21/24 consecutive English words.
// ---------------------------------------------------------------------------

const BIP39 = new Set<string>(wordlist);
const PHRASE_LENGTHS = [24, 21, 18, 15, 12] as const;
// Runs of words (3-8 letters, as the list has them) separated by blanks only.
const WORD_RUN = /(?<![A-Za-z0-9_])(?:[A-Za-z]{3,8}(?![A-Za-z0-9_])[ \t]+)*[A-Za-z]{3,8}(?![A-Za-z0-9_])/g;

const collectSeedPhrases = (text: string, spans: RedactSpan[]): void => {
  WORD_RUN.lastIndex = 0;
  for (let m = WORD_RUN.exec(text); m; m = WORD_RUN.exec(text)) {
    if (m[0].length < 12 * 3 + 11) continue;
    const words: Array<{ start: number; end: number; ok: boolean }> = [];
    const wre = /[A-Za-z]+/g;
    for (let w = wre.exec(m[0]); w; w = wre.exec(m[0])) {
      words.push({
        start: m.index + w.index,
        end: m.index + w.index + w[0].length,
        ok: BIP39.has(w[0].toLowerCase()),
      });
    }
    let i = 0;
    while (i < words.length) {
      if (!words[i]!.ok) {
        i++;
        continue;
      }
      let j = i;
      while (j < words.length && words[j]!.ok) j++;
      const run = j - i;
      const len = PHRASE_LENGTHS.find(l => run >= l);
      if (len !== undefined) {
        spans.push({ start: words[i]!.start, end: words[i + len - 1]!.end, kind: 'seed-phrase' });
        i += len;
      } else {
        i = j;
      }
    }
  }
};

// ---------------------------------------------------------------------------
// Protected spans.
// ---------------------------------------------------------------------------

const PROTECTED_PATTERNS: readonly RegExp[] = [
  // Feishu open_id / union_id / chat id / message id
  /(?<![A-Za-z0-9_])(?:ou|on|oc|om)_[0-9a-f]{8,}(?![A-Za-z0-9])/g,
  // file / image keys
  /(?<![A-Za-z0-9_])(?:file|img)_v\d_[A-Za-z0-9_-]{4,}(?![A-Za-z0-9_-])/g,
  // rendered message alias: `m` + 9 base36 characters
  /(?<![A-Za-z0-9_-])m[0-9a-z]{9}(?![A-Za-z0-9_-])/g,
  // UUID
  /(?<![0-9A-Za-z-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9A-Za-z-])/gi,
  // git SHA-1
  /(?<![0-9A-Za-z_-])[0-9a-f]{40}(?![0-9A-Za-z_-])/g,
];

// The rendering layer's tags that carry attributes; `<a href>` and `<pre>` are
// user content and stay out. Attribute values are XML-escaped, so `[^"]*` is safe
// and the loop has no ambiguity to backtrack through.
const CHATLOG_TAG = /<(?:message|mention|in-reply-to|attachment|event|plugin-event|runtime-event|omitted|custom-emoji)(?:[ \t\r\n]+[A-Za-z_:][\w:.-]*="[^"]*")*[ \t\r\n]*\/?>/g;
const ATTR_VALUE = /[ \t\r\n][A-Za-z_:][\w:.-]*="([^"]*)"/g;

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------

const collectPattern = (rule: PatternRule, text: string, spans: RedactSpan[]): void => {
  const { re } = rule;
  const group = rule.group ?? 0;
  re.lastIndex = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    let start: number;
    let end: number;
    if (group === 0) {
      start = m.index;
      end = m.index + m[0].length;
    } else {
      const idx = (m as RegExpExecArray & { indices?: Array<[number, number] | undefined> }).indices?.[group];
      if (!idx) throw new Error(`redact rule for ${rule.kind} needs the d flag to read capture group ${group}`);
      [start, end] = idx;
    }
    if (m[0].length === 0) re.lastIndex++;
    // A URL password match must follow a scheme; the pattern itself anchors on `://`.
    if (rule.kind === 'password' && m[0].startsWith('://') && !hasSchemeBefore(text, m.index)) {
      re.lastIndex = m.index + 3;
      continue;
    }
    // The value is the next field's assignment (UI_PASSWORD= UI_ADDR=1.2.3.4):
    // the name was set to nothing, so read the next field on its own.
    if (
      rule.skipNextField
      && start > 0
      && (text[start - 1] === ' ' || text[start - 1] === '\t')
      && nextFieldRe.test(text.slice(start, Math.min(text.length, start + 200)))
    ) {
      re.lastIndex = start;
      continue;
    }
    if (rule.check && !rule.check(text.slice(start, end), text, start, end)) {
      // Keep scanning just after the start of this match so that overlapping
      // candidates (a shorter, valid one inside a rejected one) are not lost.
      re.lastIndex = Math.max(re.lastIndex - (end - start) + 1, m.index + 1);
      continue;
    }
    spans.push({ start, end, kind: rule.kind });
  }
};

// On a tie in start and length the more specific kind wins.
const KIND_PRIORITY: Record<RedactKind, number> = {
  'private-key': 0,
  'api-key': 1,
  token: 2,
  'bank-card': 3,
  'cn-id': 4,
  'seed-phrase': 5,
  password: 6,
  secret: 7,
};

/** Every span the rules would redact, before protected spans are applied. */
export const findSecretCandidates = (text: string): RedactSpan[] => {
  if (text.length < 8) return [];
  const spans: RedactSpan[] = [];
  collectPrivateKeyBlocks(text, spans);
  for (const rule of PATTERN_RULES) collectPattern(rule, text, spans);
  collectSeedPhrases(text, spans);
  return spans;
};

/**
 * Spans that must never change, whatever a rule thinks of them: platform ids,
 * file keys, rendered message aliases, every attribute value of a chatlog tag,
 * UUIDs and 40-hex git SHAs. A candidate that overlaps one is dropped.
 * A UUID or SHA right after a secret's name is therefore kept too; that is the
 * price of never rewriting an id.
 */
export const findProtectedSpans = (text: string): Array<[number, number]> => {
  const out: Array<[number, number]> = [];
  if (text.length < 8) return out;
  for (const re of PROTECTED_PATTERNS) {
    re.lastIndex = 0;
    for (let m = re.exec(text); m; m = re.exec(text)) out.push([m.index, m.index + m[0].length]);
  }
  CHATLOG_TAG.lastIndex = 0;
  for (let t = CHATLOG_TAG.exec(text); t; t = CHATLOG_TAG.exec(text)) {
    ATTR_VALUE.lastIndex = 0;
    for (let a = ATTR_VALUE.exec(t[0]); a; a = ATTR_VALUE.exec(t[0])) {
      const start = t.index + a.index + a[0].indexOf('"') + 1;
      out.push([start, start + (a[1]?.length ?? 0)]);
    }
  }
  out.sort((x, y) => x[0] - y[0] || y[1] - x[1]);
  const merged: Array<[number, number]> = [];
  for (const [start, end] of out) {
    const last = merged[merged.length - 1];
    if (last && start <= last[1]) {
      if (end > last[1]) last[1] = end;
    } else {
      merged.push([start, end]);
    }
  }
  return merged;
};

const overlapsAny = (protectedSpans: ReadonlyArray<[number, number]>, start: number, end: number): boolean => {
  let lo = 0;
  let hi = protectedSpans.length;
  // first protected span whose end is after `start`
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (protectedSpans[mid]![1] <= start) lo = mid + 1;
    else hi = mid;
  }
  return lo < protectedSpans.length && protectedSpans[lo]![0] < end;
};

/** Spans to redact, sorted and merged (overlapping spans keep the first kind). */
export const findSecrets = (text: string): RedactSpan[] => {
  const candidates = findSecretCandidates(text);
  if (candidates.length === 0) return candidates;
  const protectedSpans = findProtectedSpans(text);
  const spans = protectedSpans.length === 0
    ? candidates
    : candidates.filter(c => !overlapsAny(protectedSpans, c.start, c.end));
  if (spans.length === 0) return spans;

  const ordered = [...spans].sort((a, b) =>
    a.start - b.start || b.end - a.end || KIND_PRIORITY[a.kind] - KIND_PRIORITY[b.kind]);
  const merged: RedactSpan[] = [];
  for (const s of ordered) {
    const last = merged[merged.length - 1];
    if (last && s.start < last.end) {
      if (s.end > last.end) last.end = s.end;
    } else {
      merged.push({ ...s });
    }
  }
  return merged;
};

export interface RedactHit {
  kind: RedactKind;
  length: number;
  /** First 8 hex digits of the SHA-256 of the matched text; the text itself is never exposed. */
  hash: string;
}

/** What `redactSecrets` would remove, described without the matched text. */
export const describeSecrets = (text: string): RedactHit[] =>
  findSecrets(text).map(s => ({
    kind: s.kind,
    length: s.end - s.start,
    hash: createHash('sha256').update(text.slice(s.start, s.end)).digest('hex').slice(0, 8),
  }));

/**
 * Replaces credentials and secret material with `[redacted:<kind>]`. Pure and
 * deterministic; returns the very same string when nothing matched.
 */
export const redactSecrets = (text: string): string => {
  const spans = findSecrets(text);
  if (spans.length === 0) return text;
  let out = '';
  let at = 0;
  for (const s of spans) {
    out += text.slice(at, s.start) + marker(s.kind);
    at = s.end;
  }
  return out + text.slice(at);
};
