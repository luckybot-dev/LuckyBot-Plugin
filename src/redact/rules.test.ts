import { describe, expect, it } from 'vitest';

import { describeSecrets, findProtectedSpans, findSecretCandidates, findSecrets, redactSecrets } from './rules';

// Fake credentials are assembled from parts so that no scanner mistakes this
// file for a leak.
const MIXED = 'Ab3dE5gH7jK9mN1pQ3sT5vX7zB2cD4fG6hJ8';

describe('vendor keys', () => {
  const cases: Array<[string, string, string]> = [
    ['OpenAI', `sk-${MIXED}${MIXED}`, 'api-key'],
    ['OpenAI project', `sk-proj-${MIXED}_${MIXED}`, 'api-key'],
    ['Anthropic', `sk-ant-api03-${MIXED}${MIXED}-AAAA`, 'api-key'],
    ['GitHub ghp', `ghp_${MIXED}`, 'api-key'],
    ['GitHub gho', `gho_${MIXED}`, 'api-key'],
    ['GitHub ghu', `ghu_${MIXED}`, 'api-key'],
    ['GitHub ghs', `ghs_${MIXED}`, 'api-key'],
    ['GitHub ghr', `ghr_${MIXED}`, 'api-key'],
    ['GitHub fine-grained', `github_pat_${MIXED}${MIXED}`, 'api-key'],
    ['GitLab', `glpat-${MIXED.slice(0, 24)}`, 'api-key'],
    ['Slack bot', 'xoxb' + '-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx', 'api-key'],
    ['Slack user', 'xoxp' + '-123456789012-123456789012-AbCdEfGh', 'api-key'],
    ['AWS access key', 'AKIA' + 'IOSFODNN7EXAMPLE', 'api-key'],
    ['AWS temporary key', 'ASIA' + 'IOSFODNN7EXAMPLE', 'api-key'],
    ['Google', 'AIza' + 'SyA-1234567890abcdefghijklmnopqrstu', 'api-key'],
    ['Stripe secret', 'sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc', 'api-key'],
    ['Stripe restricted', 'rk_live_' + '4eC39HqLyjWDarjtT1zdp7dc', 'api-key'],
    ['Telegram bot', '123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw0', 'api-key'],
    ['npm', `npm_${MIXED}`, 'api-key'],
    ['Hugging Face', `hf_${MIXED}`, 'api-key'],
    ['JWT', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk', 'token'],
  ];
  for (const [name, secret, kind] of cases) {
    it(`redacts ${name}`, () => {
      expect(redactSecrets(`key: use ${secret} here`)).toBe(`key: use [redacted:${kind}] here`);
      expect(redactSecrets(secret)).toBe(`[redacted:${kind}]`);
    });
  }

  it('leaves a hyphenated slug that starts with sk-', () => {
    const slug = 'sk-learn-the-basics-of-machine-learning-today';
    expect(redactSecrets(slug)).toBe(slug);
  });

  it('does not match a token glued into a longer word', () => {
    const s = `xghp_${MIXED}`;
    expect(redactSecrets(s)).toBe(s);
  });
});

describe('private keys', () => {
  const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n';

  it('redacts a PEM block as a whole', () => {
    const pem = `-----BEGIN PRIVATE KEY-----\n${body}-----END PRIVATE KEY-----`;
    expect(redactSecrets(`before\n${pem}\nafter`)).toBe('before\n[redacted:private-key]\nafter');
  });

  it('redacts RSA, EC and OpenSSH blocks', () => {
    for (const label of ['RSA PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY']) {
      const pem = `-----BEGIN ${label}-----\n${body}-----END ${label}-----`;
      expect(redactSecrets(pem)).toBe('[redacted:private-key]');
    }
  });

  it('redacts a truncated block whose END is missing', () => {
    const out = redactSecrets(`-----BEGIN RSA PRIVATE KEY-----\n${body}\nthanks`);
    expect(out).toBe('[redacted:private-key]\n\nthanks');
  });

  it('leaves public keys and certificates', () => {
    const pub = `-----BEGIN PUBLIC KEY-----\n${body}-----END PUBLIC KEY-----`;
    expect(redactSecrets(pub)).toBe(pub);
  });

  it('redacts a wallet key after a name that says so, not a bare hash', () => {
    const hex = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
    expect(redactSecrets(`private key: 0x${hex}`)).toBe('private key: [redacted:private-key]');
    expect(redactSecrets(`私钥：${hex}`)).toBe('私钥：[redacted:private-key]');
    expect(redactSecrets(`commit hash ${hex}`)).toBe(`commit hash ${hex}`);
    expect(redactSecrets(`sha256: ${hex}`)).toBe(`sha256: ${hex}`);
    expect(redactSecrets(`tx hash ${hex}`)).toBe(`tx hash ${hex}`);
  });

  it('redacts a WIF key and an extended private key by checksum', () => {
    expect(redactSecrets('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')).toBe('[redacted:private-key]');
    expect(redactSecrets('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTK')).toBe(
      '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTK',
    );
  });
});

describe('url credentials', () => {
  it('keeps scheme, user and host, drops the password', () => {
    expect(redactSecrets('postgres://app:hunter2pass@db.acme-corp.cn:5432/x')).toBe(
      'postgres://app:[redacted:password]@db.acme-corp.cn:5432/x',
    );
    expect(redactSecrets('REDIS_URL=redis://:r3disPass@cache.acme-corp.cn:6379/0')).toBe(
      'REDIS_URL=redis://:[redacted:password]@cache.acme-corp.cn:6379/0',
    );
    expect(redactSecrets('postgresql://geo:Tr0ub4dor3@10.0.0.5/geodata')).toBe(
      'postgresql://geo:[redacted:password]@10.0.0.5/geodata',
    );
  });

  it('keeps a password that is also written elsewhere in the URL (magpie)', () => {
    for (const s of [
      'postgres://postgres:postgres@localhost:5432/app',
      'mysql://root:root@127.0.0.1/shop',
      'amqp://guest:guest@rabbit:5672/',
      'mysql://app:shopdb@db.internal/shopdb?ssl=true',
      'redis://:cachebox@cachebox:6379/0',
      '"url": "postgresql://geo:geo@db/geo"',
    ]) {
      expect(redactSecrets(s)).toBe(s);
    }
  });

  it('keeps a URL without credentials, and one with only a user or a port', () => {
    for (const s of [
      'https://example.com/path?q=1',
      'https://example.com:8443/a',
      'ssh://git@github.com/luckybot-dev/LuckyBot.git',
      'http://localhost:3000/',
    ]) {
      expect(redactSecrets(s)).toBe(s);
    }
  });

  it('keeps a placeholder password', () => {
    for (const s of ['postgres://user:${DB_PASS}@host/db', 'postgres://user:<password>@host/db', 'postgres://user:****@host/db']) {
      expect(redactSecrets(s)).toBe(s);
    }
  });
});

describe('secret assignments', () => {
  it('keeps the key and replaces the value', () => {
    expect(redactSecrets('password = hunter2pass99')).toBe('password = [redacted:secret]');
    expect(redactSecrets('API_KEY=abc123def456ghi789')).toBe('API_KEY=[redacted:secret]');
    expect(redactSecrets('"token": "a1b2c3d4e5f6a7b8"')).toBe('"token": "[redacted:secret]"');
    expect(redactSecrets('client_secret: Zx9Yw8Vu7Ts6Rq5')).toBe('client_secret: [redacted:secret]');
    expect(redactSecrets('app-secret=Zx9Yw8Vu7Ts6Rq5')).toBe('app-secret=[redacted:secret]');
    expect(redactSecrets('access_key = Zx9Yw8Vu7Ts6Rq5')).toBe('access_key = [redacted:secret]');
    expect(redactSecrets('AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')).toBe(
      'AWS_SECRET_ACCESS_KEY=[redacted:secret]',
    );
  });

  it('handles several assignments in one text', () => {
    expect(redactSecrets('DB_PASSWORD=Pa55w0rdXYZ12 and SERVICE_X_KEY=Zx9Yw8Vu7Ts6Rq5')).toBe(
      'DB_PASSWORD=[redacted:secret] and SERVICE_X_KEY=[redacted:secret]',
    );
  });

  it('keeps names for secrets, placeholders and prose', () => {
    for (const s of [
      'password = process.env.PASSWORD',
      'token = ${GITHUB_TOKEN}',
      'password: <your-password>',
      'password = ********',
      'the password is secret',
      'token = refreshToken2',
      'secret = fromBase64(input)',
      'sort_key=abc123def456ghi789',
      'cwd=/tmp pwd=/home/user',
      'password: short',
    ]) {
      expect(redactSecrets(s)).toBe(s);
    }
  });

  it('does not take the next assignment for a value', () => {
    const s = 'UI_PASSWORD= UI_ADDR=1.2.3.4';
    expect(redactSecrets(s)).toBe(s);
  });

  it('redacts Authorization and Cookie header values', () => {
    expect(redactSecrets('Authorization: Bearer abcdef1234567890xyz')).toBe('Authorization: [redacted:secret]');
    expect(redactSecrets('Cookie: sid=abc123; theme=dark')).toBe('Cookie: [redacted:secret]');
  });

  it('redacts a password after its name in Chinese, Japanese and Korean', () => {
    expect(redactSecrets('密码：786kih')).toBe('密码：[redacted:password]');
    expect(redactSecrets('我的密码是 Abc12345')).toBe('我的密码是 [redacted:password]');
    expect(redactSecrets('パスワード: Abc12345')).toBe('パスワード: [redacted:password]');
    expect(redactSecrets('비밀번호: Abc12345')).toBe('비밀번호: [redacted:password]');
  });

  it('redacts a key after its name in Chinese and keeps quantities', () => {
    expect(redactSecrets('密钥为 Ab12Cd34Ef56Gh78')).toBe('密钥为 [redacted:secret]');
    expect(redactSecrets('密钥为12231241')).toBe('密钥为[redacted:secret]');
    expect(redactSecrets('密钥长度为256位')).toBe('密钥长度为256位');
  });
});

describe('seed phrases', () => {
  const twelve = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  it('redacts 12 consecutive BIP-0039 words, with or without a cue', () => {
    expect(redactSecrets(twelve)).toBe('[redacted:seed-phrase]');
    expect(redactSecrets(`my seed phrase: ${twelve}.`)).toBe('my seed phrase: [redacted:seed-phrase].');
  });

  it('redacts 24 words as a single span', () => {
    const w24 = `${twelve} ${twelve}`;
    expect(redactSecrets(w24)).toBe('[redacted:seed-phrase]');
  });

  it('does not redact eleven words, nor ordinary prose', () => {
    const eleven = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
    expect(redactSecrets(eleven)).toBe(eleven);
    const prose = 'the quick brown fox jumps over the lazy dog while the sun is shining on all of us today';
    expect(redactSecrets(prose)).toBe(prose);
  });
});

describe('financial identifiers', () => {
  it('redacts Luhn-valid cards, plain, spaced and dashed', () => {
    expect(redactSecrets('card 4111111111111111 ok')).toBe('card [redacted:bank-card] ok');
    expect(redactSecrets('card 4111 1111 1111 1111 ok')).toBe('card [redacted:bank-card] ok');
    expect(redactSecrets('card 4111-1111-1111-1111')).toBe('card [redacted:bank-card]');
    expect(redactSecrets('amex 378282246310005')).toBe('amex [redacted:bank-card]');
    expect(redactSecrets('银联 6222021234567890128')).toBe('银联 [redacted:bank-card]');
    expect(redactSecrets('amex 3782 822463 10005')).toBe('amex [redacted:bank-card]');
  });

  it('does not join numbers with mixed grouping into a card', () => {
    // From the production audit: consecutive Fibonacci numbers, Luhn-valid once joined.
    const fib = '14930352\n24157817 39088169 63245986 102334155 165580141';
    expect(redactSecrets(fib)).toBe(fib);
    expect(redactSecrets('4111 1111-1111 1111')).toBe('4111 1111-1111 1111');
  });

  it('keeps Luhn-invalid digit runs', () => {
    for (const s of ['4111111111111112', '4111 1111 1111 1112', '1234567890123456', '1792903687123', '12345678901234567890']) {
      expect(redactSecrets(s)).toBe(s);
    }
  });

  it('redacts a checksum-valid Chinese resident ID and keeps an invalid one', () => {
    expect(redactSecrets('身份证 11010519491231002X')).toBe('身份证 [redacted:cn-id]');
    expect(redactSecrets('身份证 110105194912310021')).toBe('身份证 110105194912310021');
    expect(redactSecrets('110105194912310029')).toBe('110105194912310029');
  });
});

describe('never redacted', () => {
  const keep = [
    'ou_7d8a6e3b1c9f4a5d2e8b7c6a5d4e3f21',
    'om_dc1f2a8b6e4c5d7a9f3b2e1c8d6a4b5f',
    'oc_a1b2c3d4e5f60718293a4b5c6d7e8f90',
    'm4f8a2c01x',
    'img_v3_02a1_0f3e1c2d-4b5a-4c6d-8e7f-9a0b1c2d3e4f',
    'file_v3_00a1_5c6d7e8f',
    '550e8400-e29b-41d4-a716-446655440000',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '9e4240b3f1a2c8d7e6b5a4938271605f4e3d2c1b',
    'call_9KfLmN3pQrStUvWx',
    'toolu_01A09q90qw90lq917835lq9',
    'alice@example.com',
    '+86 138 0013 8000',
    '13800138000',
    '192.168.1.100',
    '2001:db8::ff00:42:8329',
    'https://github.com/luckybot-dev/LuckyBot/pull/34',
    'https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id',
    '张伟 说今天下午三点开会',
    '1792903687123',
    '2026-11-13T20:05:11Z',
  ];
  for (const s of keep) {
    it(`keeps ${s.slice(0, 40)}`, () => {
      expect(redactSecrets(s)).toBe(s);
    });
  }

  it('keeps a rendered Feishu chatlog snippet byte-identical', () => {
    const snippet = [
      '<message id="m4f8a2c01" sender="张伟" uid="ou_7d8a6e3b1c9f4a5d2e8b7c6a5d4e3f21" t="11-13 20:05:11">',
      '  @莱克 明天的会议室是 3F-A07，链接 https://vc.feishu.cn/j/123456789 ，手机 13800138000，邮箱 zw@example.com',
      '</message>',
      '<message id="m9c3d7e21" sender="莱克" myself="true" t="11-13 20:05:20" received="11-13 20:05:40">',
      '  <in-reply-to id="m4f8a2c01"/>好的，我记下了，commit 9e4240b 已经合并',
      '  <attachment file-id="mb1c2d3e4f" type="image" key="img_v3_02a1_0f3e1c2d-4b5a-4c6d-8e7f-9a0b1c2d3e4f"/>',
      '  <mention uid="ou_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">@张伟</mention>',
      '</message>',
    ].join('\n');
    expect(redactSecrets(snippet)).toBe(snippet);
  });

  it('redacts a secret inside a chatlog without touching the markup', () => {
    const msg = `<message id="m4f8a2c01" sender="张伟" uid="ou_7d8a6e3b1c9f4a5d2e8b7c6a5d4e3f21" t="11-13 20:05:11">我的 key 是 ghp_${  MIXED  } 帮我看看</message>`;
    expect(redactSecrets(msg)).toBe(
      '<message id="m4f8a2c01" sender="张伟" uid="ou_7d8a6e3b1c9f4a5d2e8b7c6a5d4e3f21" t="11-13 20:05:11">我的 key 是 [redacted:api-key] 帮我看看</message>',
    );
  });
});

describe('protected spans', () => {
  const card = '4111111111111111';
  const apiKey = `ghp_${MIXED}`;

  it('would redact these inputs without protection (guards the tests below)', () => {
    for (const s of [`ou_${card}`, `om_${card}`, `oc_${card}`, `on_${card}`, `img_v3_${card}`, `file_v2_${card}`]) {
      expect(findSecretCandidates(s).length, s).toBeGreaterThan(0);
    }
  });

  it('keeps ids and file keys even when a rule matches inside them', () => {
    for (const s of [`ou_${card}`, `om_${card}`, `oc_${card}`, `on_${card}`, `img_v3_${card}`, `file_v2_${card}`]) {
      expect(redactSecrets(`see ${s} please`)).toBe(`see ${s} please`);
    }
  });

  it('keeps every attribute value in a chatlog tag, and still redacts the body', () => {
    const tag = `<message id="m4f8a2c01" sender="token=${MIXED}" uid="ou_${card}" t="11-13 20:05:11">`;
    expect(redactSecrets(tag)).toBe(tag);
    const attach = `<attachment file-id="m4f8a2c01" key="img_v3_${card}" name="password=hunter2pass99.png"/>`;
    expect(redactSecrets(attach)).toBe(attach);
    const mention = `<mention uid="ou_${card}">@${apiKey}</mention>`;
    expect(redactSecrets(mention)).toBe(`<mention uid="ou_${card}">@[redacted:api-key]</mention>`);
    const reply = `<in-reply-to id="m4f8a2c01" sender="api_key=${MIXED}">x</in-reply-to>`;
    expect(redactSecrets(reply)).toBe(reply);
  });

  it('does not treat other markup as chatlog markup', () => {
    expect(redactSecrets('<a href="https://u:Pa55word12@host/x">l</a>')).toBe('<a href="https://u:[redacted:password]@host/x">l</a>');
  });

  it('keeps UUIDs and 40-hex SHAs, and rendered aliases', () => {
    const uuid = '41111111-1111-1111-1111-111111111111';
    const sha = '4111111111111111111111111111111111111111';
    expect(redactSecrets(`id ${uuid} sha ${sha}`)).toBe(`id ${uuid} sha ${sha}`);
    expect(redactSecrets('reply to m4f8a2c01x and mabc123def')).toBe('reply to m4f8a2c01x and mabc123def');
  });

  it('drops a candidate that merely overlaps a protected span', () => {
    const s = `password=${MIXED} <message id="m4f8a2c01">`;
    expect(redactSecrets(s)).toBe('password=[redacted:secret] <message id="m4f8a2c01">');
    expect(findProtectedSpans(s)).toEqual([[s.indexOf('m4f8a2c01'), s.indexOf('m4f8a2c01') + 9]]);
  });

  it('does not let a protected id stop a real secret next to it', () => {
    expect(redactSecrets(`ou_7d8a6e3b1c9f4a5d2e8b7c6a5d4e3f21 sent ${apiKey}`)).toBe(
      'ou_7d8a6e3b1c9f4a5d2e8b7c6a5d4e3f21 sent [redacted:api-key]',
    );
  });
});

describe('describeSecrets', () => {
  it('reports kind, length and an 8-char hash, never the text', () => {
    const secret = `ghp_${MIXED}`;
    const hits = describeSecrets(`a ${secret} b`);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ kind: 'api-key', length: secret.length });
    expect(hits[0]!.hash).toMatch(/^[0-9a-f]{8}$/);
    expect(JSON.stringify(hits)).not.toContain(MIXED);
    expect(describeSecrets(`x ${secret}`)[0]!.hash).toBe(hits[0]!.hash);
  });
});

describe('behaviour', () => {
  it('is deterministic and idempotent', () => {
    const text = `password=hunter2pass99 and ghp_${MIXED} and 4111111111111111`;
    const once = redactSecrets(text);
    expect(redactSecrets(text)).toBe(once);
    expect(redactSecrets(once)).toBe(once);
  });

  it('returns the same string when nothing matches', () => {
    const text = 'nothing to see here, just a chat message';
    expect(redactSecrets(text)).toBe(text);
    expect(redactSecrets('')).toBe('');
  });

  it('reports sorted, non-overlapping spans', () => {
    const text = `x ghp_${MIXED} y password=hunter2pass99 z`;
    const spans = findSecrets(text);
    expect(spans.map(s => s.kind)).toEqual(['api-key', 'secret']);
    for (let i = 1; i < spans.length; i++) expect(spans[i]!.start).toBeGreaterThanOrEqual(spans[i - 1]!.end);
  });

  it('stays fast on 500 KB of hostile and ordinary input', () => {
    const inputs: Record<string, string> = {
      prose: 'Hello world, this is a normal chat message with 张伟 and some digits 12345 ok. '.repeat(7000),
      dashes: `sk-${  'a-'.repeat(250_000)}`,
      digits: '4111 '.repeat(100_000),
      words: 'abandon '.repeat(60_000),
      colons: 'password: '.repeat(50_000),
      slashes: `://${  ':a'.repeat(250_000)}`,
      begins: '-----BEGIN PRIVATE KEY-----\n'.repeat(18_000),
      spaces: `token${  ' '.repeat(500_000)}`,
      names: 'A'.repeat(500_000),
      hex: '0123456789abcdef'.repeat(31_000),
      mixed: `ghp_${MIXED} password=hunter2pass99 postgres://u:Pa55word12@h/d `.repeat(8000),
    };
    for (const [name, input] of Object.entries(inputs)) {
      const t0 = performance.now();
      redactSecrets(input);
      const ms = performance.now() - t0;
      expect(ms, `${name} took ${ms.toFixed(0)} ms`).toBeLessThan(1500);
    }
  });
});
