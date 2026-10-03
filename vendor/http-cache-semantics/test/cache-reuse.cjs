// Regression coverage for GHSA-ch52-4w7c-c8xp. No network or timers are needed.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createRequire } = require('node:module');
const path = require('node:path');
const websiteRequire = createRequire(path.resolve(__dirname, '../../../apps/website/package.json'));
const astroRequire = createRequire(websiteRequire.resolve('astro'));
// Exercise what Astro loads, so a broken override cannot leave these tests green.
const CachePolicy = astroRequire('http-cache-semantics');

test('Astro resolves to the reviewed local backport', () => {
  assert.equal(CachePolicy, require('../index.js'));
});

function request(cacheControl, extra = {}) {
  return {
    url: 'https://example.invalid/account',
    method: 'GET',
    headers: { host: 'example.invalid', 'cache-control': cacheControl, ...extra },
  };
}

function policy(cacheControl, extra = {}, options = {}, initialRequest = request('')) {
  const result = new CachePolicy(initialRequest, {
    status: 200,
    headers: { 'cache-control': cacheControl, ...extra },
  }, options);
  // The response is 10 seconds old. Control the clock instead of sleeping.
  const storedAt = result._responseTime;
  result.now = () => storedAt + 10_000;
  return result;
}

const restrictions = [
  ['shared Set-Cookie', 'max-age=60', { 'set-cookie': 'session=user-a' }],
  ['proxy-revalidate', 'max-age=60, proxy-revalidate'],
  ['no-cache', 'max-age=60, no-cache'],
  ['no-store', 'max-age=60, no-store'],
  ['private in shared cache', 'max-age=60, private'],
  ['must-revalidate', 'max-age=1, must-revalidate'],
];

for (const [label, cacheControl, headers] of restrictions) {
  for (const directive of ['max-stale', 'max-stale=3600']) {
    test(`${label} cannot be bypassed by ${directive}`, () => {
      const cached = policy(cacheControl, headers);
      const req = request(directive);
      assert.equal(cached.satisfiesWithoutRevalidation(req), false);
      const result = cached.evaluateRequest(req);
      assert.equal(result.response, undefined, 'must not expose cached response headers');
      assert.equal(result.revalidation.synchronous, true);
    });
  }
  test(`${label} cannot bypass restrictions via stale-while-revalidate`, () => {
    const cached = policy(`${cacheControl}, stale-while-revalidate=3600`, headers);
    assert.equal(cached.evaluateRequest(request('')).response, undefined);
  });
}

test('authenticated responses without a shared-cache opt-in cannot be reused', () => {
  const cached = policy('max-age=60', {}, {}, request('', { authorization: 'Bearer user-a' }));
  assert.equal(cached.evaluateRequest(request('max-stale')).response, undefined);
});

test('restrictions survive cache-policy serialization', () => {
  const original = policy('max-age=60', { 'set-cookie': 'session=user-a' });
  const restored = CachePolicy.fromObject(JSON.parse(JSON.stringify(original.toObject())));
  restored.now = original.now;
  assert.equal(restored.evaluateRequest(request('max-stale')).response, undefined);
});

test('restrictions survive a 304 revalidation', () => {
  const original = policy('max-age=60', { 'set-cookie': 'session=user-a', etag: '"v1"' });
  const revalidated = original.revalidatedPolicy(request(''), {
    status: 304,
    headers: { etag: '"v1"', 'cache-control': 'max-age=60' },
  }).policy;
  const storedAt = revalidated._responseTime;
  revalidated.now = () => storedAt + 10_000;
  assert.equal(revalidated.evaluateRequest(request('max-stale')).response, undefined);
});

for (const directive of ['max-stale', 'max-stale=3600']) {
  test(`ordinary expired public responses still accept ${directive}`, () => {
    assert.ok(policy('public, max-age=1').evaluateRequest(request(directive)).response);
  });
}

test('finite max-stale still enforces its age limit', () => {
  assert.equal(policy('public, max-age=1').evaluateRequest(request('max-stale=2')).response, undefined);
});

test('ordinary stale-while-revalidate still returns an asynchronous revalidation', () => {
  const result = policy('public, max-age=1, stale-while-revalidate=60').evaluateRequest(request(''));
  assert.ok(result.response);
  assert.equal(result.revalidation.synchronous, false);
});

for (const optIn of ['public', 'immutable']) {
  test(`explicit ${optIn} opt-in preserves upstream cookie-cache behavior`, () => {
    const cached = policy(`${optIn}, max-age=1`, { 'set-cookie': 'shared=explicit' });
    assert.ok(cached.evaluateRequest(request('max-stale')).response);
  });
}

test('private caches can still reuse their own cookie response', () => {
  const cached = policy('private, max-age=1', { 'set-cookie': 'session=user-a' }, { shared: false });
  assert.ok(cached.evaluateRequest(request('max-stale')).response);
});

test('fresh responses without restrictions remain reusable', () => {
  assert.ok(policy('public, max-age=60').evaluateRequest(request('')).response);
});

test('a different URL cannot reuse the cached response', () => {
  const req = { ...request('max-stale'), url: 'https://example.invalid/other' };
  assert.equal(policy('public, max-age=1').evaluateRequest(req).response, undefined);
});
