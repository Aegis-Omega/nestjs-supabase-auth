'use strict';

const { SupabaseAuthStrategy, UNAUTHORIZED } = require('../dist');

describe('SupabaseAuthStrategy fail-closed behavior', () => {
  test('rejects a missing bearer extractor before constructing a client', () => {
    expect(() => new SupabaseAuthStrategy({
      supabaseUrl: 'https://example.supabase.co',
      supabaseKey: 'test-public-key',
      extractor: null,
    })).toThrow(/Extractor is not a function/);
  });

  test('rejects a request with no token without contacting Supabase', () => {
    const strategy = new SupabaseAuthStrategy({
      supabaseUrl: 'https://example.supabase.co',
      supabaseKey: 'test-public-key',
      extractor: () => null,
    });
    strategy.fail = jest.fn();

    strategy.authenticate({});

    expect(strategy.fail).toHaveBeenCalledTimes(1);
    expect(strategy.fail).toHaveBeenCalledWith(UNAUTHORIZED, 401);
  });

  test('accepts a validated nonempty user and invokes Passport success', async () => {
    const strategy = new SupabaseAuthStrategy({
      supabaseUrl: 'https://example.supabase.co',
      supabaseKey: 'test-public-key',
      extractor: () => 'unused',
    });
    strategy.success = jest.fn();
    const user = { id: 'offline-fixture' };

    await expect(strategy.validate(user)).resolves.toEqual(user);
    expect(strategy.success).toHaveBeenCalledWith(user, {});
  });
});
