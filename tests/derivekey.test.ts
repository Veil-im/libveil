/*
 * This test depend 100% on the bun test framework.
 * If you want to run this test, you need to install bun and run the test with bun test.
 */

import VeilIdGenerator from '@/utils/hash/veilid';
import { deriveKey } from '@/utils/kdf/pbkdf2';
import { expect, test } from 'bun:test';

test(
  'Testing derive key',
  async () => {
    const v = await VeilIdGenerator.generate();
    console.log(v);
    expect(await deriveKey('123', v)).toBe(await deriveKey('123', v));
    expect(await deriveKey('123', v)).not.toBe(await deriveKey('123', '123'));
  },
  {
    timeout: 10000, // 10 seconds
  }
);
