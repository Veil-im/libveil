import KeyGenerator from '@/utils/crypto/ec';
import { expect, test } from 'bun:test';

test('Testing X25519', async () => {
  const keyGenerator = new KeyGenerator();
  const keyPair = await keyGenerator.generateECDSAKeyPair();
  console.log(keyPair);
  expect(keyPair).toBeDefined();
});
