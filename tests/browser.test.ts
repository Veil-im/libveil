import { decrypt } from '@/utils/crypto/aesgcm';
import { encrypt } from '@/utils/crypto/aesgcm';
import {
  generateECDHKeyPair,
  generateECDSAKeyPair,
  deriveSharedSecret,
  deriveAESGCMKey,
  sign,
  verify,
  type KeyPair,
} from '@/utils/crypto/ec';
import { compareArrayBuffers } from '@/utils/binary';
interface EncryptedData {
  ciphertext: string; // Base64 encoded
  iv: string; // Base64 encoded
  aad?: string; // Base64 encoded (required)
  version: number; // Protocol version
}

interface BobKeys {
  ecdhKeyPair: KeyPair;
  ecdsaKeyPair: KeyPair;
}

interface AliceKeys {
  ecdhKeyPair: KeyPair;
  ecdsaKeyPair: KeyPair;
}

interface SharedSecrets {
  sharedSecretBob: ArrayBuffer;
  sharedSecretAlice: ArrayBuffer;
}

interface AESKeys {
  aesKeyBob: CryptoKey;
  aesKeyAlice: CryptoKey;
}

interface MessageData {
  message: string;
  messageBytes: Uint8Array;
  bobSignature: Uint8Array;
  encryptedData: EncryptedData;
}

async function generateBobKeys(): Promise<BobKeys> {
  console.log('Generating ECDH keys for Bob');
  const [ecdhKeyPair, ecdsaKeyPair] = await Promise.all([
    generateECDHKeyPair(),
    generateECDSAKeyPair(),
  ]);

  if (ecdhKeyPair && ecdsaKeyPair) {
    console.log("Bob's keys generated");
    return { ecdhKeyPair, ecdsaKeyPair };
  } else {
    console.error("Failed to generate Bob's keys");
    throw new Error("Failed to generate Bob's keys");
  }
}

async function generateAliceKeys(): Promise<AliceKeys> {
  console.log('Generating ECDH keys for Alice');
  const [ecdhKeyPair, ecdsaKeyPair] = await Promise.all([
    generateECDHKeyPair(),
    generateECDSAKeyPair(),
  ]);

  if (ecdhKeyPair && ecdsaKeyPair) {
    console.log("Alice's keys generated");
    return { ecdhKeyPair, ecdsaKeyPair };
  } else {
    console.error("Failed to generate Alice's keys");
    throw new Error("Failed to generate Alice's keys");
  }
}

async function deriveSharedSecrets(bobKeys: BobKeys, aliceKeys: AliceKeys): Promise<SharedSecrets> {
  console.log('Deriving shared secret using ECDH');
  const sharedSecretBob = await deriveSharedSecret(
    aliceKeys.ecdhKeyPair.publicKey,
    bobKeys.ecdhKeyPair.privateKey
  );
  const sharedSecretAlice = await deriveSharedSecret(
    bobKeys.ecdhKeyPair.publicKey,
    aliceKeys.ecdhKeyPair.privateKey
  );

  if (compareArrayBuffers(sharedSecretBob, sharedSecretAlice)) {
    console.log('Shared secret derived');
    return { sharedSecretBob, sharedSecretAlice };
  } else {
    console.error('Shared secrets do not match');
    throw new Error('Shared secrets do not match');
  }
}

async function deriveAESKeys(secrets: SharedSecrets): Promise<AESKeys> {
  console.log('Deriving AES-GCM keys from shared secret');
  const [aesKeyBob, aesKeyAlice] = await Promise.all([
    deriveAESGCMKey(secrets.sharedSecretBob),
    deriveAESGCMKey(secrets.sharedSecretAlice),
  ]);
  console.log('AES-GCM keys derived');
  return { aesKeyBob, aesKeyAlice };
}

async function signAndEncryptMessage(bobKeys: BobKeys, aesKeys: AESKeys): Promise<MessageData> {
  const message = 'Hello, secure world!';
  const messageBytes = new TextEncoder().encode(message);

  console.log('Bob signing the message');
  const bobSignature = await sign(messageBytes, bobKeys.ecdsaKeyPair.privateKey);
  console.log('Message signed, encrypting data');
  const encryptedData = await encrypt(message, aesKeys.aesKeyBob, bobSignature);

  return { message, messageBytes, bobSignature, encryptedData };
}

async function verifySignature(messageData: MessageData, bobKeys: BobKeys): Promise<boolean> {
  console.log("Alice verifying Bob's signature");
  const isValidSignature = await verify(
    messageData.bobSignature,
    messageData.messageBytes,
    bobKeys.ecdsaKeyPair.publicKey
  );

  if (isValidSignature) {
    console.log('Signature verified');
    return true;
  } else {
    console.error('Signature verification failed');
    throw new Error('Signature verification failed');
  }
}

async function decryptMessage(messageData: MessageData, aesKeys: AESKeys): Promise<string> {
  console.log('Alice decrypting the message');
  const decryptedMessage = await decrypt(messageData.encryptedData, aesKeys.aesKeyAlice);

  if (decryptedMessage === messageData.message) {
    console.log('Message decrypted successfully');
    return decryptedMessage;
  } else {
    console.error('Decrypted message does not match the original');
    throw new Error('Decrypted message does not match the original');
  }
}

async function testTamperedSignature(messageData: MessageData, bobKeys: BobKeys): Promise<boolean> {
  console.log('Testing decryption with wrong signature');
  const tamperedSignature = new Uint8Array(messageData.bobSignature);
  tamperedSignature[0] ^= 1; // Flip one bit
  const isInvalidSignature = await verify(
    tamperedSignature,
    messageData.messageBytes,
    bobKeys.ecdsaKeyPair.publicKey
  );

  if (!isInvalidSignature) {
    console.log('Decryption with wrong signature failed as expected');
    return true;
  } else {
    console.error('Decryption with wrong signature succeeded unexpectedly');
    throw new Error('Decryption with wrong signature succeeded unexpectedly');
  }
}

async function test_main() {
  const bobKeys = await generateBobKeys();
  const aliceKeys = await generateAliceKeys();
  const secrets = await deriveSharedSecrets(bobKeys, aliceKeys);
  const aesKeys = await deriveAESKeys(secrets);
  const messageData = await signAndEncryptMessage(bobKeys, aesKeys);
  await verifySignature(messageData, bobKeys);
  await decryptMessage(messageData, aesKeys);
  await testTamperedSignature(messageData, bobKeys);
}

test_main();
