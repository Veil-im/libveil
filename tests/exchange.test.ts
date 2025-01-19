import { decrypt } from "@/utils/crypto/aesgcm";
import { encrypt } from "@/utils/crypto/aesgcm";
import KeyGenerator from "@/utils/crypto/ec";
import { expect, test } from "bun:test";

test("Testing secure message exchange", async () => {
    console.log("Generating ECDH keys for Bob");
    const bobKeyGenerator = new KeyGenerator();
    const bobECDHKeyPair = await bobKeyGenerator.generateECDHKeyPair();
    const bobECDSAKeyPair = await bobKeyGenerator.generateECDSAKeyPair();
    expect(bobECDHKeyPair).toBeDefined();
    expect(bobECDSAKeyPair).toBeDefined();
    console.log("Bob's keys generated");

    console.log("Generating ECDH keys for Alice");
    const aliceKeyGenerator = new KeyGenerator();
    const aliceECDHKeyPair = await aliceKeyGenerator.generateECDHKeyPair();
    const aliceECDSAKeyPair = await aliceKeyGenerator.generateECDSAKeyPair();
    expect(aliceECDHKeyPair).toBeDefined();
    expect(aliceECDSAKeyPair).toBeDefined();
    console.log("Alice's keys generated");

    console.log("Deriving shared secret using ECDH");
    const sharedSecretBob = await bobKeyGenerator.deriveSharedSecret(aliceECDHKeyPair.publicKey, bobECDHKeyPair.privateKey);
    const sharedSecretAlice = await aliceKeyGenerator.deriveSharedSecret(bobECDHKeyPair.publicKey, aliceECDHKeyPair.privateKey);
    expect(sharedSecretBob).toEqual(sharedSecretAlice);
    console.log("Shared secret derived");

    console.log("Deriving AES-GCM keys from shared secret");
    const aesKeyBob = await bobKeyGenerator.deriveAESGCMKey(sharedSecretBob);
    const aesKeyAlice = await aliceKeyGenerator.deriveAESGCMKey(sharedSecretAlice);
    console.log("AES-GCM keys derived");

    const message = "Hello, secure world!";
    const messageBytes = new TextEncoder().encode(message);
    
    console.log("Bob signing the message");
    const bobSignature = await bobKeyGenerator.sign(messageBytes, bobECDSAKeyPair.privateKey);
    console.log("Message signed, encrypting data");
    const encryptedData = await encrypt(message, aesKeyBob, bobSignature);
    
    console.log("Alice verifying Bob's signature");
    const isValidSignature = await aliceKeyGenerator.verify(
        bobSignature,
        messageBytes,
        bobECDSAKeyPair.publicKey
    );
    expect(isValidSignature).toBe(true);
    console.log("Signature verified");

    console.log("Alice decrypting the message");
    const decryptedMessage = await decrypt(encryptedData, aesKeyAlice);
    expect(decryptedMessage).toBe(message);
    console.log("Message decrypted successfully");

    console.log("Testing decryption with wrong signature");
    const tamperedSignature = new Uint8Array(bobSignature);
    tamperedSignature[0] ^= 1; // Flip one bit
    const isInvalidSignature = await aliceKeyGenerator.verify(
        tamperedSignature,
        messageBytes,
        bobECDSAKeyPair.publicKey
    );
    expect(isInvalidSignature).toBe(false);
    console.log("Decryption with wrong signature failed as expected");
});