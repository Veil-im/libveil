import { decrypt } from "@/utils/crypto/aesgcm";
import { encrypt } from "@/utils/crypto/aesgcm";
import { generateECDHKeyPair, generateECDSAKeyPair, deriveSharedSecret, deriveAESGCMKey, sign, verify } from "@/utils/crypto/ec";
import { expect, test } from "bun:test";

test("Testing secure message exchange", async () => {
    console.log("Generating ECDH keys for Bob");
    const [bobECDHKeyPair, bobECDSAKeyPair] = await Promise.all([
        generateECDHKeyPair(),
        generateECDSAKeyPair()
    ]);
    expect(bobECDHKeyPair).toBeDefined();
    expect(bobECDSAKeyPair).toBeDefined();
    console.log("Bob's keys generated");

    console.log("Generating ECDH keys for Alice");
    const [aliceECDHKeyPair, aliceECDSAKeyPair] = await Promise.all([
        generateECDHKeyPair(),
        generateECDSAKeyPair()
    ]);
    expect(aliceECDHKeyPair).toBeDefined();
    expect(aliceECDSAKeyPair).toBeDefined();
    console.log("Alice's keys generated");

    console.log("Deriving shared secret using ECDH");
    const sharedSecretBob = await deriveSharedSecret(aliceECDHKeyPair.publicKey, bobECDHKeyPair.privateKey);
    const sharedSecretAlice = await deriveSharedSecret(bobECDHKeyPair.publicKey, aliceECDHKeyPair.privateKey);
    expect(sharedSecretBob).toEqual(sharedSecretAlice);
    console.log("Shared secret derived");

    console.log("Deriving AES-GCM keys from shared secret");
    const [aesKeyBob, aesKeyAlice] = await Promise.all([
        deriveAESGCMKey(sharedSecretBob),
        deriveAESGCMKey(sharedSecretAlice)
    ]);
    console.log("AES-GCM keys derived");

    const message = "Hello, secure world!";
    const messageBytes = new TextEncoder().encode(message);
    
    console.log("Bob signing the message");
    const bobSignature = await sign(messageBytes, bobECDSAKeyPair.privateKey);
    console.log("Message signed, encrypting data");
    const encryptedData = await encrypt(message, aesKeyBob, bobSignature);
    
    console.log("Alice verifying Bob's signature");
    const isValidSignature = await verify(
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
    const isInvalidSignature = await verify(
        tamperedSignature,
        messageBytes,
        bobECDSAKeyPair.publicKey
    );
    expect(isInvalidSignature).toBe(false);
    console.log("Decryption with wrong signature failed as expected");
});