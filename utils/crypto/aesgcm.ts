import { encode, decode } from '../encoding/base64';

const PROTOCOL_VERSION = 1;

interface EncryptedData {
    ciphertext: string;  // Base64 encoded
    iv: string;         // Base64 encoded
    aad?: string;       // Base64 encoded (required)
    version: number;    // Protocol version
}

/**
 * Creates authenticated data by combining protocol version, context, and user AAD
 */
function createAAD(userAAD?: BufferSource): Uint8Array {
    const encoder = new TextEncoder();
    const versionBytes = new Uint8Array([PROTOCOL_VERSION]);
    const contextBytes = encoder.encode("VEIL-AESGCM");
    
    if (!userAAD) {
        return concatenateArrays(versionBytes, contextBytes);
    }

    const userAADBytes = userAAD instanceof Uint8Array ? userAAD : new Uint8Array(userAAD instanceof ArrayBuffer ? userAAD : userAAD.buffer);
    return concatenateArrays(versionBytes, contextBytes, userAADBytes);
}

/**
 * Concatenates multiple Uint8Arrays
 */
function concatenateArrays(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    
    return result;
}

/**
 * Encrypts data using AES-GCM with additional authenticated data (AAD)
 * @param plaintext - The data to encrypt
 * @param key - The AES-GCM key
 * @param userAAD - Optional user-provided additional authenticated data
 * @returns EncryptedData object containing ciphertext, IV, AAD, and version
 */
export async function encrypt(
    plaintext: string,
    key: CryptoKey,
    userAAD?: BufferSource
): Promise<EncryptedData> {
    // Generate a random 96-bit (12 byte) IV
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    try {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(plaintext);
        const aad = createAAD(userAAD);

        const encryptedData = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                additionalData: aad,
                tagLength: 128 // 128-bit authentication tag
            },
            key,
            encodedData
        );

        return {
            version: PROTOCOL_VERSION,
            ciphertext: encode(new Uint8Array(encryptedData)),
            iv: encode(iv),
            aad: encode(aad)
        };
    } catch (error) {
        throw new Error(`Encryption failed: ${error instanceof Error ? error.message : String(error)}`);
    }
}

/**
 * Decrypts AES-GCM encrypted data
 * @param encryptedData - The EncryptedData object containing ciphertext, IV, AAD, and version
 * @param key - The AES-GCM key
 * @returns Decrypted plaintext
 */
export async function decrypt(
    encryptedData: EncryptedData,
    key: CryptoKey
): Promise<string> {
    try {
        // Version check
        if (encryptedData.version !== PROTOCOL_VERSION) {
            throw new Error(`Unsupported protocol version: ${encryptedData.version}`);
        }

        // AAD is now required
        if (!encryptedData.aad) {
            throw new Error('Missing required AAD');
        }

        const decoder = new TextDecoder();
        const ciphertext = decode(encryptedData.ciphertext);
        const iv = decode(encryptedData.iv);
        const aad = decode(encryptedData.aad);

        const decryptedData = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
                additionalData: aad,
                tagLength: 128 // Must match encryption
            },
            key,
            ciphertext
        );

        return decoder.decode(decryptedData);
    } catch (error) {
        throw new Error(`Decryption failed: ${error instanceof Error ? error.message : String(error)}`);
    }
}
