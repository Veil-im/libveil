interface KeyDetails {
    key: CryptoKey;
    type: "public" | "private";
    algorithm: CryptoAlgorithm;
    extractable: boolean;
    usages: KeyUsage[];
    id: string;
    raw?: string;  // Only for public keys
    spki?: string;  // For public keys in standard format
    pkcs8?: string; // For private keys in standard format
}

interface AESGCMKeyDetails {
    key: CryptoKey;
    algorithm: CryptoAlgorithm;
    extractable: boolean;
    usages: KeyUsage[];
    id: string;
}

export interface KeyPair {
    publicKey: KeyDetails;
    privateKey: KeyDetails;
}

export enum CryptoAlgorithm {
 /*
 * Ed25519 (for signatures) and X25519 (for key exchange) are based on the Curve25519.
 * However, they are not natively supported by the Web Crypto API as of now :/
 *
 * Instead, we use ECDSA (for signing) and ECDH (for key exchange) with standard NIST curves
 * like P-256, P-384, or P-521. While they serve similar purposes, they are based on different
 * elliptic curves and have different properties. However, NIST curves are not considered the most
 * secure according to https://safecurves.cr.yp.to/.
 */
    ECDSA = "ECDSA",
    ECDH = "ECDH"

}

export enum Curve {
    P256 = "P-256",
    P384 = "P-384",
    P521 = "P-521",
}

export enum KeyLength {
    TwoFiftySix = 256,
    ThreeHundredEightyFour = 384,
    FiveHundredTwelve = 512
}

// Abstract KeyGenerator class with a generic key generation function
export class KeyGenerator {
    // Method to derive a shared secret using ECDH
    public async deriveSharedSecret(publicKey: KeyDetails, privateKey: KeyDetails): Promise<ArrayBuffer> {
        try {
            if (privateKey.algorithm !== CryptoAlgorithm.ECDH || publicKey.algorithm !== CryptoAlgorithm.ECDH) {
                throw new Error('Both keys must be ECDH keys');
            }

            const derivedBits = await crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: publicKey.key
                },
                privateKey.key,
                KeyLength.TwoFiftySix // Derive 256 bits for the shared secret
            );

            return derivedBits;
        } catch (error) {
            throw new Error(`Failed to derive shared secret: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    
    public async deriveAESGCMKey(sharedSecret: ArrayBuffer): Promise<CryptoKey> {
        try {
            // Derive a deterministic salt from the shared secret using SHA-256
            const saltHash = await crypto.subtle.digest('SHA-256', sharedSecret);
            const salt = new Uint8Array(saltHash).slice(0, 32); // Use first 32 bytes as salt

            // Import the shared secret as HKDF key material
            const hkdfKey = await crypto.subtle.importKey(
                "raw",
                sharedSecret,
                { name: "HKDF" },
                false,
                ["deriveKey"]
            );

            // Derive an AES-GCM key using HKDF with deterministic salt
            const aesKey = await crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: salt,
                    info: new TextEncoder().encode("AES-GCM Key"), // Context info
                },
                hkdfKey,
                {
                    name: "AES-GCM",
                    length: 256
                },
                true, // extractable
                ["encrypt", "decrypt"] // Key usages
            );

            return aesKey;
        } catch (error) {
            throw new Error(`Failed to derive AES-GCM key from shared secret: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    // Helper method to convert ArrayBuffer to base64
    private arrayBufferToBase64(buffer: ArrayBuffer): string {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }

    // Helper method to generate key ID (16 chars, base64url-safe)
    private async generateKeyId(keyBuffer: ArrayBuffer): Promise<string> {
        const hash = await crypto.subtle.digest('SHA-256', keyBuffer);
        // Take first 12 bytes (96 bits) of the hash
        const truncated = new Uint8Array(hash).slice(0, 12);
        // Convert to base64url-safe string (~ 16 chars)
        return btoa(String.fromCharCode(...truncated))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    // Helper method to create key details
    private async createKeyDetails(
        key: CryptoKey,
        type: "public" | "private",
        algorithm: CryptoAlgorithm,
        keyUsages: KeyUsage[],
        exportedFormats: {
            raw?: ArrayBuffer;
            spki?: ArrayBuffer;
            pkcs8?: ArrayBuffer;
        }
    ): Promise<KeyDetails> {
        const details: KeyDetails = {
            key,
            type,
            algorithm,
            extractable: true,
            usages: keyUsages,
            // Generate ID from SPKI for public keys and PKCS8 for private keys
            id: await this.generateKeyId(type === "public" ? exportedFormats.spki! : exportedFormats.pkcs8!)
        };

        // Add the appropriate formats based on key type
        if (type === "public") {
            if (exportedFormats.raw) {
                details.raw = this.arrayBufferToBase64(exportedFormats.raw);
            }
            details.spki = this.arrayBufferToBase64(exportedFormats.spki!);
        } else {
            details.pkcs8 = this.arrayBufferToBase64(exportedFormats.pkcs8!);
        }

        return details;
    }

    // Method to generate the key pair for a specific algorithm
    private async generateKeyPair(algorithm: CryptoAlgorithm, curve: Curve): Promise<KeyPair> {
        try {
            // Define key usages based on algorithm
            const keyUsages: KeyUsage[] = algorithm === CryptoAlgorithm.ECDSA 
                ? ["sign", "verify"]
                : ["deriveKey", "deriveBits"];

            // Generate the key pair using Web Crypto API
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: algorithm,
                    namedCurve: curve
                } as EcKeyGenParams,
                true,
                keyUsages
            );

            // Export public key in both raw and SPKI formats
            const [publicKeyRaw, publicKeySpki] = await Promise.all([
                crypto.subtle.exportKey("raw", keyPair.publicKey),
                crypto.subtle.exportKey("spki", keyPair.publicKey)
            ]);

            // Export private key only in PKCS8 format
            const privateKeyPkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

            // Create key details
            const publicKeyDetails = await this.createKeyDetails(
                keyPair.publicKey,
                "public",
                algorithm,
                algorithm === CryptoAlgorithm.ECDSA ? ["verify"] : ["deriveKey", "deriveBits"],
                { raw: publicKeyRaw, spki: publicKeySpki }
            );

            const privateKeyDetails = await this.createKeyDetails(
                keyPair.privateKey,
                "private",
                algorithm,
                algorithm === CryptoAlgorithm.ECDSA ? ["sign"] : ["deriveKey", "deriveBits"],
                { pkcs8: privateKeyPkcs8 }
            );

            return {
                publicKey: publicKeyDetails,
                privateKey: privateKeyDetails
            };
        } catch (error) {
            throw new Error(`Failed to generate key pair: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    // Method to generate ECDSA key pair
    public generateECDSAKeyPair(): Promise<KeyPair> {
        return this.generateKeyPair(CryptoAlgorithm.ECDSA, Curve.P384);
    }

    // Method to generate ECDH key pair
    public generateECDHKeyPair(): Promise<KeyPair> {
        return this.generateKeyPair(CryptoAlgorithm.ECDH, Curve.P384);
    }

    /**
     * Signs data using ECDSA with SHA-384
     * @returns The signature as a Uint8Array
     */
    public async sign(data: BufferSource, privateKey: KeyDetails): Promise<Uint8Array> {
        try {
            if (privateKey.algorithm !== CryptoAlgorithm.ECDSA) {
                throw new Error('Key must be an ECDSA key');
            }

            const signature = await crypto.subtle.sign(
                {
                    name: "ECDSA",
                    hash: "SHA-384", // Using SHA-384 to match P-384 curve security level
                },
                privateKey.key,
                data
            );

            return new Uint8Array(signature);
        } catch (error) {
            throw new Error(`Signing failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Verifies an ECDSA signature
     * @returns True if signature is valid
     */
    public async verify(signature: BufferSource, data: BufferSource, publicKey: KeyDetails): Promise<boolean> {
        try {
            if (publicKey.algorithm !== CryptoAlgorithm.ECDSA) {
                throw new Error('Key must be an ECDSA key');
            }

            return await crypto.subtle.verify(
                {
                    name: "ECDSA",
                    hash: "SHA-384", // Using SHA-384 to match P-384 curve security level
                },
                publicKey.key,
                signature,
                data
            );
        } catch (error) {
            throw new Error(`Verification failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
}

export default KeyGenerator;
