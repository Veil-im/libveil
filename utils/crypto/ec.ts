export interface KeyDetails {
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

export interface KeyPair {
    publicKey: KeyDetails;
    privateKey: KeyDetails;
}

export enum CryptoAlgorithm {
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

// Helper functions
async function arrayBufferToBase64(buffer: ArrayBuffer): Promise<string> {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

async function generateKeyId(keyBuffer: ArrayBuffer): Promise<string> {
    const hash = await crypto.subtle.digest('SHA-256', keyBuffer);
    const truncated = new Uint8Array(hash).slice(0, 12);
    return btoa(String.fromCharCode(...truncated))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

async function createKeyDetails(
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
        id: await generateKeyId(type === "public" ? exportedFormats.spki! : exportedFormats.pkcs8!)
    };

    if (type === "public") {
        if (exportedFormats.raw) {
            details.raw = await arrayBufferToBase64(exportedFormats.raw);
        }
        details.spki = await arrayBufferToBase64(exportedFormats.spki!);
    } else {
        details.pkcs8 = await arrayBufferToBase64(exportedFormats.pkcs8!);
    }

    return details;
}

// Core crypto functions
export async function generateKeyPair(algorithm: CryptoAlgorithm, curve: Curve = Curve.P384): Promise<KeyPair> {
    try {
        const keyUsages: KeyUsage[] = algorithm === CryptoAlgorithm.ECDSA 
            ? ["sign", "verify"]
            : ["deriveKey", "deriveBits"];

        const keyPair = await crypto.subtle.generateKey(
            {
                name: algorithm,
                namedCurve: curve
            } as EcKeyGenParams,
            true,
            keyUsages
        );

        const [publicKeyRaw, publicKeySpki] = await Promise.all([
            crypto.subtle.exportKey("raw", keyPair.publicKey),
            crypto.subtle.exportKey("spki", keyPair.publicKey)
        ]);

        const privateKeyPkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

        const publicKeyDetails = await createKeyDetails(
            keyPair.publicKey,
            "public",
            algorithm,
            algorithm === CryptoAlgorithm.ECDSA ? ["verify"] : ["deriveKey", "deriveBits"],
            { raw: publicKeyRaw, spki: publicKeySpki }
        );

        const privateKeyDetails = await createKeyDetails(
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

export async function generateECDSAKeyPair(): Promise<KeyPair> {
    return generateKeyPair(CryptoAlgorithm.ECDSA);
}

export async function generateECDHKeyPair(): Promise<KeyPair> {
    return generateKeyPair(CryptoAlgorithm.ECDH);
}

export async function deriveSharedSecret(publicKey: KeyDetails, privateKey: KeyDetails): Promise<ArrayBuffer> {
    try {
        if (privateKey.algorithm !== CryptoAlgorithm.ECDH || publicKey.algorithm !== CryptoAlgorithm.ECDH) {
            throw new Error('Both keys must be ECDH keys');
        }

        return await crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: publicKey.key
            },
            privateKey.key,
            KeyLength.TwoFiftySix
        );
    } catch (error) {
        throw new Error(`Failed to derive shared secret: ${error instanceof Error ? error.message : String(error)}`);
    }
}

export async function deriveAESGCMKey(sharedSecret: ArrayBuffer): Promise<CryptoKey> {
    try {
        const saltHash = await crypto.subtle.digest('SHA-256', sharedSecret);
        const salt = new Uint8Array(saltHash).slice(0, 32);

        const hkdfKey = await crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "HKDF" },
            false,
            ["deriveKey"]
        );

        return await crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: salt,
                info: new TextEncoder().encode("AES-GCM Key"),
            },
            hkdfKey,
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    } catch (error) {
        throw new Error(`Failed to derive AES-GCM key from shared secret: ${error instanceof Error ? error.message : String(error)}`);
    }
}

export async function sign(data: BufferSource, privateKey: KeyDetails): Promise<Uint8Array> {
    try {
        if (privateKey.algorithm !== CryptoAlgorithm.ECDSA) {
            throw new Error('Key must be an ECDSA key');
        }

        const signature = await crypto.subtle.sign(
            {
                name: "ECDSA",
                hash: "SHA-384",
            },
            privateKey.key,
            data
        );

        return new Uint8Array(signature);
    } catch (error) {
        throw new Error(`Signing failed: ${error instanceof Error ? error.message : String(error)}`);
    }
}

export async function verify(signature: BufferSource, data: BufferSource, publicKey: KeyDetails): Promise<boolean> {
    try {
        if (publicKey.algorithm !== CryptoAlgorithm.ECDSA) {
            throw new Error('Key must be an ECDSA key');
        }

        return await crypto.subtle.verify(
            {
                name: "ECDSA",
                hash: "SHA-384",
            },
            publicKey.key,
            signature,
            data
        );
    } catch (error) {
        throw new Error(`Verification failed: ${error instanceof Error ? error.message : String(error)}`);
    }
}
