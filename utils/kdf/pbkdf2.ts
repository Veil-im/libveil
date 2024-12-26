export async function deriveKey(password: string, salt: string): Promise<string> {
    // Convert password and salt into ArrayBuffers
    const passwordBuffer = new TextEncoder().encode(password); // Encoding password into Uint8Array
    const saltBuffer = new TextEncoder().encode(salt); // Encoding salt into Uint8Array

    // Import the password into a CryptoKey object
    const key = await crypto.subtle.importKey(
        "raw", // We're working with raw material (password)
        passwordBuffer,
        { name: "PBKDF2" }, // We're using PBKDF2 for key derivation
        false, // We don't need to export the key
        ["deriveBits"] // This will be used for key derivation
    );

    // Use PBKDF2 to derive the key with the salt
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: 100000, // Number of iterations (adjust as needed)
            hash: "SHA-256", // Hashing algorithm
        },
        key, // The imported key (password)
        256 // Length of the derived key in bits (256-bit = 32 bytes)
    );

    // Convert the derived bits into a hexadecimal string
    const derivedKey = Array.from(new Uint8Array(derivedBits))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

    return derivedKey;
}
