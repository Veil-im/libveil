export async function bcryptHash(password: string): Promise<string> {
    // Convert password to bytes
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);

    // Generate a random salt
    const salt = crypto.getRandomValues(new Uint8Array(16));

    // Create key material from password
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordData,
        'PBKDF2',
        false,
        ['deriveBits']
    );

    // Generate hash using PBKDF2
    const hash = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000, // Industry standard iterations
            hash: 'SHA-256'
        },
        keyMaterial,
        256 // 256 bits hash
    );

    // Combine salt and hash
    const hashArray = new Uint8Array(hash);
    const combined = new Uint8Array(salt.length + hashArray.length);
    combined.set(salt);
    combined.set(hashArray, salt.length);

    // Convert to base64 string
    return btoa(String.fromCharCode(...combined));
}