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

export async function strongHash(input: string, options?: { memoryCost?: number; timeCost?: number }): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    
    // Default parameters for strong security
    const memoryCost = options?.memoryCost || 16;
    const timeCost = options?.timeCost || 4;
    
    // Generate a strong salt
    const salt = crypto.getRandomValues(new Uint8Array(32));
    
    // Create key material
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        data,
        'PBKDF2',
        false,
        ['deriveBits']
    );
    
    // First round with memory cost
    const firstRound = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000 * memoryCost,
            hash: 'SHA-512'
        },
        keyMaterial,
        512
    );
    
    // Second round with time cost
    const secondRound = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: new Uint8Array(firstRound),
            iterations: 50000 * timeCost,
            hash: 'SHA-512'
        },
        keyMaterial,
        512
    );
    
    // Combine results
    const hashArray = new Uint8Array(secondRound);
    const combined = new Uint8Array(salt.length + hashArray.length);
    combined.set(salt);
    combined.set(hashArray, salt.length);
    // Return as URL-safe base64
    return btoa(String.fromCharCode(...combined))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
