/**
 * Encodes a Uint8Array to a URL-safe base64 string
 */
export function encode(data: Uint8Array): string {
    return btoa(String.fromCharCode(...data))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Decodes a URL-safe base64 string to a Uint8Array
 */
export function decode(b64: string): Uint8Array {
    // Add back padding if needed
    b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
} 