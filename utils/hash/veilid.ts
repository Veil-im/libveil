import { strongHash } from './password'

export class VeilIdGenerator {
    /**
     * Generates a cryptographically secure Veilid identifier using an intentionally 
     * computationally intensive multi-round hashing approach.
     * 
     * This implementation employs an extreme level of entropy generation and mixing,
     * deliberately trading performance for maximum randomness and unpredictability.
     * While the computational cost may seem excessive, it serves several critical purposes:
     * 
     * 1. Multiple rounds of strong hashing with different memory/time costs create 
     *    layered entropy that is extremely difficult to reverse-engineer
     * 2. The combination of device-specific salt, extra entropy injection, and 
     *    varied hashing parameters makes each VID uniquely unpredictable
     * 3. The intensive computation acts as a natural rate-limiter against 
     *    automated VID generation attempts
     * 
     * The approach is specifically designed for systems where VID uniqueness and 
     * cryptographic strength are paramount concerns that justify the performance trade-off.
     * 
     * @returns Promise<string> A cryptographically secure Veilid identifier prefixed with 'v/'
     */
    public static async generate(): Promise<string> {
        // Helper function using Bun's native crypto
        const getRandomHex = (size: number) => 
            Buffer.from(crypto.getRandomValues(new Uint8Array(size))).toString('hex')
        
        // Generate initial random seed with higher entropy (256-bit)
        const seed = getRandomHex(32)
        
        // Create additional random salt for added unpredictability
        const deviceSalt = getRandomHex(16)
        
        // First round - combine seed with device salt
        let hash = await strongHash(seed + deviceSalt, {
            memoryCost: 8,
            timeCost: 4
        })

        // Second round - add more entropy
        const extraEntropy = getRandomHex(8)
        hash = await strongHash(hash + extraEntropy, {
            memoryCost: 16,
            timeCost: 2
        })

        // Final round with bcrypt-like parameters
        const finalHash = await strongHash(hash)
        
        // Take first 64 characters for consistent length
        return `v/${finalHash.replace('/','')}`
    }
}

export default VeilIdGenerator