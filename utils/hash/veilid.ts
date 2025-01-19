import { bcryptHash } from './password'

export class VeilIdGenerator {
    /**
     * Generates a secure Veilid identifier using a multi-round hashing approach.
     * 
     * This method balances performance with randomness and unpredictability.
     * 
     * @returns Promise<string> A secure Veilid identifier prefixed with 'v/'
     */
    public static async generate(): Promise<string> {
        const getRandomBytes = (size: number) => 
            crypto.getRandomValues(new Uint8Array(size));
        
        const seed = getRandomBytes(32);
        const deviceSalt = getRandomBytes(16);
        
        let hash = await bcryptHash(Buffer.from(seed).toString('hex') + Buffer.from(deviceSalt).toString('hex'));
        const extraEntropy = getRandomBytes(8);
        hash = await bcryptHash(hash + Buffer.from(extraEntropy).toString('hex'));
        
        // Remove all non-alphanumeric characters from the hash
        return `v/${hash.replace(/[^a-zA-Z0-9]/g, '').substring(0, 32)}`;
    }
}

export default VeilIdGenerator