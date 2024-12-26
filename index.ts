import VeilIdGenerator from '@vhash/veilid'
import { deriveKey } from "@/utils/kdf/pbkdf2";

async function main() {
    const v = await VeilIdGenerator.generate()
    console.log(v)
    console.log(await deriveKey("123", v))
    
}


main()