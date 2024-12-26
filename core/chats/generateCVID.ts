import VeilIdGenerator  from "@vhash/veilid";

export async function generateCVID(){
    const VID = await VeilIdGenerator.generate()
    const CVID = VID.slice(0,32)
    return CVID
}