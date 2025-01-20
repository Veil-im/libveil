export function compareArrayBuffers(buffer1: ArrayBuffer, buffer2: ArrayBuffer): boolean {
    if (buffer1.byteLength !== buffer2.byteLength) {
        return false;
    }

    const view1 = new Uint8Array(buffer1);
    const view2 = new Uint8Array(buffer2);

    for (let i = 0; i < buffer1.byteLength; i++) {
        if (view1[i] !== view2[i]) {
            return false;
        }
    }
    return true;
}