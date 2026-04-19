/**
 * 
 * @param {CModuleStreams.Stream} stream
 * @param {Uint8Array} buf  
 */
export function readOnce(stream, buf) {
    return new Promise((rs, rj) => {
        stream.onread = (data, err) => {
            if (err) rj(err);
            buf.set(data, 0);
            rs(data.length);
        }
    });
}