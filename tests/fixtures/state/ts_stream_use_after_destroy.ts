import * as fs from 'fs';

function writeAfterDestroy(path: string): void {
    var stream = fs.createWriteStream(path);
    stream.destroy();
    stream.write("data"); // use after close!
}
