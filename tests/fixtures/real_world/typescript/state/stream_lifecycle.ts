import * as fs from 'fs';

function processStream(inputPath: string, outputPath: string): void {
    var reader = fs.createReadStream(inputPath);
    var writer = fs.createWriteStream(outputPath);
    reader.pipe(writer);
    // Streams may leak if error occurs before pipe completes
}

function processStreamSafe(inputPath: string, outputPath: string): void {
    var reader = fs.createReadStream(inputPath);
    var writer = fs.createWriteStream(outputPath);

    reader.on('error', function(err: Error) {
        console.error('Read error:', err);
        writer.destroy();
        reader.destroy();
    });

    writer.on('error', function(err: Error) {
        console.error('Write error:', err);
        reader.destroy();
        writer.destroy();
    });

    reader.pipe(writer);
}
