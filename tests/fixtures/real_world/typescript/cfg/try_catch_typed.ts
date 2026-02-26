import * as fs from 'fs';

class FileProcessor {
    private fd: number | null = null;

    open(path: string): void {
        this.fd = fs.openSync(path, 'r');
    }

    process(): string {
        if (this.fd === null) throw new Error('not opened');
        var buf = Buffer.alloc(1024);
        fs.readSync(this.fd, buf);
        return buf.toString();
    }

    close(): void {
        if (this.fd !== null) {
            fs.closeSync(this.fd);
            this.fd = null;
        }
    }
}

function riskyUsage(path: string): string {
    var fp = new FileProcessor();
    fp.open(path);
    var data = fp.process(); // may throw
    fp.close(); // skipped on throw
    return data;
}

function safeUsage(path: string): string {
    var fp = new FileProcessor();
    try {
        fp.open(path);
        var data = fp.process();
        return data;
    } finally {
        fp.close();
    }
}
