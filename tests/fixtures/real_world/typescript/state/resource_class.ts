import * as fs from 'fs';

class Database {
    private connection: number;

    constructor(path: string) {
        this.connection = fs.openSync(path, 'r');
    }

    query(): string {
        var buf = Buffer.alloc(1024);
        fs.readSync(this.connection, buf);
        return buf.toString();
    }

    close(): void {
        fs.closeSync(this.connection);
    }
}

function leak(): void {
    var db = new Database('/tmp/test.db');
    db.query();
    // Missing db.close()
}

function clean(): void {
    var db = new Database('/tmp/test.db');
    db.query();
    db.close();
}
