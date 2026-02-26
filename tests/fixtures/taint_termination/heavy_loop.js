// Synthetic fixture: many tainted variables in loops.
// Triggers divergent taint-map hashes on each loop iteration,
// exercising the BFS iteration limit in the taint engine.
// Without the limit the BFS would run forever.

function heavyLoop(req) {
    const userInput = req.query.data;    // source
    let a = userInput;
    let b = a;
    let c = b;
    let d = c;
    let e = d;
    let f = e;
    let g = f;
    let h = g;
    let i = h;
    let j = i;

    // Loop with accumulating taint
    for (let k = 0; k < 100; k++) {
        a = b + c;
        b = c + d;
        c = d + e;
        d = e + f;
        e = f + g;
        f = g + h;
        g = h + i;
        h = i + j;
        i = j + a;
        j = a + b;
    }

    // Nested loop
    for (let m = 0; m < 10; m++) {
        for (let n = 0; n < 10; n++) {
            a = b + c + d;
            b = c + d + e;
            c = d + e + f;
        }
    }

    // Sink: eval with tainted data
    eval(a + b + c + d + e);
}

function multiSource(req, res) {
    const x1 = req.query.a;
    const x2 = req.query.b;
    const x3 = req.query.c;
    const x4 = req.query.d;
    const x5 = req.query.e;
    const x6 = req.query.f;
    const x7 = req.query.g;
    const x8 = req.query.h;

    let result = x1;
    for (let i = 0; i < 20; i++) {
        result = result + x2 + x3;
        const tmp = x4 + x5 + x6;
        result = result + tmp + x7 + x8;
    }

    eval(result);
}
