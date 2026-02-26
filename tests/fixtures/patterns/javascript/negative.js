// Negative fixture: none of these should trigger security patterns.

function safeStringOps() {
    var x = "hello";
    var y = x.toUpperCase();
    var z = JSON.stringify({ key: "value" });
}

function safeTimeout(fn) {
    // Function reference, not string
    setTimeout(fn, 1000);
}

function safeDomManipulation(el) {
    el.textContent = "safe text";
    el.setAttribute("class", "active");
}

function safeRandomness() {
    var buf = crypto.getRandomValues(new Uint8Array(16));
}

function safeCopy(src) {
    var copy = Object.assign({}, src);
}
