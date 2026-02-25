// Negative fixture: none of the security-relevant patterns should fire here.

function safeStringOps(): string {
    const x: string = "hello";
    return x.toUpperCase();
}

function safeTimeout(fn: () => void): void {
    setTimeout(fn, 1000);
}

function safeDomManipulation(el: Element): void {
    el.textContent = "safe text";
}

function safeTypedParam(x: number): number {
    return x + 1;
}

function safeUnknownHandling(x: unknown): string {
    if (typeof x === "string") {
        return x;
    }
    return String(x);
}
