// Regression fixture: TypeScript arrow capturing a tainted variable
// with explicit type annotations.  Equivalent to the JS fixture; here we
// also exercise the TS tree-sitter grammar path and any TypeScript-only
// return-type/handler-signature differences.
type Handler = (req: unknown) => void;

function makeHandler(): Handler {
    const tainted: string = process.env.USER_INPUT as string;
    return (req: unknown): void => {
        require('child_process').exec(tainted);
    };
}

const h: Handler = makeHandler();
h({});

export { makeHandler };
