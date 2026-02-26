// Positive fixture: each snippet should trigger the named pattern.

// ts.code_exec.eval
function triggerEval(code: string): void {
    eval(code);
}

// ts.code_exec.new_function
function triggerNewFunction(body: string): void {
    const fn = new Function(body);
}

// ts.code_exec.settimeout_string
function triggerSetTimeout(): void {
    setTimeout("alert(1)", 1000);
}

// ts.xss.document_write
function triggerDocumentWrite(data: string): void {
    document.write(data);
}

// ts.xss.outer_html
function triggerOuterHtml(el: Element, data: string): void {
    el.outerHTML = data;
}

// ts.xss.insert_adjacent_html
function triggerInsertAdjacentHtml(el: Element, data: string): void {
    el.insertAdjacentHTML("beforeend", data);
}

// ts.quality.any_annotation
function triggerAnyAnnotation(x: any): void {
    console.log(x);
}

// ts.quality.as_any
function triggerAsAny(x: unknown): void {
    const y = x as any;
}

// ts.prototype.proto_assignment
function triggerProtoAssignment(obj: Record<string, unknown>): void {
    obj.__proto__ = { malicious: true };
}

// ts.xss.location_assign
function triggerLocationAssign(url: string): void {
    window.location = url;
}

// ts.xss.cookie_write
function triggerCookieWrite(sid: string): void {
    document.cookie = "session=" + sid;
}
