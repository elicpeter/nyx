import { describe, it, expect } from 'vitest';
import { escapeHtml, highlightSyntax } from '../../utils/syntaxHighlight';

describe('escapeHtml', () => {
  it('escapes ampersands', () => {
    expect(escapeHtml('a & b')).toBe('a &amp; b');
  });

  it('escapes less-than signs', () => {
    expect(escapeHtml('<div>')).toBe('&lt;div&gt;');
  });

  it('escapes greater-than signs', () => {
    expect(escapeHtml('1 > 0')).toBe('1 &gt; 0');
  });

  it('escapes double quotes', () => {
    expect(escapeHtml('"hello"')).toBe('&quot;hello&quot;');
  });

  it('escapes all special chars together', () => {
    expect(escapeHtml('<a href="x&y">z</a>')).toBe(
      '&lt;a href=&quot;x&amp;y&quot;&gt;z&lt;/a&gt;',
    );
  });

  it('returns plain text unchanged', () => {
    expect(escapeHtml('hello world')).toBe('hello world');
  });

  it('returns empty string unchanged', () => {
    expect(escapeHtml('')).toBe('');
  });
});

describe('highlightSyntax', () => {
  it('returns input unchanged for an unknown language', () => {
    const code = 'const x = 1;';
    expect(highlightSyntax(code, 'cobol')).toBe(code);
  });

  it('wraps JavaScript keywords in tok-keyword spans', () => {
    const result = highlightSyntax('const x = 1;', 'javascript');
    expect(result).toContain('<span class="tok-keyword">const</span>');
  });

  it('wraps string literals in tok-string spans', () => {
    const result = highlightSyntax('"hello"', 'javascript');
    expect(result).toContain('<span class="tok-string">"hello"</span>');
  });

  it('wraps numbers in tok-number spans', () => {
    const result = highlightSyntax('42', 'javascript');
    expect(result).toContain('<span class="tok-number">42</span>');
  });

  it('wraps line comments in tok-comment spans', () => {
    const result = highlightSyntax('// a comment', 'javascript');
    expect(result).toContain('<span class="tok-comment">// a comment</span>');
  });

  it('treats typescript as a javascript alias', () => {
    const result = highlightSyntax('const x = 1;', 'typescript');
    expect(result).toContain('<span class="tok-keyword">const</span>');
  });

  it('highlights Python keywords', () => {
    const result = highlightSyntax('def foo():', 'python');
    expect(result).toContain('<span class="tok-keyword">def</span>');
  });

  it('highlights Rust keywords', () => {
    const result = highlightSyntax('fn main()', 'rust');
    expect(result).toContain('<span class="tok-keyword">fn</span>');
  });

  it('highlights Go keywords', () => {
    const result = highlightSyntax('func main()', 'go');
    expect(result).toContain('<span class="tok-keyword">func</span>');
  });

  it('highlights Java keywords', () => {
    const result = highlightSyntax('public class Foo', 'java');
    expect(result).toContain('<span class="tok-keyword">public</span>');
  });

  it('highlights C keywords', () => {
    const result = highlightSyntax('int main()', 'c');
    expect(result).toContain('<span class="tok-keyword">int</span>');
  });

  it('treats c++ as a c alias', () => {
    const result = highlightSyntax('int x = 0;', 'c++');
    expect(result).toContain('<span class="tok-keyword">int</span>');
  });

  it('gives comments priority over keywords inside a comment', () => {
    const code = '// const x = 1;';
    const result = highlightSyntax(code, 'javascript');
    // The whole line should be a comment span, not split into keyword spans
    expect(result).toContain(
      '<span class="tok-comment">// const x = 1;</span>',
    );
    expect(result).not.toContain('tok-keyword');
  });

  it('returns unchanged text when no tokens match', () => {
    const code = 'hello world';
    expect(highlightSyntax(code, 'python')).toBe('hello world');
  });
});
