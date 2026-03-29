interface SyntaxRules {
  keywords: RegExp;
  strings: RegExp;
  comments: RegExp;
  numbers: RegExp;
}

const MAX_HIGHLIGHT_INPUT_CHARS = 20_000;

const SYNTAX_RULES: Record<string, SyntaxRules> = {
  javascript: {
    keywords:
      /\b(const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|new|this|class|extends|import|export|from|default|try|catch|finally|throw|async|await|yield|typeof|instanceof|in|of|null|undefined|true|false)\b/g,
    strings: /(["'`])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  python: {
    keywords:
      /\b(def|class|return|if|elif|else|for|while|import|from|as|try|except|finally|raise|with|yield|lambda|pass|break|continue|and|or|not|in|is|None|True|False|self|async|await|global|nonlocal)\b/g,
    strings:
      /("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g,
    comments: /(#.*$)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  go: {
    keywords:
      /\b(func|return|if|else|for|range|switch|case|default|break|continue|go|defer|select|chan|map|struct|interface|package|import|var|const|type|nil|true|false|make|new|append|len|cap|error)\b/g,
    strings: /(["'`])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  java: {
    keywords:
      /\b(public|private|protected|static|final|abstract|class|interface|extends|implements|return|if|else|for|while|do|switch|case|break|continue|new|this|super|try|catch|finally|throw|throws|import|package|void|int|long|double|float|boolean|char|byte|short|String|null|true|false|instanceof|synchronized|volatile|transient)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?[lLfFdD]?)\b/g,
  },
  rust: {
    keywords:
      /\b(fn|let|mut|const|static|return|if|else|for|while|loop|match|break|continue|use|mod|pub|crate|self|super|struct|enum|impl|trait|where|type|as|in|ref|move|async|await|unsafe|extern|dyn|true|false|None|Some|Ok|Err|Self)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?(?:_\d+)*[uif]?\d*)\b/g,
  },
  php: {
    keywords:
      /\b(function|return|if|else|elseif|for|foreach|while|do|switch|case|break|continue|class|extends|implements|new|public|private|protected|static|echo|print|require|include|use|namespace|try|catch|finally|throw|null|true|false|array|isset|empty|unset)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|#.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  ruby: {
    keywords:
      /\b(def|end|class|module|return|if|elsif|else|unless|for|while|until|do|begin|rescue|ensure|raise|yield|block_given\?|require|include|extend|attr_accessor|attr_reader|attr_writer|self|nil|true|false|and|or|not|in|then|when|case)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(#.*$)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  c: {
    keywords:
      /\b(int|char|float|double|void|long|short|unsigned|signed|const|static|extern|struct|union|enum|typedef|return|if|else|for|while|do|switch|case|break|continue|goto|sizeof|NULL|true|false|include|define|ifdef|ifndef|endif)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?[uUlLfF]*)\b/g,
  },
};

// Aliases
SYNTAX_RULES.typescript = SYNTAX_RULES.javascript;
SYNTAX_RULES['c++'] = SYNTAX_RULES.c;

interface Token {
  start: number;
  end: number;
  cls: string;
  text: string;
}

/**
 * Apply simple regex-based syntax highlighting to already-escaped HTML.
 * Returns HTML string with `<span class="tok-*">` wrappers.
 */
export function highlightSyntax(escapedHtml: string, lang: string): string {
  const rules = SYNTAX_RULES[lang];
  if (!rules || escapedHtml.length > MAX_HIGHLIGHT_INPUT_CHARS)
    return escapedHtml;

  const tokens: Token[] = [];

  const addTokens = (regex: RegExp, cls: string) => {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(escapedHtml)) !== null) {
      tokens.push({
        start: m.index,
        end: m.index + m[0].length,
        cls,
        text: m[0],
      });
    }
  };

  // Order matters: comments first (highest priority), then strings, then keywords/numbers
  addTokens(rules.comments, 'tok-comment');
  addTokens(rules.strings, 'tok-string');
  addTokens(rules.keywords, 'tok-keyword');
  addTokens(rules.numbers, 'tok-number');

  // Sort by start position
  tokens.sort((a, b) => a.start - b.start);

  // Remove overlapping tokens (earlier/higher-priority wins)
  const filtered: Token[] = [];
  let lastEnd = 0;
  for (const t of tokens) {
    if (t.start >= lastEnd) {
      filtered.push(t);
      lastEnd = t.end;
    }
  }

  // Build result
  let result = '';
  let pos = 0;
  for (const t of filtered) {
    result += escapedHtml.slice(pos, t.start);
    result += `<span class="${t.cls}">${t.text}</span>`;
    pos = t.end;
  }
  result += escapedHtml.slice(pos);
  return result;
}

/**
 * Escape a raw string for safe insertion as HTML.
 */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
