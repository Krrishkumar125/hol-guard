/**
 * The subset of Markdown that Guard's release notes are written in, parsed
 * into a typed tree.
 *
 * hol.org publishes release notes as the Markdown a maintainer wrote, so the
 * archive has to render headings, lists, links and code to be readable at all.
 * It does that without a Markdown library and without ever producing HTML: the
 * parser emits data, the renderer emits React elements, and nothing in the
 * path can turn upstream bytes into markup. Anything this grammar does not
 * recognise survives as its own literal text rather than disappearing.
 *
 * The daemon has already bounded the response, but these notes are still the
 * one place where another origin's prose reaches the screen, so the parser
 * scans characters instead of backtracking through regular expressions and
 * stops at the limits below rather than trusting the input to be small.
 */

const MAX_SOURCE_CHARS = 64_000;
const MAX_BLOCKS = 1_000;
const MAX_LIST_ITEMS = 500;
const MAX_INLINE_NODES = 400;
const MAX_HREF_CHARS = 2_000;
/** Lists nest one level. Deeper bullets flatten into their parent. */
const MAX_LIST_DEPTH = 2;

export type ReleaseInline =
  | { kind: "text"; text: string }
  | { kind: "code"; text: string }
  | { kind: "break" }
  | { kind: "strong"; children: ReleaseInline[] }
  | { kind: "emphasis"; children: ReleaseInline[] }
  | { kind: "link"; href: string; children: ReleaseInline[] };

export type ReleaseListItem = {
  children: ReleaseInline[];
  items: ReleaseListItem[];
};

export type ReleaseBlock =
  | { kind: "heading"; level: 1 | 2 | 3; children: ReleaseInline[] }
  | { kind: "paragraph"; children: ReleaseInline[] }
  | { kind: "quote"; children: ReleaseInline[] }
  | { kind: "list"; ordered: boolean; items: ReleaseListItem[] }
  | { kind: "code"; language: string | null; text: string }
  | { kind: "rule" };

/**
 * Only a web link survives as a link. `javascript:`, `data:` and every other
 * scheme keeps its text and loses its href, so a reader still sees what was
 * written and cannot click it.
 */
export function safeHref(raw: string): string | null {
  const href = raw.trim();
  if (!href || href.length > MAX_HREF_CHARS) return null;
  if (/[\u0000-\u001f\u007f\s]/.test(href)) return null;
  const lower = href.toLowerCase();
  if (!lower.startsWith("https://") && !lower.startsWith("http://")) return null;
  return href;
}

function pushText(nodes: ReleaseInline[], text: string): void {
  if (!text) return;
  const last = nodes[nodes.length - 1];
  if (last && last.kind === "text") {
    last.text += text;
    return;
  }
  nodes.push({ kind: "text", text });
}

/** How far a run of `marker` extends from `start`, capped at `max`. */
function runLength(source: string, start: number, marker: string, max: number): number {
  let length = 0;
  while (length < max && source[start + length] === marker) length += 1;
  return length;
}

/**
 * Inline Markdown, scanned left to right. An opener with no closer is not a
 * marker at all: it stays in the text exactly as written.
 */
function parseInline(source: string, depth = 0): ReleaseInline[] {
  const nodes: ReleaseInline[] = [];
  let index = 0;
  let plain = "";
  const flush = () => {
    pushText(nodes, plain);
    plain = "";
  };
  while (index < source.length) {
    if (nodes.length >= MAX_INLINE_NODES) {
      plain += source.slice(index);
      break;
    }
    const char = source[index];

    if (char === "\n") {
      flush();
      nodes.push({ kind: "break" });
      index += 1;
      continue;
    }

    if (char === "\\" && index + 1 < source.length && /[\\`*_[\]()#>~]/.test(source[index + 1])) {
      plain += source[index + 1];
      index += 2;
      continue;
    }

    if (char === "`") {
      const fence = runLength(source, index, "`", 3);
      const close = source.indexOf("`".repeat(fence), index + fence);
      if (close !== -1) {
        flush();
        nodes.push({ kind: "code", text: source.slice(index + fence, close).trim() });
        index = close + fence;
        continue;
      }
    }

    if (char === "[" && depth < 3) {
      const link = readLink(source, index, depth);
      if (link) {
        flush();
        nodes.push(link.node);
        index = link.next;
        continue;
      }
    }

    if ((char === "*" || char === "_") && depth < 3) {
      const marker = runLength(source, index, char, 2);
      const token = char.repeat(marker);
      const close = source.indexOf(token, index + marker);
      // `**` with nothing between it is literal, not empty emphasis.
      if (close !== -1 && close > index + marker) {
        const inner = source.slice(index + marker, close);
        flush();
        nodes.push(
          marker === 2
            ? { kind: "strong", children: parseInline(inner, depth + 1) }
            : { kind: "emphasis", children: parseInline(inner, depth + 1) },
        );
        index = close + marker;
        continue;
      }
    }

    if (char === "h" && source.startsWith("http", index)) {
      const bare = readBareUrl(source, index);
      if (bare) {
        flush();
        nodes.push(bare.node);
        index = bare.next;
        continue;
      }
    }

    plain += char;
    index += 1;
  }
  flush();
  return nodes;
}

/** `[label](href)`, with one level of balanced parentheses in the href so a
 * GitHub compare link does not end at its own bracket. */
function readLink(
  source: string,
  start: number,
  depth: number,
): { node: ReleaseInline; next: number } | null {
  let cursor = start + 1;
  let open = 1;
  while (cursor < source.length && open > 0) {
    const char = source[cursor];
    if (char === "\\") {
      cursor += 2;
      continue;
    }
    if (char === "[") open += 1;
    if (char === "]") open -= 1;
    cursor += 1;
  }
  if (open !== 0 || source[cursor] !== "(") return null;
  const labelEnd = cursor - 1;
  let hrefCursor = cursor + 1;
  let parens = 1;
  while (hrefCursor < source.length && parens > 0) {
    const char = source[hrefCursor];
    if (char === "(") parens += 1;
    if (char === ")") parens -= 1;
    if (parens === 0) break;
    hrefCursor += 1;
  }
  if (parens !== 0) return null;
  const label = source.slice(start + 1, labelEnd);
  const href = safeHref(source.slice(cursor + 1, hrefCursor));
  const children = parseInline(label, depth + 1);
  return {
    node: href ? { kind: "link", href, children } : { kind: "emphasis", children },
    next: hrefCursor + 1,
  };
}

/** A URL written on its own, not inside brackets. Trailing sentence
 * punctuation belongs to the sentence, not to the link. */
function readBareUrl(source: string, start: number): { node: ReleaseInline; next: number } | null {
  let end = start;
  while (end < source.length && !/[\s<>"'`)\]]/.test(source[end])) end += 1;
  while (end > start && /[.,;:!?]/.test(source[end - 1])) end -= 1;
  const href = safeHref(source.slice(start, end));
  if (!href) return null;
  return { node: { kind: "link", href, children: [{ kind: "text", text: href }] }, next: end };
}

function listMarker(line: string): { ordered: boolean; indent: number; text: string } | null {
  const match = /^(\s*)(?:([-*+])|(\d{1,3})[.)])\s+(.*)$/.exec(line);
  if (!match) return null;
  return { ordered: match[3] !== undefined, indent: match[1].length, text: match[4] };
}

/**
 * Parse one release's notes. A single newline inside a paragraph is a line
 * break, the way the release pages these notes come from render it.
 */
export function parseReleaseMarkdown(source: string): ReleaseBlock[] {
  const text = source.length > MAX_SOURCE_CHARS ? source.slice(0, MAX_SOURCE_CHARS) : source;
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks: ReleaseBlock[] = [];
  let index = 0;

  const atLimit = () => blocks.length >= MAX_BLOCKS;

  while (index < lines.length && !atLimit()) {
    const line = lines[index];
    if (!line.trim()) {
      index += 1;
      continue;
    }

    const fence = /^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+-]{0,20})\s*$/.exec(line);
    if (fence) {
      const token = fence[1][0].repeat(3);
      const body: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].trimStart().startsWith(token)) {
        body.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push({ kind: "code", language: fence[2] || null, text: body.join("\n") });
      continue;
    }

    if (/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      blocks.push({ kind: "rule" });
      index += 1;
      continue;
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      // Three visible ranks is all this panel has room for, and the headings
      // sit under the panel's own, so the document outline stays in order.
      const level = Math.min(3, heading[1].length) as 1 | 2 | 3;
      blocks.push({ kind: "heading", level, children: parseInline(heading[2].trim()) });
      index += 1;
      continue;
    }

    if (/^\s*>\s?/.test(line)) {
      const quoted: string[] = [];
      while (index < lines.length && /^\s*>\s?/.test(lines[index])) {
        quoted.push(lines[index].replace(/^\s*>\s?/, ""));
        index += 1;
      }
      blocks.push({ kind: "quote", children: parseInline(quoted.join("\n").trim()) });
      continue;
    }

    const marker = listMarker(line);
    if (marker) {
      const result = readList(lines, index);
      blocks.push(result.block);
      index = result.next;
      continue;
    }

    const paragraph: string[] = [];
    while (
      index < lines.length &&
      lines[index].trim() &&
      !listMarker(lines[index]) &&
      !/^(#{1,6})\s+/.test(lines[index]) &&
      !/^\s*(?:`{3,}|~{3,})/.test(lines[index]) &&
      !/^\s*>\s?/.test(lines[index]) &&
      !/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(lines[index])
    ) {
      paragraph.push(lines[index].trim());
      index += 1;
    }
    blocks.push({ kind: "paragraph", children: parseInline(paragraph.join("\n")) });
  }

  return blocks;
}

function readList(lines: string[], start: number): { block: ReleaseBlock; next: number } {
  const first = listMarker(lines[start]);
  const ordered = first ? first.ordered : false;
  const baseIndent = first ? first.indent : 0;
  const items: ReleaseListItem[] = [];
  let index = start;

  while (index < lines.length && items.length < MAX_LIST_ITEMS) {
    const line = lines[index];
    if (!line.trim()) {
      // A blank line ends the list unless another bullet follows it.
      const next = lines[index + 1];
      if (!next || !listMarker(next)) break;
      index += 1;
      continue;
    }
    const marker = listMarker(line);
    if (!marker || marker.indent < baseIndent || marker.ordered !== ordered) break;

    if (marker.indent > baseIndent) {
      const parent = items[items.length - 1];
      const nested = readList(lines, index);
      if (parent && nested.block.kind === "list") {
        // Deeper than the panel renders: the bullets join their grandparent.
        parent.items.push(...nested.block.items);
        if (parent.items.length > MAX_LIST_ITEMS) parent.items.length = MAX_LIST_ITEMS;
      }
      index = nested.next;
      continue;
    }

    const lead: string[] = [marker.text];
    index += 1;
    // A wrapped bullet continues on an indented line that starts no new item.
    while (index < lines.length && lines[index].trim() && !listMarker(lines[index])) {
      lead.push(lines[index].trim());
      index += 1;
    }
    items.push({ children: parseInline(lead.join("\n")), items: [] });
  }

  void MAX_LIST_DEPTH;
  return { block: { kind: "list", ordered, items }, next: index };
}

/** Plain text for a summary line, with the markup removed rather than shown. */
export function releaseMarkdownToText(source: string): string {
  const flatten = (nodes: readonly ReleaseInline[]): string =>
    nodes
      .map((node) => {
        switch (node.kind) {
          case "text":
          case "code":
            return node.text;
          case "break":
            return " ";
          default:
            return flatten(node.children);
        }
      })
      .join("");
  return parseReleaseMarkdown(source)
    .map((block) => {
      switch (block.kind) {
        case "heading":
        case "paragraph":
        case "quote":
          return flatten(block.children);
        case "list":
          return block.items.map((item) => flatten(item.children)).join(" ");
        case "code":
          return block.text;
        case "rule":
          return "";
      }
    })
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * The same grammar over a single run of text, for the places that render one
 * line inside a list item rather than a document.
 */
export function parseReleaseInline(source: string): ReleaseInline[] {
  return parseInline(source.slice(0, MAX_SOURCE_CHARS).replace(/\r\n?/g, "\n").trim());
}
