import assert from "node:assert/strict";

import { parseReleaseMarkdown, releaseMarkdownToText, safeHref } from "./release-markdown";
import type { ReleaseBlock, ReleaseInline } from "./release-markdown";

function flatten(nodes: readonly ReleaseInline[]): string {
  return nodes
    .map((node) => (node.kind === "text" || node.kind === "code" ? node.text : node.kind === "break" ? "\n" : flatten(node.children)))
    .join("");
}

function only<T extends ReleaseBlock["kind"]>(blocks: ReleaseBlock[], kind: T): Extract<ReleaseBlock, { kind: T }>[] {
  return blocks.filter((block): block is Extract<ReleaseBlock, { kind: T }> => block.kind === kind);
}

// The real shape hol.org publishes: a lead paragraph with inline links and
// bold, "## " section headings, bullets that each end in a pull-request link,
// an install code fence, and a sign-off.
const PUBLISHED_NOTES = [
  "Guard 3.53.0a3 is an opt-in prerelease cut from [`c2da623`](https://github.com/hashgraph-online/hol-guard/commit/c2da623a).",
  "**11 commits • 11 merged pull requests • 1 contributor** since [Guard 3.53.0a2](https://github.com/hashgraph-online/hol-guard/releases/tag/alpha/v3.53.0a2).",
  "",
  "## Fixes",
  "",
  "- **extensions**: Repair a split catalog binding ([#5485](https://github.com/hashgraph-online/hol-guard/pull/5485))",
  "- **resident**: Wait for an exiting owner before spawning on Windows ([#5494](https://github.com/hashgraph-online/hol-guard/pull/5494))",
  "",
  "## Install",
  "",
  "Install the native alpha with `hol-guard update --alpha`.",
  "",
  "```bash",
  "hol-guard update --alpha",
  "```",
  "",
  "**Full changelog**: [alpha/v3.53.0a2...alpha/v3.53.0a3](https://github.com/hashgraph-online/hol-guard/compare/alpha/v3.53.0a2...alpha/v3.53.0a3)",
].join("\n");

// Published notes survive with their structure, not as one wall of text.
{
  const blocks = parseReleaseMarkdown(PUBLISHED_NOTES);
  const headings = only(blocks, "heading");
  assert.deepEqual(headings.map((heading) => flatten(heading.children)), ["Fixes", "Install"]);

  const lists = only(blocks, "list");
  assert.equal(lists.length, 1);
  assert.equal(lists[0].items.length, 2);
  assert.equal(lists[0].ordered, false);
  const [strong, , link] = lists[0].items[0].children;
  assert.equal(strong.kind, "strong");
  assert.equal(flatten([strong]), "extensions");
  assert.equal(link.kind, "link");
  assert.equal(link.kind === "link" ? link.href : "", "https://github.com/hashgraph-online/hol-guard/pull/5485");
  assert.equal(flatten([link]), "#5485");

  const code = only(blocks, "code");
  assert.equal(code.length, 1);
  assert.equal(code[0].language, "bash");
  assert.equal(code[0].text, "hol-guard update --alpha");

  // A compare link's own "..." and parentheses must not end the href early.
  const changelog = only(blocks, "paragraph").at(-1);
  assert.ok(changelog);
  const compare = changelog.children.find((node) => node.kind === "link");
  assert.equal(
    compare?.kind === "link" ? compare.href : "",
    "https://github.com/hashgraph-online/hol-guard/compare/alpha/v3.53.0a2...alpha/v3.53.0a3",
  );

  // The lead's two lines are one paragraph with a break, the way the release
  // page they come from renders them.
  const lead = only(blocks, "paragraph")[0];
  assert.ok(lead.children.some((node) => node.kind === "break"));
  assert.ok(flatten(lead.children).includes("c2da623"));
}

// An inline code span keeps its text and is not read as a fence.
{
  const [block] = parseReleaseMarkdown("Run `hol-guard status` first.");
  assert.equal(block.kind, "paragraph");
  const span = block.kind === "paragraph" ? block.children.find((node) => node.kind === "code") : undefined;
  assert.equal(span?.kind === "code" ? span.text : "", "hol-guard status");
}

// Only a web link stays clickable. Anything else keeps its text and loses the
// href, so upstream prose can never become a navigable scheme.
{
  assert.equal(safeHref("https://hol.org/guard"), "https://hol.org/guard");
  assert.equal(safeHref("http://localhost:8765/"), "http://localhost:8765/");
  assert.equal(safeHref("javascript:alert(1)"), null);
  assert.equal(safeHref("JavaScript:alert(1)"), null);
  assert.equal(safeHref("data:text/html,<script>"), null);
  assert.equal(safeHref("  java\nscript:alert(1)  "), null);
  assert.equal(safeHref(`https://hol.org/${"x".repeat(4000)}`), null);

  const [block] = parseReleaseMarkdown("[click me](javascript:alert(1))");
  assert.equal(block.kind, "paragraph");
  const nodes = block.kind === "paragraph" ? block.children : [];
  assert.equal(nodes.some((node) => node.kind === "link"), false);
  assert.equal(flatten(nodes), "click me");
}

// Raw HTML is text. The renderer never receives markup to pass through.
{
  const blocks = parseReleaseMarkdown("<img src=x onerror=alert(1)> and <b>bold</b>");
  assert.equal(releaseMarkdownToText("<img src=x onerror=alert(1)> and <b>bold</b>"), "<img src=x onerror=alert(1)> and <b>bold</b>");
  assert.equal(blocks.every((block) => block.kind === "paragraph"), true);
}

// An unterminated marker is literal text, not a swallowed rest-of-document.
{
  const [block] = parseReleaseMarkdown("A **bold start that never closes and [a link that does not");
  assert.equal(flatten(block.kind === "paragraph" ? block.children : []), "A **bold start that never closes and [a link that does not");
}

// Nested bullets stay attached to the bullet above them.
{
  const [block] = parseReleaseMarkdown(["- Parent", "  - Child one", "  - Child two", "- Second parent"].join("\n"));
  assert.equal(block.kind, "list");
  const items = block.kind === "list" ? block.items : [];
  assert.equal(items.length, 2);
  assert.deepEqual(items[0].items.map((item) => flatten(item.children)), ["Child one", "Child two"]);
  assert.equal(flatten(items[1].children), "Second parent");
}

// Ordered lists, quotes and rules each keep their own shape.
{
  const blocks = parseReleaseMarkdown(["1. First", "2. Second", "", "> Quoted warning", "", "---"].join("\n"));
  assert.equal(only(blocks, "list")[0].ordered, true);
  assert.equal(flatten(only(blocks, "quote")[0].children), "Quoted warning");
  assert.equal(only(blocks, "rule").length, 1);
}

// A heading deeper than the panel's three ranks clamps instead of emitting an
// element the page's outline has no room for.
{
  const blocks = parseReleaseMarkdown("###### Deep heading");
  assert.equal(only(blocks, "heading")[0].level, 3);
}

// A bare URL on its own is a link, and the sentence keeps its full stop.
{
  const [block] = parseReleaseMarkdown("See https://hol.org/guard/releases.");
  const nodes = block.kind === "paragraph" ? block.children : [];
  const link = nodes.find((node) => node.kind === "link");
  assert.equal(link?.kind === "link" ? link.href : "", "https://hol.org/guard/releases");
  assert.equal(flatten(nodes), "See https://hol.org/guard/releases.");
}

// Pathological input terminates and stays bounded rather than hanging the tab.
{
  const started = Date.now();
  const blocks = parseReleaseMarkdown("*".repeat(20_000) + "\n" + "- item\n".repeat(5_000) + "[".repeat(5_000));
  assert.ok(Date.now() - started < 4_000, "parsing pathological markdown must not hang");
  assert.ok(blocks.length <= 1_000);
  assert.ok(only(blocks, "list").every((list) => list.items.length <= 500));
}

// The plain-text projection drops markup instead of showing it, for the one
// line of summary that has no room to render structure.
{
  assert.equal(
    releaseMarkdownToText("**11 commits** since [Guard 3.53.0a2](https://github.com/x/y).\n\n## Fixes\n\n- A `fix`"),
    "11 commits since Guard 3.53.0a2. Fixes A fix",
  );
}

console.log("release-markdown tests passed");
