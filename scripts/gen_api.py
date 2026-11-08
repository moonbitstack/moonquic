#!/usr/bin/env python3
"""Render the API reference and the site's counts from what the modules declare.

The public surface is read from every package's `pkg.generated.mbti`; the prose comes from the
`///` comments in the `.mbt` files beside it. Everything is sorted, so two runs on the same
sources produce byte-identical output and CI can hold the page to `git diff --exit-code`.

Usage: python scripts/gen_api.py
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
DOCS = REPO / "docs"

# The order a reader meets them in, and the one line each package gets at the top of its section.
PACKAGES = [
    ("frame", "Frames and acknowledgements: the payload of a packet."),
    ("packet", "Headers, packet numbers and the spaces they live in."),
    ("crypto", "Packet protection, header protection and the keys that drive them."),
    ("recovery", "Round-trip time, loss detection, congestion control and pacing."),
    ("stream", "Streams, both state machines, flow control and the send scheduler."),
    ("conn", "The transport itself: parameters, handshakes, paths and the event loop."),
]

# Methods that exist because a trait is implemented, not because a caller reaches for them by name.
TRAIT_METHODS = {
    "equal",
    "not_equal",
    "compare",
    "to_repr",
    "to_string",
    "output",
    "to_json",
    "from_json",
    "hash",
    "hash_combine",
}

DECL = re.compile(
    r"pub(?:\([a-z]+\))? (?:async )?"
    r"(fn|struct|enum|suberror|trait|typealias|let|const)\s*"
    r"(?:\[[^\]]*\]\s*)?"
    r"([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)?)"
)


def esc(text: str) -> str:
    return html.escape(text, quote=True)


def inline(text: str) -> str:
    """Escape, then make `backticked` runs code."""
    pieces = esc(text).split("`")
    return "".join(f"<code>{piece}</code>" if index % 2 else piece for index, piece in enumerate(pieces))


def docs_by_name(package_dir: Path) -> dict[str, str]:
    """Every `///` block in the package, keyed by the declaration it sits above."""
    found: dict[str, str] = {}
    for path in sorted(package_dir.rglob("*.mbt")):
        block: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("///"):
                text = stripped[3:].strip()
                block.append(text[1:].strip() if text.startswith("|") else text)
                continue
            if not block:
                continue
            match = DECL.match(stripped)
            if match:
                key = match.group(2)
                if key not in found:
                    found[key] = " ".join(part for part in block if part).strip()
                block = []
            elif not stripped.startswith("#") and stripped:
                block = []
    return found


def mbti_items(package_dir: Path) -> list[dict[str, str]]:
    """The declarations of one package, split by what kind of thing they are."""
    mbti = package_dir / "pkg.generated.mbti"
    if not mbti.exists():
        return []
    items: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in mbti.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if current is not None:
            if line.startswith("}"):
                current = None
                continue
            if line and not line.startswith("//"):
                field = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)", line)
                variant = re.match(r"([A-Z][A-Za-z0-9_]*)\s*(\(.*\))?$", line)
                if field:
                    current["fields"].append((field.group(1), field.group(2).rstrip(",")))
                elif variant and current["kind"] == "enum":
                    current["fields"].append((variant.group(1), (variant.group(2) or "").strip("()")))
            continue
        if not line.startswith("pub"):
            continue
        if " with " in line or line.startswith("pub impl") or line.startswith("pub extend"):
            continue
        match = DECL.match(line)
        if not match:
            continue
        keyword, name = match.group(1), match.group(2)
        if keyword == "fn":
            kind = "fn"
        elif keyword in ("let", "const"):
            kind = "value"
        else:
            kind = "enum" if keyword in ("enum", "suberror") else "type"
        item = {"kind": kind, "name": name, "sig": line, "fields": []}
        items.append(item)
        if kind in ("type", "enum") and line.startswith("pub(all)") and line.rstrip().endswith("{"):
            current = item
    return items


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def render_item(item: dict[str, str], docs: dict[str, str]) -> str:
    name = item["name"]
    bare = name.split("::")[-1]
    doc = docs.get(name) or docs.get(bare) or ""
    body = esc(item["sig"])
    body = re.sub(
        r"\b(pub(?:\([a-z]+\))?|fn|struct|enum|suberror|trait|typealias|let|mut)\b",
        r'<span class="kw">\1</span>',
        body,
    )
    tag = '<span class="item__tag">from a trait</span>' if bare in TRAIT_METHODS else ""
    doc_html = f'<p class="item__doc">{inline(doc)}</p>' if doc else ""
    rows = []
    for field, shape in item.get("fields", []):
        field_doc = docs.get(field, "")
        note = f'<span class="fieldnote">{inline(field_doc)}</span>' if field_doc else ""
        rows.append(
            f'<li><code>{esc(field)}</code>'
            + (f' <span class="shape">{esc(shape)}</span>' if shape else "")
            + note
            + "</li>"
        )
    fields_html = f'<ul class="itemfields">{"".join(rows)}</ul>' if rows else ""
    return (
        f'<div class="item" id="{slug(name)}">'
        f'<p class="item__sig">{body}{tag}</p>{doc_html}{fields_html}</div>'
    )


def package_html(package: str, note: str) -> tuple[str, int]:
    directory = SRC / package
    items = mbti_items(directory)
    if not items:
        return "", 0
    docs = docs_by_name(directory)
    groups = [
        ("Types", [item for item in items if item["kind"] in ("type", "enum")]),
        ("Values", [item for item in items if item["kind"] == "value"]),
        ("Functions", [item for item in items if item["kind"] == "fn"]),
    ]
    body: list[str] = []
    for title, subset in groups:
        if not subset:
            continue
        body.append(f'<h3 class="apigroup">{title}</h3>\n')
        for item in sorted(subset, key=lambda entry: entry["name"].lower()):
            body.append(render_item(item, docs) + "\n")
    html_section = (
        f'<section class="pkgsec" id="pkg-{package}">'
        f'<div class="pkgsec__head"><h2>{package}</h2><p>{esc(note)}</p></div>'
        f'<p class="apicount">moonbitstack/moonquic/{package} · {len(items)} public items</p>'
        f'{"".join(body)}</section>'
    )
    return html_section, len(items)


HEAD = """<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API — moonquic</title>
<meta name="description" content="Every public type, value and function of moonquic, generated from the packages' own interfaces.">
<meta name="theme-color" content="#f4eddf">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%23f4eddf'/%3E%3Cg fill='%2312181c'%3E%3Crect x='6' y='7' width='5' height='5'/%3E%3Crect x='14' y='7' width='5' height='5'/%3E%3Crect x='22' y='7' width='4' height='5'/%3E%3Crect x='6' y='19' width='5' height='5'/%3E%3Crect x='18' y='19' width='5' height='5'/%3E%3C/g%3E%3C/svg%3E">
<script>
  (function () {
    var KEY = "moonquic-theme", root = document.documentElement;
    var entry = performance.getEntriesByType("navigation")[0];
    try { if (entry && entry.type === "reload") sessionStorage.removeItem(KEY); } catch (e) {}
    var value = null;
    try { value = sessionStorage.getItem(KEY); } catch (e) {}
    if (!value) {
      value = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    root.dataset.theme = value;
  })();
</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Inter:wght@400;500&family=JetBrains+Mono:wght@400;500&display=swap">
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>

<header class="masthead">
  <div class="shell masthead__inner">
    <a class="brand" href="./" aria-label="moonquic, home">
      <svg class="brand__mark" viewBox="0 0 26 32" aria-hidden="true">
        <rect x="0.5" y="0.5" width="25" height="31" fill="none" stroke="currentColor" stroke-width="1"></rect>
        <g fill="currentColor">
          <rect x="5" y="6" width="4" height="4"></rect>
          <rect x="11" y="6" width="4" height="4"></rect>
          <rect x="18" y="6" width="3" height="4"></rect>
          <rect x="5" y="14" width="4" height="4"></rect>
          <rect x="15" y="14" width="4" height="4"></rect>
          <rect x="11" y="22" width="4" height="4"></rect>
          <rect x="18" y="22" width="3" height="4"></rect>
        </g>
      </svg>
      <span>
        <span class="brand__word">moonquic</span>
        <span class="brand__sub">quic transport</span>
      </span>
    </a>
    <nav class="nav" aria-label="Sections">
      <a href="./">Home</a>
      <a href="guide.html">Guide</a>
      <a href="api.html" aria-current="page">API</a>
      <a href="capture.html">Capture</a>
    </nav>
    <button class="iconbtn" type="button" data-theme-toggle aria-label="Switch theme" aria-pressed="false">
      <svg class="iconbtn__sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true">
        <circle cx="12" cy="12" r="4.2"></circle>
        <path d="M12 2.6v2.2M12 19.2v2.2M2.6 12h2.2M19.2 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M18.7 5.3l-1.6 1.6M6.9 17.1l-1.6 1.6"></path>
      </svg>
      <svg class="iconbtn__moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11z"></path>
      </svg>
    </button>
    <a class="iconbtn" href="https://github.com/moonbitstack/moonquic" aria-label="Repository on GitHub" title="Repository on GitHub">
      <svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path></svg>
    </a>
  </div>
</header>

<main id="main">
  <div class="shell" style="padding-block:clamp(36px,5vw,60px) 0">
    <header style="max-width:70ch">
      <p class="kicker">reference · generated</p>
      <h1 class="display" style="font-size:clamp(38px,5.4vw,62px)">Every public name</h1>
      <p class="lead" style="margin-top:16px">Read out of each package's interface and the comments
        beside it, so the page cannot drift from the code. <strong data-stat="items">0</strong> public
        items across <strong data-stat="packages">0</strong> packages.</p>
    </header>
  </div>
  <div class="shell">
    <div class="apigrid">
      <nav class="pkglist" aria-label="Packages">
"""

TAIL = """
<footer class="colophon">
  <div class="shell colophon__row">
    <span>moonquic · Apache-2.0 · <span data-stat="version">0.0.0</span></span>
    <span><a href="./">home</a> · <a href="guide.html">guide</a> · <a href="capture.html">capture</a></span>
    <span><a href="https://mooncakes.io/docs/moonbitstack/moonquic">mooncakes</a> · <a href="https://github.com/moonbitstack/moonquic">source</a></span>
  </div>
</footer>

<script src="assets/theme.js" defer></script>
<script src="assets/stats.js" defer></script>
</body>
</html>
"""


def main() -> None:
    mod = (REPO / "moon.mod").read_text(encoding="utf-8")
    version = re.search(r'version\s*=\s*"([^"]+)"', mod).group(1)

    sections: list[str] = []
    nav: list[str] = []
    total = 0
    for package, note in PACKAGES:
        rendered, count = package_html(package, note)
        if not rendered:
            continue
        sections.append(rendered)
        total += count
        nav.append(f'<a href="#pkg-{package}">{package}<span>{count}</span></a>')

    page = (
        HEAD
        + "".join(nav)
        + '</nav>\n<div class="apibody">'
        + "".join(sections)
        + "</div>\n</div>\n</div>\n</main>\n"
        + TAIL
    )
    page = page.replace('<strong data-stat="items">0</strong>', f'<strong data-stat="items">{total}</strong>')
    page = page.replace(
        '<strong data-stat="packages">0</strong>', f'<strong data-stat="packages">{len(sections)}</strong>'
    )
    (DOCS / "api.html").write_text(page, encoding="utf-8", newline="\n")

    stats = {
        "version": version,
        "packages": len(sections),
        "items": total,
    }
    (DOCS / "assets" / "stats.json").write_text(
        json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"api.html: {len(sections)} packages, {total} public items")


if __name__ == "__main__":
    main()
