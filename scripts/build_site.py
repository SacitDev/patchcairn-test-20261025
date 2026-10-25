#!/usr/bin/env python3
"""Build only the reviewed static documentation, using Python's standard library.

No network, template evaluation, directory archive, or maintenance operation.
CLI output stays beneath work/site/; source-root fixtures stay beneath
work/site/tests/. Neither boundary adopts or moves older preview trees.
Use an owner-controlled quiet source/output tree; this is not an OS sandbox.
"""
from __future__ import annotations

import argparse
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import sys
from urllib.parse import unquote, urlsplit
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
OUTPUT_BOUNDARY = PurePosixPath("work/site")
FIXTURE_BOUNDARY = OUTPUT_BOUNDARY / "tests"
LOGO_SHA256 = "762b084643a18e022ce08156c39d728b645e1f40fc5c83c76c62385d65ab06ca"
# These two literals are reviewed release inputs, not a general JavaScript or
# image discovery mechanism. Update their hashes only after source review.
ENHANCEMENTS_SHA256 = "b24c2e2c0ed63ee003c4484d5690ccd148f34929732aabd8b06ebaf943b230e9"
HERO_SHA256 = "a444648c306797487a08ca0cccf386fbcf27046eda3138e81d9e1ed989743001"
SITE_CSP = "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'"
REPOSITORY_NOTICE = "GitHub repository link not configured"
REPOSITORY_FALLBACK = '<span class="repository-link" aria-disabled="true" title="' + REPOSITORY_NOTICE + '" aria-label="' + REPOSITORY_NOTICE + '">GitHub</span>'
MAX_SOURCE_BYTES = 2_000_000
# The manifest lists this builder's own inputs and outputs; it is not a PatchCairn record and carries no schema fields.
SITE_GENERATOR = "patchcairn-site-builder"
# Exact positive allowlist. No glob, discovery, recursive source copy, or work input.
PAGES = {
    "docs/GETTING_STARTED.md": "guides/getting-started.html",
    "docs/YOUR_FIRST_RUN.md": "guides/your-first-run.html",
    "docs/FAQ.md": "guides/faq.html",
    "docs/CONTRIBUTING.md": "guides/contributing.html",
    "docs/PLATFORM_SUPPORT.md": "guides/platform-support.html",
    "docs/WORKFLOW_ENGINE.md": "guides/workflow-engine.html",
    "docs/SERVICE_INTEGRATION.md": "guides/service-integration.html",
    "docs/STORAGE_BACKUP_API.md": "guides/storage-backup.html",
    "docs/DIAGNOSTIC_API.md": "guides/diagnostics.html",
    "docs/TOOLS.md": "guides/tools.html",
    "docs/ARCHITECTURE.md": "guides/architecture.html",
    "docs/ASSISTANT_COMPATIBILITY.md": "guides/assistant-compatibility.html",
    "docs/SCOPED_FILESYSTEM.md": "guides/scoped-filesystem.html",
    "docs/WINDOWS_ADAPTER.md": "guides/windows-adapter.html",
    "docs/DIAGNOSIS_EXAMPLE.md": "guides/diagnosis-example.html",
    "docs/GITHUB_SETUP.md": "guides/github-setup.html",
    "docs/UTC_PUBLICATION.md": "guides/utc-publication.html",
    "SECURITY.md": "guides/security.html",
    "RECOVERY_AND_CLEANUP.md": "guides/recovery.html",
    "AGENTS.md": "guides/working-agreement.html",
    "WORKFLOW.md": "guides/maintenance-workflow.html",
    "PUBLICATION.md": "guides/publication.html",
    "PROMPTS.md": "guides/prompts.html",
    "references/COMMUNICATION.md": "guides/communication.html",
    "references/SOURCES_AND_RESEARCH.md": "guides/source-research.html",
    "references/COMPATIBILITY.md": "guides/compatibility.html",
    "references/AGENTS_AND_DECISIONS.md": "guides/agents-decisions.html",
    "references/LINUX.md": "guides/linux.html",
    "references/MACOS.md": "guides/macos.html",
    "references/DIAGNOSIS.md": "guides/diagnosis-reference.html",
    "references/SECURITY_UPDATES_WORKFLOW.md": "guides/security-updates-workflow.html",
    "references/DIAGNOSIS_WORKFLOW.md": "guides/diagnosis-workflow.html",
    "references/STORAGE_CLEANUP_WORKFLOW.md": "guides/storage-cleanup-workflow.html",
    "references/BACKUP_RECOVERY_WORKFLOW.md": "guides/backup-recovery-workflow.html",
}
COPIES = {
    "site/styles.css": "styles.css",
    "site/enhancements.js": "enhancements.js",
    "assets/patchcairn-logo.png": "assets/patchcairn-logo.png",
    "assets/night-circuit-hero.png": "assets/night-circuit-hero.png",
    "LICENSE": "reference/LICENSE.txt",
    "templates/tool-catalog.json": "reference/tool-catalog.json",
}
PUBLIC_SOURCES = tuple(["site/index.html", *PAGES, *COPIES])
LINK_TARGETS = {**PAGES, **COPIES, "README.md": "index.html", "site/index.html": "index.html"}


class SiteRefusal(ValueError):
    """A site boundary or input failed validation."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def no_links(path: Path, *, directory: bool | None = None) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise SiteRefusal("Links and reparse points are not site inputs or outputs")
    if directory is True and not stat.S_ISDIR(info.st_mode):
        raise SiteRefusal("Expected an ordinary directory")
    if directory is False and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise SiteRefusal("Expected an ordinary single-link file")
    return info


def checked_path(root: Path, relative: str, *, exists: bool = True) -> Path:
    if not isinstance(relative, str) or "\\" in relative or ":" in relative or "\x00" in relative:
        raise SiteRefusal("Invalid site-relative path")
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute() or any(p in (".", "..") for p in relative.split("/")):
        raise SiteRefusal("Site path must be a plain relative path")
    no_links(root, directory=True)
    current = root
    for index, part in enumerate(parts):
        current = current / part
        if current.exists() or current.is_symlink():
            no_links(current, directory=True if index < len(parts) - 1 else None)
        elif exists:
            raise SiteRefusal("A required public source or output is missing: " + relative)
    return current


def read_regular(root: Path, relative: str) -> bytes:
    path = checked_path(root, relative)
    before = no_links(path, directory=False)
    if before.st_size > MAX_SOURCE_BYTES:
        raise SiteRefusal("Public source exceeds its size bound")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
            raise SiteRefusal("Public file changed while opening")
        data = stream.read(MAX_SOURCE_BYTES + 1)
    after = no_links(path, directory=False)
    if len(data) > MAX_SOURCE_BYTES or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise SiteRefusal("Public file changed while reading")
    return data


def repository_url(value: str | None) -> str | None:
    if value is None:
        return None
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}", value):
        raise SiteRefusal("Repository link must be an explicit HTTPS GitHub owner/repository URL")
    if value.rsplit("/", 1)[1] in (".", ".."):
        raise SiteRefusal("Invalid repository name")
    return value


def repository_markup(repository: str | None) -> str:
    repository = repository_url(repository)
    return '<a class="repository-link" href="' + html.escape(repository, quote=True) + '">GitHub ↗</a>' if repository else REPOSITORY_FALLBACK


def slug(value: str) -> str:
    value = re.sub(r"[`*_]", "", value).lower()
    value = re.sub(r"[^a-z0-9\s-]", "", value)
    return re.sub(r"\s+", "-", value.strip()) or "section"


def safe_url(value: str) -> tuple[str, str]:
    if not value or any(ord(c) < 32 for c in value) or "\\" in value:
        raise SiteRefusal("Empty or unsafe public URL")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise SiteRefusal("Public links must use HTTPS and contain no credentials")
        hostname = parsed.hostname.lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9.-]+", hostname) or "." not in hostname or hostname.endswith((".local", ".localhost", ".internal")):
            raise SiteRefusal("Local service URLs do not belong in the public site")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
        if hostname == "localhost" or address is not None and not address.is_global:
            raise SiteRefusal("Local service URLs do not belong in the public site")
        return "external", value
    decoded = unquote(parsed.path)
    if unquote(decoded) != decoded or ":" in decoded or "\\" in decoded or decoded.startswith("/") or parsed.query:
        raise SiteRefusal("Unsafe or nonportable local URL")
    return "local", value


def markdown_link(label: str, target: str, source: str, repository: str | None) -> str:
    kind, _ = safe_url(target)
    escaped_label = html.escape(label)
    if kind == "external":
        return '<a href="' + html.escape(target, quote=True) + '">' + escaped_label + '</a>'
    parsed = urlsplit(target)
    normalized = posixpath.normpath(posixpath.join(posixpath.dirname(source), unquote(parsed.path))) if parsed.path else source
    if normalized == ".." or normalized.startswith("../"):
        raise SiteRefusal("Markdown reference escapes the source package")
    mapped = LINK_TARGETS.get(normalized)
    if mapped:
        href = posixpath.relpath(mapped, "guides")
        if parsed.fragment:
            href += "#" + parsed.fragment
        return '<a href="' + html.escape(href, quote=True) + '">' + escaped_label + '</a>'
    # Non-published source code/schema stays a source-package reference. Do not
    # create dead file URLs, infer a Git branch, or copy arbitrary referenced files.
    return '<span class="source-reference">' + escaped_label + ' <small>(source package: <code>' + html.escape(normalized) + '</code>)</small></span>'


def inline(value: str, source: str, repository: str | None) -> str:
    result = []
    pattern = re.compile(r"(`+)(.+?)\1|\[([^\]\n]+)\]\(([^)\s]+)\)|\*\*(.+?)\*\*")
    cursor = 0
    for match in pattern.finditer(value):
        result.append(html.escape(value[cursor:match.start()]))
        if match.group(1):
            result.append("<code>" + html.escape(match.group(2)) + "</code>")
        elif match.group(3):
            result.append(markdown_link(match.group(3), match.group(4), source, repository))
        else:
            result.append("<strong>" + html.escape(match.group(5)) + "</strong>")
        cursor = match.end()
    result.append(html.escape(value[cursor:]))
    return "".join(result)


class RenderedText(HTMLParser):
    """Read text only from already escaped/rendered fragments; never reuse markup."""
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def rendered_text(fragment: str) -> str:
    parser = RenderedText()
    parser.feed(fragment)
    return " ".join("".join(parser.parts).split())


def render_markdown(text: str, source: str, repository: str | None = None) -> tuple[str, str]:
    """Small inert Markdown subset: headings, lists, tables, quotes, fences.

    Raw HTML is escaped; no extensions, includes, JavaScript, or template code.
    Unsupported syntax remains readable literal text rather than executing.
    """
    lines = text.replace("\r\n", "\n").splitlines()
    output, paragraph, headings = [], [], {}
    title = "PatchCairn guide"
    heading_context = ""
    list_tag = None
    index = 0

    def flush() -> None:
        if paragraph:
            output.append("<p>" + inline(" ".join(paragraph), source, repository) + "</p>")
            paragraph.clear()

    def close_list() -> None:
        nonlocal list_tag
        if list_tag:
            output.append("</" + list_tag + ">")
            list_tag = None

    def cells(line: str) -> list[str]:
        return [part.strip().replace("\\|", "|") for part in re.split(r"(?<!\\)\|", line.strip().strip("|"))]

    while index < len(lines):
        line = lines[index]
        if line.startswith("```") or line.startswith("~~~"):
            flush(); close_list()
            fence = line[:3]
            language = line[3:].strip().lower()
            code = []
            index += 1
            while index < len(lines) and not lines[index].startswith(fence):
                code.append(lines[index]); index += 1
            if index == len(lines):
                raise SiteRefusal("Unclosed Markdown code block in " + source)
            if language == "mermaid":
                output.append('<details class="diagram-source"><summary>View Mermaid source</summary><p class="diagram-source-note">GitHub renders this diagram. This static guide keeps its source here; the surrounding text explains the sequence.</p><pre role="region" aria-label="Mermaid diagram source" tabindex="0"><code>' + html.escape("\n".join(code)) + '</code></pre></details>')
            else:
                label = "Code example" + (": " + heading_context[:180] if heading_context else "")
                output.append('<pre role="region" aria-label="' + html.escape(label, quote=True) + '" tabindex="0"><code>' + html.escape("\n".join(code)) + "</code></pre>")
        elif re.match(r"^#{1,6} ", line):
            flush(); close_list()
            heading, value = line.split(" ", 1)
            base = slug(value)
            count = headings.get(base, 0)
            headings[base] = count + 1
            anchor = base if count == 0 else base + "-" + str(count)
            if len(heading) == 1:
                title = re.sub(r"[`*_]", "", value)
            value_html = inline(value, source, repository)
            heading_context = rendered_text(value_html)
            output.append('<h' + str(len(heading)) + ' id="' + anchor + '">' + value_html + '</h' + str(len(heading)) + '>')
        elif index + 1 < len(lines) and "|" in line and re.fullmatch(r"[\s|:-]+", lines[index + 1]) and "-" in lines[index + 1]:
            flush(); close_list()
            label = "Reference table" + (": " + heading_context[:180] if heading_context else "")
            output.append('<div class="table-scroll" role="region" aria-label="' + html.escape(label, quote=True) + '" tabindex="0"><table><thead><tr>')
            output.extend('<th scope="col">' + inline(cell, source, repository) + '</th>' for cell in cells(line))
            output.append("</tr></thead><tbody>")
            index += 2
            while index < len(lines) and "|" in lines[index] and lines[index].strip():
                output.append("<tr>" + "".join("<td>" + inline(cell, source, repository) + "</td>" for cell in cells(lines[index])) + "</tr>")
                index += 1
            output.append("</tbody></table></div>")
            continue
        elif line.startswith(">"):
            flush(); close_list()
            quote = []
            while index < len(lines) and lines[index].startswith(">"):
                quote.append(lines[index][1:].lstrip()); index += 1
            output.append("<blockquote><p>" + inline(" ".join(quote), source, repository) + "</p></blockquote>")
            continue
        elif re.match(r"^\s*(?:[-*] |\d+\. )", line):
            flush()
            match = re.match(r"^\s*([-*]|\d+\.) (.*)$", line)
            tag = "ul" if match.group(1) in ("-", "*") else "ol"
            if tag != list_tag:
                close_list(); list_tag = tag; output.append("<" + tag + ">")
            output.append("<li>" + inline(match.group(2), source, repository) + "</li>")
        elif not line.strip():
            flush(); close_list()
        elif line.strip() in ("---", "***", "___"):
            flush(); close_list(); output.append("<hr>")
        else:
            close_list(); paragraph.append(line.strip())
        index += 1
    flush(); close_list()
    return title, "\n".join(output)


GUIDE_GROUPS = (
    ("Get started", (("docs/YOUR_FIRST_RUN.md", "Your first run"), ("docs/GETTING_STARTED.md", "Setup and first session"), ("docs/FAQ.md", "Common questions"), ("docs/ASSISTANT_COMPATIBILITY.md", "Assistant capabilities"), ("PROMPTS.md", "Prompt examples"))),
    ("Jobs and workflows", (("references/SECURITY_UPDATES_WORKFLOW.md", "Security updates"), ("references/STORAGE_CLEANUP_WORKFLOW.md", "Storage cleanup"), ("references/DIAGNOSIS_WORKFLOW.md", "Diagnosis and repair"), ("references/BACKUP_RECOVERY_WORKFLOW.md", "Backup and recovery"), ("WORKFLOW.md", "Maintenance workflow"), ("docs/DIAGNOSIS_EXAMPLE.md", "Diagnosis example"), ("references/DIAGNOSIS.md", "Diagnosis reference"))),
    ("Safety and requirements", (("docs/PLATFORM_SUPPORT.md", "Platform support"), ("docs/TOOLS.md", "Official tools"), ("SECURITY.md", "Security and privacy"), ("RECOVERY_AND_CLEANUP.md", "Recovery and cleanup"), ("references/COMMUNICATION.md", "Communication"), ("references/COMPATIBILITY.md", "Compatibility"))),
    ("Technical reference", (("docs/WORKFLOW_ENGINE.md", "Workflow engine"), ("docs/SERVICE_INTEGRATION.md", "Service integration"), ("docs/STORAGE_BACKUP_API.md", "Storage and backup API"), ("docs/DIAGNOSTIC_API.md", "Diagnostic API"), ("docs/ARCHITECTURE.md", "Architecture"), ("docs/SCOPED_FILESYSTEM.md", "Scoped filesystem"), ("docs/WINDOWS_ADAPTER.md", "Windows adapter"), ("references/AGENTS_AND_DECISIONS.md", "Agents and decisions"), ("references/LINUX.md", "Linux reference"), ("references/MACOS.md", "macOS reference"))),
    ("Project", (("docs/CONTRIBUTING.md", "Contributing"), ("AGENTS.md", "Working agreement"), ("references/SOURCES_AND_RESEARCH.md", "Sources and research"), ("PUBLICATION.md", "Public package"), ("docs/GITHUB_SETUP.md", "GitHub and Pages"), ("docs/UTC_PUBLICATION.md", "UTC publication"))),
)


class RenderedOutline(HTMLParser):
    """Collect actual rendered heading IDs and text; never import heading markup."""
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items, self.seen = [], set()
        self.level, self.anchor, self.parts = None, None, []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in ("h2", "h3"):
            return
        if self.level is not None:
            raise SiteRefusal("Nested rendered headings cannot form a page outline")
        anchor = dict(attrs).get("id")
        if not isinstance(anchor, str) or not re.fullmatch(r"[a-z0-9-]+", anchor) or anchor in self.seen:
            raise SiteRefusal("Page outline requires actual unique safe rendered heading IDs")
        self.seen.add(anchor)
        self.level, self.anchor, self.parts = int(tag[1]), anchor, []

    def handle_data(self, data: str) -> None:
        if self.level is not None:
            self.parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self.level is not None and tag == "h" + str(self.level):
            label = " ".join("".join(self.parts).split())
            if label:
                self.items.append({"level": self.level, "anchor": self.anchor, "label": label})
            self.level, self.anchor, self.parts = None, None, []


def outline_items(body: str) -> list[dict]:
    parser = RenderedOutline()
    parser.feed(body)
    if parser.level is not None:
        raise SiteRefusal("Unclosed rendered heading")
    # Long reference pages get a compact h2 outline; short pages can include h3.
    return parser.items if len(parser.items) <= 12 else [item for item in parser.items if item["level"] == 2]


def guide_navigation(destination: str) -> tuple[str, str, str]:
    sources = [source for _, group in GUIDE_GROUPS for source, _ in group]
    if len(sources) != len(set(sources)) or set(sources) != set(PAGES):
        raise SiteRefusal("Documentation navigation must cover every exact public guide once")
    groups, selected_group, selected_label = [], None, None
    for group_label, entries in GUIDE_GROUPS:
        links = []
        for source, label in entries:
            target = PAGES[source]
            current = target == destination
            if current:
                selected_group, selected_label = group_label, label
            links.append('<li><a href="' + html.escape(PurePosixPath(target).name, quote=True) + '"' + (' aria-current="page"' if current else '') + '>' + html.escape(label) + '</a></li>')
        is_current_group = any(PAGES[source] == destination for source, _ in entries)
        groups.append('<details class="nav-group"' + (' open' if is_current_group else '') + '><summary>' + html.escape(group_label) + '</summary><ul>' + ''.join(links) + '</ul></details>')
    if selected_label is None:
        raise SiteRefusal("Current guide is outside the exact documentation navigation")
    return ''.join(groups), selected_group, selected_label


def guide_html(title: str, body: str, destination: str, repository: str | None) -> str:
    navigation, group_label, page_label = guide_navigation(destination)
    outline = outline_items(body)
    outline_links = ''.join('<li' + (' class="outline-sub"' if item['level'] == 3 else '') + '><a href="#' + html.escape(item['anchor'], quote=True) + '">' + html.escape(item['label']) + '</a></li>' for item in outline)
    outline_list = '<ul class="outline-list">' + outline_links + '</ul>'
    mobile_outline = '<details class="mobile-toc"><summary>On this page</summary><nav aria-label="On this page, compact">' + outline_list + '</nav></details>' if outline else ''
    h1_end = body.find('</h1>')
    if h1_end < 0:
        raise SiteRefusal("A guide requires its rendered title before the page outline")
    outline_jump = '<a class="outline-jump" href="#page-outline">On this page</a>' if outline else ''
    sections = [position for tag in ('<h2 ', '<h3 ') if (position := body.find(tag, h1_end + 5)) >= 0]
    tools_position = min(sections) if sections else len(body)
    article = body[:tools_position] + outline_jump + mobile_outline + body[tools_position:]
    desktop_outline = '<aside class="page-outline" id="page-outline" tabindex="-1"><nav aria-label="On this page"><p class="outline-label">On this page</p>' + outline_list + '</nav></aside>' if outline else ''
    repo = repository_markup(repository)
    breadcrumbs = '<nav class="breadcrumbs" aria-label="Breadcrumb"><ol><li><a href="../index.html">Docs</a></li><li>' + html.escape(group_label) + '</li><li aria-current="page">' + html.escape(page_label) + '</li></ol></nav>'
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark"><meta http-equiv="Content-Security-Policy" content="''' + SITE_CSP + '''">
<title>''' + html.escape(title) + ''' — PatchCairn</title><link rel="stylesheet" href="../styles.css"><script src="../enhancements.js" defer></script></head><body>
<a class="skip-link" href="#main">Skip to content</a><header class="site-header"><div class="header-inner"><a class="brand" href="../index.html" aria-label="PatchCairn documentation home"><img src="../assets/patchcairn-logo.png" alt="PatchCairn" width="156" height="52"></a><span class="header-label">Documentation</span><nav aria-label="Main navigation"><a href="../index.html">Overview</a><a href="your-first-run.html">Your first run</a><a href="../index.html#guides">Guides</a>''' + repo + '''</nav></div></header>
<details class="mobile-doc-nav"><summary>Browse documentation</summary><nav aria-label="Documentation, compact">''' + navigation + '''</nav></details>
<div class="docs-shell"><aside class="docs-sidebar"><nav aria-label="Documentation">''' + navigation + '''</nav></aside><main class="document" id="main">''' + breadcrumbs + article + '''<p class="document-note">Developed by Michael. Private session records belong locally under <code>work/</code>; this public guide contains no live computer records.</p></main>''' + desktop_outline + '''</div>
<footer class="site-footer"><div class="footer-inner"><p>PatchCairn documentation · Developed by Michael</p><a href="../reference/LICENSE.txt">MIT License</a><a href="#main">Back to top</a></div></footer></body></html>'''


class PublicHTML(HTMLParser):
    """Validate this site's literal markup, never a general HTML sanitizer.

    The single reviewed enhancement script changes presentation only and has no
    maintenance or host controls.
    Decorative SVG is restricted to inert drawing primitives, without URL
    references, embedded content, animation elements, or namespace switches.
    """
    HTML_TAGS = frozenset("html head meta title link body a header div span nav main section aside article figure figcaption p h1 h2 h3 h4 h5 h6 img pre code strong em small ul ol li dl dt dd blockquote hr br table thead tbody tr th td details summary footer script".split())
    SVG_TAGS = frozenset("svg g path circle rect line polyline polygon ellipse title desc".split())
    SVG_ATTRIBUTES = {
        "svg": {"viewbox", "width", "height", "fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "aria-hidden", "role", "class", "focusable", "preserveaspectratio"},
        "g": {"fill", "stroke", "stroke-width", "class", "opacity", "stroke-linecap", "stroke-linejoin"},
        "path": {"d", "fill", "stroke", "stroke-width", "class", "opacity", "stroke-linecap", "stroke-linejoin", "stroke-dasharray", "stroke-dashoffset"},
        "circle": {"cx", "cy", "r", "fill", "stroke", "stroke-width", "class", "opacity"},
        "rect": {"x", "y", "width", "height", "rx", "ry", "fill", "stroke", "stroke-width", "class", "opacity"},
        "line": {"x1", "y1", "x2", "y2", "stroke", "stroke-width", "class", "opacity", "stroke-linecap", "stroke-dasharray", "stroke-dashoffset"},
        "polyline": {"points", "fill", "stroke", "stroke-width", "class", "opacity", "stroke-linecap", "stroke-linejoin"},
        "polygon": {"points", "fill", "stroke", "stroke-width", "class", "opacity"},
        "ellipse": {"cx", "cy", "rx", "ry", "fill", "stroke", "stroke-width", "class", "opacity"},
        "title": set(), "desc": set(),
    }
    COMMON_ATTRIBUTES = frozenset({"id", "class", "title", "role", "aria-label", "aria-labelledby", "aria-describedby", "aria-hidden", "aria-current", "tabindex"})
    HTML_ATTRIBUTES = {
        "html": {"lang"}, "meta": {"charset", "name", "content", "http-equiv"},
        "link": {"rel", "href"}, "a": {"href"},
        "img": {"src", "alt", "width", "height", "loading", "decoding", "fetchpriority"},
        "th": {"scope"}, "details": {"open"}, "script": {"src", "defer"}, "span": {"aria-disabled"},
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links, self.ids, self.tags = [], set(), []
        self.headings, self.lang, self.viewport, self.main = [], False, False, 0
        self.scripts, self.repository_fallbacks, self.csp = [], 0, []
        self.script_open, self.svg_stack = False, []

    def validate_svg(self, tag: str, attributes: dict) -> None:
        if tag not in self.SVG_TAGS or set(attributes) - self.SVG_ATTRIBUTES[tag]:
            raise SiteRefusal("Only reviewed inert SVG drawing attributes and primitives are allowed")
        for key, value in attributes.items():
            if not isinstance(value, str):
                raise SiteRefusal("SVG attributes require literal values")
            if key in {"fill", "stroke"}:
                valid = re.fullmatch(r"(?:none|currentColor|#[a-fA-F0-9]{3}(?:[a-fA-F0-9]{3})?)", value)
            elif key == "d":
                valid = re.fullmatch(r"[MmZzLlHhVvCcSsQqTtAa0-9.,+\-\s]+", value)
            elif key in {"viewbox", "points", "stroke-dasharray"}:
                valid = re.fullmatch(r"[0-9.,+\-\s]+", value)
            elif key == "class":
                valid = re.fullmatch(r"[A-Za-z0-9_\- ]+", value)
            elif key == "stroke-linecap":
                valid = value in {"butt", "round", "square"}
            elif key == "stroke-linejoin":
                valid = value in {"miter", "round", "bevel"}
            elif key == "aria-hidden":
                valid = value == "true"
            elif key == "focusable":
                valid = value == "false"
            elif key == "preserveaspectratio":
                valid = value == "none"
            elif key == "role":
                valid = value == "img"
            else:
                valid = re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", value)
            if not valid:
                raise SiteRefusal("SVG attributes must be safe literal drawing values")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if len(attributes) != len(attrs):
            raise SiteRefusal("Duplicate HTML attribute")
        self.tags.append(tag)
        if any(key.startswith("on") or key in {"style", "srcdoc", "srcset", "ping"} for key in attributes):
            raise SiteRefusal("Active or inline HTML attributes are not allowed")
        if self.svg_stack or tag == "svg":
            if tag == "svg" and self.svg_stack:
                raise SiteRefusal("Nested SVG is outside the reviewed drawing contract")
            self.validate_svg(tag, attributes)
            self.svg_stack.append(tag)
            return
        if tag not in self.HTML_TAGS:
            raise SiteRefusal("The public site contains an unreviewed HTML element")
        if set(attributes) - (self.COMMON_ATTRIBUTES | self.HTML_ATTRIBUTES.get(tag, set())):
            raise SiteRefusal("The public site contains an unreviewed HTML attribute")
        if any(value is None and key not in {"defer", "open"} for key, value in attrs):
            raise SiteRefusal("HTML attributes require literal values except reviewed boolean attributes")
        if "tabindex" in attributes and attributes["tabindex"] not in {"-1", "0"}:
            raise SiteRefusal("Public focus targets cannot change the tab order")
        if tag == "script":
            if set(attributes) != {"src", "defer"} or attributes["src"] not in {"enhancements.js", "../enhancements.js"} or attributes["defer"] not in {None, ""}:
                raise SiteRefusal("Only the exact local deferred classic enhancement script is allowed")
            if self.script_open:
                raise SiteRefusal("Nested scripts are not allowed")
            self.script_open = True
            self.scripts.append(attributes["src"])
        elif "aria-disabled" in attributes:
            if tag != "span" or attributes != {"class": "repository-link", "aria-disabled": "true", "title": REPOSITORY_NOTICE, "aria-label": REPOSITORY_NOTICE}:
                raise SiteRefusal("Only the exact inactive repository navigation notice is allowed")
            self.repository_fallbacks += 1
            if self.repository_fallbacks > 1:
                raise SiteRefusal("Only one repository navigation notice is allowed")
        elif tag == "link":
            if set(attributes) != {"rel", "href"} or attributes["rel"] != "stylesheet" or attributes["href"] not in {"styles.css", "../styles.css"}:
                raise SiteRefusal("Only the exact local stylesheet resource is allowed")
        elif tag == "meta":
            if "http-equiv" in attributes:
                if attributes["http-equiv"].lower() != "content-security-policy" or attributes.get("content") != SITE_CSP or set(attributes) != {"http-equiv", "content"}:
                    raise SiteRefusal("The public site requires its exact restrictive content security policy")
                self.csp.append(attributes["content"])
            elif set(attributes) not in ({"charset"}, {"name", "content"}):
                raise SiteRefusal("Unreviewed metadata attributes")
            elif "name" in attributes and attributes["name"] not in {"viewport", "description", "color-scheme"}:
                raise SiteRefusal("Unreviewed metadata name")
        elif any(key in attributes for key in {"formaction", "action", "method", "autofocus", "contenteditable", "download", "manifest", "xmlns", "xlink:href"}):
            raise SiteRefusal("Document controls and namespace switches are not allowed")
        if "src" in attributes and tag not in {"img", "script"} or "href" in attributes and tag not in {"a", "link"}:
            raise SiteRefusal("Resource attributes are restricted to their reviewed elements")
        if tag == "html":
            self.lang = attributes.get("lang") == "en"
        if tag == "meta" and attributes.get("name") == "viewport":
            self.viewport = "width=device-width" in attributes.get("content", "")
        if tag == "main":
            self.main += 1
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append(int(tag[1]))
        if "id" in attributes:
            if not attributes["id"] or attributes["id"] in self.ids:
                raise SiteRefusal("Empty or duplicate HTML anchor")
            self.ids.add(attributes["id"])
        if tag == "img" and not attributes.get("alt"):
            raise SiteRefusal("Public images require descriptive alternative text")
        if tag == "img" and attributes.get("src") not in {"assets/patchcairn-logo.png", "../assets/patchcairn-logo.png", "assets/night-circuit-hero.png", "../assets/night-circuit-hero.png"}:
            raise SiteRefusal("Only exact reviewed local images are allowed")
        if tag == "nav" and not attributes.get("aria-label"):
            raise SiteRefusal("Navigation needs an accessible name")
        for attribute in ("href", "src"):
            if attribute in attributes:
                kind, _ = safe_url(attributes[attribute])
                if kind == "external" and (tag != "a" or attribute != "href"):
                    raise SiteRefusal("All site resources must be local for offline use")
                self.links.append(attributes[attribute])

    def handle_data(self, data: str) -> None:
        if self.script_open and data.strip():
            raise SiteRefusal("Inline script content is not allowed")

    def handle_endtag(self, tag: str) -> None:
        if self.svg_stack:
            if tag != self.svg_stack[-1]:
                raise SiteRefusal("SVG drawing markup must be correctly nested")
            self.svg_stack.pop()
        elif tag == "script":
            if not self.script_open:
                raise SiteRefusal("Unexpected script closing tag")
            self.script_open = False

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            raise SiteRefusal("The deferred classic script requires an explicit closing tag")
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)


def validate_motion_css(css: str) -> dict:
    """Conservative checks for this site's reviewed literal CSS motion contract.

    This is not a general CSS interpreter or a substitute for rendered QA.
    Reviewed feedback has one literal iteration, lasts at most four seconds
    including delay, and is gated on the ordinary-motion system preference.
    """
    clean = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    reduced = re.search(r"@media\s*\(\s*prefers-reduced-motion\s*:\s*reduce\s*\)\s*\{", clean)
    if reduced is None:
        raise SiteRefusal("Motion requires a complete reduced-motion alternative")
    start, depth, end = reduced.end(), 1, reduced.end()
    while end < len(clean) and depth:
        depth += (clean[end] == "{") - (clean[end] == "}")
        end += 1
    if depth:
        raise SiteRefusal("Unclosed reduced-motion block")
    body = re.sub(r"\s+", "", clean[start:end - 1])
    for required in ("*,*::before,*::after", "animation:none!important", "transition:none!important", "transform:none!important", "scroll-behavior:auto!important"):
        if required not in body:
            raise SiteRefusal("Reduced motion must cover animations, pseudo-elements, transitions, transforms and scrolling")
    if re.search(r"(?<![\w-])(?:-\w+-)?animation-[a-z-]+\s*:", clean):
        raise SiteRefusal("Use only finite literal animation shorthands, without longhand overrides")
    spans, used_names = [], set()
    ordinary_motion = []
    for preference in re.finditer(r"@media\s*\(\s*prefers-reduced-motion\s*:\s*no-preference\s*\)\s*\{", clean):
        preference_end, preference_depth = preference.end(), 1
        while preference_end < len(clean) and preference_depth:
            preference_depth += (clean[preference_end] == "{") - (clean[preference_end] == "}")
            preference_end += 1
        if preference_depth:
            raise SiteRefusal("Unclosed ordinary-motion block")
        ordinary_motion.append((preference.end(), preference_end))

    approved_names = {"nc-edge-light", "nc-route-sweep", "nc-region-entry", "nc-command-entry"}
    for match in re.finditer(r"(?<![\w-])(?:-\w+-)?animation\s*:\s*([^;{}]+)", clean):
        value = match.group(1)
        if re.fullmatch(r"\s*none\s*(?:!important)?\s*", value):
            continue
        literal = re.fullmatch(r"\s*([A-Za-z][A-Za-z0-9_-]*)\s+(\d*\.?\d+)(ms|s)\s+(?:linear|ease|ease-in|ease-out|ease-in-out)\s+(?:(\d*\.?\d+)(ms|s)\s+)?1(?:\s+(?:none|forwards|backwards|both))?\s*", value)
        if literal is None or literal.group(1) not in approved_names:
            raise SiteRefusal("Decorative animation must be a finite literal single iteration")
        duration = float(literal.group(2)) / (1000 if literal.group(3) == "ms" else 1)
        delay = float(literal.group(4) or 0) / (1000 if literal.group(5) == "ms" else 1)
        if duration <= 0 or duration + delay > 4:
            raise SiteRefusal("Decorative animation duration plus delay must not exceed four seconds")
        if not any(start <= match.start() < end for start, end in ordinary_motion):
            raise SiteRefusal("Finite decorative motion must stay inside its preference gate")
        used_names.add(literal.group(1))
        spans.append(duration + delay)
    frames = re.findall(r"@(?:-\w+-)?keyframes\s+([A-Za-z][A-Za-z0-9_-]*)", clean)
    if len(frames) != len(set(frames)) or set(frames) - approved_names or used_names - set(frames):
        raise SiteRefusal("Only unique reviewed finite decorative keyframes may be used")
    return {"finite_animation_declarations": len(spans), "recurring_animation_declarations": 0, "maximum_declared_span_seconds": max(spans, default=0), "reduced_motion_complete": True}


def validate_public_output(outputs: dict[str, bytes]) -> None:
    expected = {"index.html", ".nojekyll", *PAGES.values(), *COPIES.values()}
    if set(outputs) not in (expected, expected | {"site-manifest.json"}):
        raise SiteRefusal("Public output membership must match the exact reviewed site")
    for name, expected_hash in (("enhancements.js", ENHANCEMENTS_SHA256), ("assets/night-circuit-hero.png", HERO_SHA256), ("assets/patchcairn-logo.png", LOGO_SHA256)):
        if digest(outputs[name]) != expected_hash:
            raise SiteRefusal("A reviewed local resource changed: " + name)
    parsed = {}
    for name, data in outputs.items():
        if name.endswith(".html"):
            parser = PublicHTML()
            parser.feed(data.decode("utf-8"))
            parser.close()
            if parser.script_open or parser.svg_stack or len(parser.scripts) != 1 or len(parser.csp) != 1:
                raise SiteRefusal("Each page requires one complete fixed script and restrictive policy: " + name)
            if not parser.lang or not parser.viewport or parser.main != 1 or parser.headings.count(1) != 1 or "main" not in parser.ids:
                raise SiteRefusal("Each page needs language, viewport, one main, one h1, and a skip target: " + name)
            if any(b > a + 1 for a, b in zip(parser.headings, parser.headings[1:])):
                raise SiteRefusal("Heading levels must not skip: " + name)
            parsed[name] = parser
    css = outputs["styles.css"].decode("utf-8")
    resource_css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    if re.search(r"\\|(?:url|image-set|image|src|paint|expression)\s*\(|@import|@font-face|-moz-binding|(?<![\w-])behavior\s*:", resource_css, flags=re.I):
        raise SiteRefusal("Styles cannot fetch resources or execute expressions")
    validate_motion_css(css)
    for name, parser in parsed.items():
        for url in parser.links:
            if safe_url(url)[0] == "external":
                continue
            link = urlsplit(url)
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), unquote(link.path))) if link.path else name
            if target not in outputs:
                raise SiteRefusal("Local link is outside the exact site output: " + name + " -> " + target)
            if link.fragment and (target not in parsed or unquote(link.fragment) not in parsed[target].ids):
                raise SiteRefusal("Missing local anchor: " + name + " -> " + target + "#" + link.fragment)
        expected_script = posixpath.relpath("enhancements.js", posixpath.dirname(name) or ".")
        if parser.scripts != [expected_script]:
            raise SiteRefusal("The enhancement script must resolve to its exact local output")


def output_path(root: Path, value: str | Path) -> Path:
    raw = str(value)
    if any(part == ".." for part in raw.replace("\\", "/").split("/")):
        raise SiteRefusal("Output traversal is not allowed")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        relative = candidate.relative_to(root).as_posix()
        tail = PurePosixPath(relative).relative_to(OUTPUT_BOUNDARY)
    except ValueError as error:
        raise SiteRefusal("Site output must be beneath work/site/") from error
    if not tail.parts:
        raise SiteRefusal("Choose a distinct child output directory beneath the site work boundary")
    checked_path(root, relative, exists=False)
    return candidate


def create_directories(root: Path, target: Path) -> None:
    relative = target.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        try:
            current.mkdir()
        except FileExistsError:
            pass
        no_links(current, directory=True)


def existing_output(output: Path, expected_names: set[str]) -> dict[str, str]:
    if not output.exists():
        return {}
    no_links(output, directory=True)
    entries = list(output.iterdir())
    if not entries:
        return {}
    manifest_data = read_regular(output, "site-manifest.json")
    manifest = json.loads(manifest_data)
    if not isinstance(manifest, dict) or set(manifest) != {"generator", "inputs", "outputs"} or manifest["generator"] != SITE_GENERATOR or not isinstance(manifest["outputs"], dict):
        raise SiteRefusal("Existing output is not a recognized managed site")
    known = manifest["outputs"]
    if set(known) != expected_names - {"site-manifest.json"}:
        raise SiteRefusal("Existing output membership differs from the exact public site")
    files, directories = set(), set()
    for parent, children, names in os.walk(output, followlinks=False):
        for child in children:
            path = Path(parent) / child
            no_links(path, directory=True)
            directories.add(path.relative_to(output).as_posix())
        for name in names:
            path = Path(parent) / name
            no_links(path, directory=False)
            files.add(path.relative_to(output).as_posix())
    allowed_dirs = {str(parent) for name in expected_names for parent in PurePosixPath(name).parents if str(parent) != "."}
    if files != expected_names or directories != allowed_dirs:
        raise SiteRefusal("Unexpected files or directories in existing site output")
    for name, expected_hash in known.items():
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or digest(read_regular(output, name)) != expected_hash:
            raise SiteRefusal("A managed site file changed; preserve it and choose a new output directory")
    return {**known, "site-manifest.json": digest(manifest_data)}


def build_site(output: str | Path, *, root: Path = ROOT, repository: str | None = None) -> dict:
    if ".." in Path(root).parts:
        raise SiteRefusal("Alternate source root traversal is not allowed")
    root = Path(root).absolute()
    # Fixture overrides are restricted to this builder's designated private work.
    if root != ROOT:
        try:
            fixture_tail = root.relative_to(ROOT / Path(str(FIXTURE_BOUNDARY)))
        except ValueError as error:
            raise SiteRefusal("Alternate source roots are restricted to distinct owned fixtures beneath work/site/tests/") from error
        if not fixture_tail.parts:
            raise SiteRefusal("Choose a distinct owned fixture beneath work/site/tests/")
        no_links(checked_path(ROOT, root.relative_to(ROOT).as_posix()), directory=True)
    repository = repository_url(repository)
    destination = output_path(root, output)
    inputs = {name: read_regular(root, name) for name in PUBLIC_SOURCES}
    if digest(inputs["assets/patchcairn-logo.png"]) != LOGO_SHA256:
        raise SiteRefusal("The approved logo changed; preserve the selected asset exactly")
    for name, expected_hash in (("site/enhancements.js", ENHANCEMENTS_SHA256), ("assets/night-circuit-hero.png", HERO_SHA256)):
        if digest(inputs[name]) != expected_hash:
            raise SiteRefusal("A reviewed local resource changed: " + name)
    outputs = {target: inputs[source] for source, target in COPIES.items()}
    index = inputs["site/index.html"].decode("utf-8")
    if index.count("<!-- repository-link -->") != 1:
        raise SiteRefusal("Expected one optional repository link slot")
    optional_link = repository_markup(repository)
    outputs["index.html"] = index.replace("<!-- repository-link -->", optional_link).encode("utf-8")
    for source, target in PAGES.items():
        title, body = render_markdown(inputs[source].decode("utf-8"), source, repository)
        outputs[target] = guide_html(title, body, target, repository).encode("utf-8")
    outputs[".nojekyll"] = b""
    validate_public_output(outputs)
    manifest = {"generator": SITE_GENERATOR, "inputs": {name: digest(data) for name, data in sorted(inputs.items())}, "outputs": {name: digest(data) for name, data in sorted(outputs.items())}}
    outputs["site-manifest.json"] = (json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8")
    previous = existing_output(destination, set(outputs))
    create_directories(root, destination)
    # Each temporary and final file is a known site child. No recursive deletion.
    for name, data in sorted(outputs.items()):
        target = checked_path(destination, name, exists=False)
        create_directories(root, target.parent)
        if target.exists():
            if name not in previous or digest(read_regular(destination, name)) != previous[name]:
                raise SiteRefusal("Output changed before replacement")
        temporary = target.parent / (".site-write-" + uuid.uuid4().hex + ".tmp")
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        no_links(target.parent, directory=True)
        os.replace(temporary, target)
    # Verify exact final membership and hashes using the same managed boundary.
    existing_output(destination, set(outputs))
    return {"files": len(outputs), "pages": len(PAGES) + 1, "logo_sha256": LOGO_SHA256, "manifest_sha256": digest(outputs["site-manifest.json"]), "output": destination.relative_to(root).as_posix()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="work/site/preview", help="Distinct output child beneath work/site/")
    parser.add_argument("--repository-url", help="Optional explicit HTTPS GitHub repository URL; derive from the chosen repository at publication")
    args = parser.parse_args()
    try:
        result = build_site(args.output, repository=args.repository_url)
    except (SiteRefusal, OSError, UnicodeError, json.JSONDecodeError) as error:
        print("Site build stopped: " + str(error), file=sys.stderr)
        return 2
    print("Built {pages} documentation pages and {files} exact output files at {output}.".format(**result))
    print("Approved logo SHA-256: " + result["logo_sha256"])
    print("Site manifest SHA-256: " + result["manifest_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
