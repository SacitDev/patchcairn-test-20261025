#!/usr/bin/env python3
"""Fictional offline checks for the public documentation builder's boundaries."""
from __future__ import annotations

import importlib.util
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
spec = importlib.util.spec_from_file_location("patchcairn_site_builder", ROOT / "scripts/build_site.py")
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)
TEST_BOUNDARY = ROOT / Path(str(site.FIXTURE_BOUNDARY))


def contrast(first: str, second: str) -> float:
    def luminance(color: str) -> float:
        channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
        return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))
    bright, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (bright + 0.05) / (dark + 0.05)


class NavigationInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.navs, self.details = {}, []
        self.current, self.anchor = None, None
        self.nested_anchors = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "nav":
            self.current = attributes.get("aria-label")
            self.navs[self.current] = []
        if tag == "details":
            self.details.append(attributes)
        if tag == "a" and self.current:
            if self.anchor is not None:
                self.nested_anchors = True
            self.anchor = {**attributes, "label": ""}

    def handle_data(self, data):
        if self.anchor is not None:
            self.anchor["label"] += data

    def handle_endtag(self, tag):
        if tag == "a" and self.anchor is not None:
            self.navs[self.current].append(self.anchor)
            self.anchor = None
        if tag == "nav":
            self.current = None


class SiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_inputs = {name: site.read_regular(ROOT, name) for name in site.PUBLIC_SOURCES}
        site.create_directories(ROOT, TEST_BOUNDARY)

    def setUp(self) -> None:
        self.fixture = TEST_BOUNDARY / ("fictional-" + uuid.uuid4().hex)
        self.fixture.mkdir()
        for name, data in self.public_inputs.items():
            target = self.fixture / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.output = self.fixture / "work/site/output"

    def tearDown(self) -> None:
        # A fixed owned fixture only; resolve before recursive removal on Windows.
        resolved = self.fixture.resolve()
        if resolved.parent != TEST_BOUNDARY.resolve() or self.fixture.is_symlink():
            raise AssertionError("Refuse cleanup outside the exact owned fixture")
        shutil.rmtree(resolved)

    def build(self, **kwargs) -> dict:
        return site.build_site("work/site/output", root=self.fixture, **kwargs)

    def test_build_is_exact_offline_and_preserves_logo(self) -> None:
        result = self.build()
        expected = {"index.html", ".nojekyll", "site-manifest.json", *site.PAGES.values(), *site.COPIES.values()}
        actual = {path.relative_to(self.output).as_posix() for path in self.output.rglob("*") if path.is_file()}
        self.assertEqual(actual, expected)
        self.assertEqual(result["pages"], 37)
        logo = (self.output / "assets/patchcairn-logo.png").read_bytes()
        self.assertEqual(logo, (ROOT / "assets/patchcairn-logo.png").read_bytes())
        self.assertEqual(site.digest(logo), site.LOGO_SHA256)
        outputs = {name: (self.output / name).read_bytes() for name in expected}
        site.validate_public_output(outputs)
        manifest = json.loads(outputs["site-manifest.json"])
        self.assertEqual(set(manifest["inputs"]), set(site.PUBLIC_SOURCES))
        self.assertFalse(any(name.startswith(("work/", ".git/")) for name in manifest["inputs"]))
        self.assertEqual({name for name in actual if name.endswith(".js")}, {"enhancements.js"})
        self.assertEqual(site.digest(outputs["enhancements.js"]), site.ENHANCEMENTS_SHA256)
        self.assertEqual(site.digest(outputs["assets/night-circuit-hero.png"]), site.HERO_SHA256)

    def test_managed_rebuild_is_deterministic(self) -> None:
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)

    def test_arbitrary_source_file_is_never_copied(self) -> None:
        private = self.fixture / "work/fictional-private-record.json"
        private.parent.mkdir()
        private.write_text('{"fictional_private_record":true}', encoding="utf-8")
        (self.fixture / "site/extra.html").write_text("fictional unreviewed page", encoding="utf-8")
        self.build()
        text = "\n".join(path.read_text(encoding="utf-8") for path in self.output.rglob("*.html"))
        self.assertNotIn("fictional_private_record", text)
        self.assertNotIn("unreviewed page", text)

    def test_changed_approved_logo_refuses_before_output(self) -> None:
        (self.fixture / "assets/patchcairn-logo.png").write_bytes(b"fictional unapproved logo")
        with self.assertRaisesRegex(site.SiteRefusal, "approved logo"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_reviewed_script_and_hero_integrity_refuse_before_output(self) -> None:
        for name in ("site/enhancements.js", "assets/night-circuit-hero.png"):
            with self.subTest(name=name):
                path = self.fixture / name
                original = path.read_bytes()
                path.write_bytes(original + b"\nfictional unreviewed payload")
                with self.assertRaisesRegex(site.SiteRefusal, "reviewed local resource changed"):
                    self.build()
                self.assertFalse(self.output.exists())
                path.write_bytes(original)

    def test_source_only_cli_build_needs_no_git_server_or_live_host(self) -> None:
        helper = self.fixture / "scripts/build_site.py"
        helper.parent.mkdir()
        helper.write_bytes(site.read_regular(ROOT, "scripts/build_site.py"))
        help_result = subprocess.run([sys.executable, "-B", str(helper), "--help"], cwd=self.fixture, text=True, capture_output=True, timeout=15, check=False)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("work/site/", help_result.stdout)
        self.assertNotIn("upgrade_v3", help_result.stdout)
        self.assertNotIn("--root", help_result.stdout)
        self.assertFalse((self.fixture / ".git").exists())
        self.assertFalse((self.fixture / "work").exists())
        result = subprocess.run([sys.executable, "-B", str(helper), "--output", "work/site/output"], cwd=self.fixture, text=True, capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Built 37 documentation pages", result.stdout)
        manifest = json.loads((self.output / "site-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest["inputs"]), set(site.PUBLIC_SOURCES))
        self.assertFalse((self.fixture / ".git").exists())

    def test_output_escape_and_boundary_root_refused(self) -> None:
        self.assertEqual(site.OUTPUT_BOUNDARY.as_posix(), "work/site")
        self.assertEqual(site.FIXTURE_BOUNDARY.as_posix(), "work/site/tests")
        for target in ("../escape", "site/output", "work", "work/site", "work/site/../escape", "work/upgrade_v3/site", "work/upgrade_v3/site/output", str(self.fixture.parent / "outside")):
            with self.subTest(target=target), self.assertRaises(site.SiteRefusal):
                site.build_site(target, root=self.fixture)
        self.assertFalse((self.fixture / "site/output").exists())
        for source_root in (ROOT / "docs", ROOT / "work", ROOT / "work/site", ROOT / "work/site/tests", ROOT / "work/site/night_review/fictional-other", ROOT / "work/upgrade_v3/site/fictional-other", self.fixture / ".." / "fictional-other"):
            with self.subTest(source_root=source_root), self.assertRaises(site.SiteRefusal):
                site.build_site("work/site/output", root=source_root)

    def test_unknown_previous_files_and_directories_are_preserved(self) -> None:
        self.build()
        unknown = self.output / "fictional-private.txt"
        unknown.write_text("preserve me", encoding="utf-8")
        with self.assertRaisesRegex(site.SiteRefusal, "Unexpected files"):
            self.build()
        self.assertEqual(unknown.read_text(), "preserve me")
        unknown.unlink()
        (self.output / "unknown-empty-directory").mkdir()
        with self.assertRaisesRegex(site.SiteRefusal, "Unexpected files"):
            self.build()

    def test_changed_managed_output_is_not_overwritten(self) -> None:
        self.build()
        changed = self.output / "index.html"
        changed.write_text("fictional owner edit", encoding="utf-8")
        with self.assertRaisesRegex(site.SiteRefusal, "managed site file changed"):
            self.build()
        self.assertEqual(changed.read_text(), "fictional owner edit")

    def test_nonempty_unmanaged_output_is_not_replaced(self) -> None:
        self.output.mkdir(parents=True)
        unknown = self.output / "keep.txt"
        unknown.write_text("fictional unrelated output", encoding="utf-8")
        with self.assertRaises(site.SiteRefusal):
            self.build()
        self.assertEqual(unknown.read_text(), "fictional unrelated output")

    def test_hardlinked_input_and_output_refused(self) -> None:
        source = self.fixture / "site/styles.css"
        alias = self.fixture / "fictional-link.css"
        os.link(source, alias)
        with self.assertRaisesRegex(site.SiteRefusal, "single-link"):
            self.build()
        alias.unlink()
        self.build()
        os.link(self.output / "styles.css", self.fixture / "fictional-output-link.css")
        with self.assertRaisesRegex(site.SiteRefusal, "single-link"):
            self.build()

    def test_linked_output_parent_refused_when_supported(self) -> None:
        outside = self.fixture / "fictional-outside"
        outside.mkdir()
        parent = self.fixture / "work/site"
        parent.parent.mkdir(parents=True)
        junction = False
        try:
            parent.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            if os.name != "nt":
                self.skipTest("This host does not permit creating symbolic-link fixtures")
            try:
                import _winapi
                _winapi.CreateJunction(str(outside), str(parent))
                junction = True
            except (OSError, AttributeError):
                self.skipTest("This host permits neither symbolic-link nor junction fixtures")
        try:
            with self.assertRaisesRegex(site.SiteRefusal, "Links and reparse"):
                self.build()
            self.assertEqual(list(outside.iterdir()), [])
        finally:
            if junction:
                parent.rmdir()
            else:
                parent.unlink()

    def test_linked_alternate_source_ancestor_refused_when_supported(self) -> None:
        target = self.fixture / "fictional-source"
        nested = target / "nested"
        nested.mkdir(parents=True)
        alias = self.fixture / "fictional-source-alias"
        junction = False
        try:
            alias.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            if os.name != "nt":
                self.skipTest("This host does not permit creating symbolic-link fixtures")
            try:
                import _winapi
                _winapi.CreateJunction(str(target), str(alias))
                junction = True
            except (OSError, AttributeError):
                self.skipTest("This host permits neither symbolic-link nor junction fixtures")
        try:
            with self.assertRaisesRegex(site.SiteRefusal, "Links and reparse"):
                site.build_site("work/site/output", root=alias / "nested")
            self.assertEqual(list(nested.iterdir()), [])
        finally:
            if junction:
                alias.rmdir()
            else:
                alias.unlink()

    def test_local_file_script_network_resource_and_dead_links_refused(self) -> None:
        original = (self.fixture / "site/index.html").read_text(encoding="utf-8")
        cases = [
            '<a href="file:///fictional/private">bad</a>',
            '<a href="C:/fictional/private">bad</a>',
            '<a href="//fictional.invalid/path">bad</a>',
            '<a href="https://localhost/private">bad</a>',
            '<a href="https://127.0.0.1/private">bad</a>',
            '<a href="https://192.168.1.1/private">bad</a>',
            '<a href="https://fictional.local/private">bad</a>',
            '<a href="../../private.html">bad</a>',
            '<a href="missing.html">bad</a>',
            '<a href="#missing-anchor">bad</a>',
            '<script src="anything.js"></script>',
            '<script src="enhancements.js" defer></script>',
            '<script src="enhancements.js" type="module" defer></script>',
            '<script src="enhancements.js" async></script>',
            '<script src="enhancements.js" src="enhancements.js" defer></script>',
            '<script src="enhancements.js" defer>alert("fictional")</script>',
            '<script src="enhancements.js" defer><!-- fictional() --></script>',
            '<script src="https://fictional.invalid/script.js" defer></script>',
            '<script src="enhancements.js?payload=fictional" defer></script>',
            '<script src="./enhancements.js" defer></script>',
            '<script src="../../enhancements.js" defer></script>',
            '<script src="enhancements.js" defer/>',
            '<script>alert("fictional")</script>',
            '<img src="https://fictional.invalid/tracker.png" alt="bad">',
            '<button>Start maintenance</button>',
            '<button id="motion-toggle" type="submit" aria-pressed="false">Pause</button>',
            '<button id="motion-toggle" type="button" aria-pressed="false" onclick="fictional()">Pause</button>',
            '<button id="install" type="button" aria-pressed="false">Install</button>',
            '<form action="https://fictional.invalid"><input></form>',
            '<meta http-equiv="refresh" content="0;url=https://fictional.invalid">',
            '<link rel="modulepreload" href="enhancements.js">',
            '<body background="https://fictional.invalid/pixel">',
            '<span onclick="alert(1)">bad</span>',
            '<svg><foreignObject><p>fictional</p></foreignObject></svg>',
            '<svg><use href="assets/patchcairn-logo.png"></use></svg>',
            '<svg><image href="https://fictional.invalid/pixel"></image></svg>',
            '<svg><path d="M0 0 L1 1" fill="url(https://fictional.invalid/paint)"></path></svg>',
            '<svg><path d="M0 0 L1 1" style="fill:red"></path></svg>',
            '<svg><animate attributeName="href" values="https://fictional.invalid"></animate></svg>',
            '<svg><set attributeName="onclick" to="fictional()"></set></svg>',
            '<svg onload="fictional()"></svg>',
            '<svg xmlns:xlink="http://www.w3.org/1999/xlink"><path d="M0 0" xlink:href="#fictional"></path></svg>',
            '<svg><script src="enhancements.js" defer></script></svg>',
            '<math><annotation-xml encoding="text/html"><script>fictional()</script></annotation-xml></math>',
        ]
        for content in cases:
            with self.subTest(content=content):
                (self.fixture / "site/index.html").write_text(original.replace("</main>", content + "</main>"), encoding="utf-8")
                with self.assertRaises(site.SiteRefusal):
                    self.build()
                self.assertFalse(self.output.exists())

    def test_fixed_enhancement_and_drawing_contract_is_narrow(self) -> None:
        markup = '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M2 4 L22 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path><circle cx="12" cy="12" r="2" fill="#ff9933"></circle></svg>'
        parser = site.PublicHTML(); parser.feed(markup)
        self.assertEqual(parser.svg_stack, [])
        parser = site.PublicHTML(); parser.feed('<script src="enhancements.js" defer></script>')
        self.assertEqual(parser.scripts, ["enhancements.js"])
        self.assertFalse(parser.script_open)
        parser = site.PublicHTML(); parser.feed(site.REPOSITORY_FALLBACK)
        self.assertEqual(parser.repository_fallbacks, 1)
        for markup in ('<svg><svg></svg></svg>', '<svg><path d="M0 0" href="#fictional"></path></svg>', '<svg><path d="M0 0" id="fictional"></path></svg>', '<svg><path d="M0 0"></svg>', '<script src="../enhancements.js" defer="false"></script>', '<button id="motion-toggle" type="button" class="motion-toggle" aria-pressed="false" aria-label="Pause visual motion" hidden>Pause visual motion</button>', '<button type="button">Replay visual motion</button>', '<span aria-disabled="true">GitHub</span>', site.REPOSITORY_FALLBACK.replace('aria-disabled="true"', 'aria-disabled="false"')):
            with self.subTest(markup=markup), self.assertRaises(site.SiteRefusal):
                parser = site.PublicHTML(); parser.feed(markup)

    def test_policy_script_count_resource_membership_and_routes_are_exact(self) -> None:
        self.build()
        outputs = {path.relative_to(self.output).as_posix(): path.read_bytes() for path in self.output.rglob("*") if path.is_file()}
        for name in ("index.html", *site.PAGES.values()):
            parser = site.PublicHTML(); parser.feed(outputs[name].decode("utf-8"))
            self.assertEqual(parser.csp, [site.SITE_CSP])
            self.assertEqual(parser.scripts, ["../enhancements.js" if name.startswith("guides/") else "enhancements.js"])
            self.assertNotIn("button", parser.tags)
            self.assertEqual(parser.repository_fallbacks, 1)
        for injection in (b"default-src 'none'", b"script-src 'self' 'unsafe-inline'", b"script-src https:"):
            changed = dict(outputs)
            changed["index.html"] = outputs["index.html"].replace(site.SITE_CSP.encode(), injection)
            with self.subTest(injection=injection), self.assertRaises(site.SiteRefusal):
                site.validate_public_output(changed)
        for path in ("work/private.json", ".git/config", "extra.js", "assets/extra.png"):
            changed = {**outputs, path: b"fictional"}
            with self.subTest(path=path), self.assertRaisesRegex(site.SiteRefusal, "membership"):
                site.validate_public_output(changed)
        changed = dict(outputs)
        changed["enhancements.js"] += b"\nfictional unreviewed payload"
        with self.assertRaisesRegex(site.SiteRefusal, "reviewed local resource changed"):
            site.validate_public_output(changed)

    def test_reviewed_script_has_no_network_storage_or_imported_markup_capability(self) -> None:
        script = self.public_inputs["site/enhancements.js"].decode("utf-8")
        self.assertEqual(site.digest(script.encode("utf-8")), site.ENHANCEMENTS_SHA256)
        self.assertNotRegex(script, r"\b(?:fetch|eval|Function|import|require|XMLHttpRequest|WebSocket|Worker|SharedWorker|open|sendBeacon|postMessage|setTimeout|setInterval|requestAnimationFrame)\s*\(")
        self.assertNotRegex(script, r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|localStorage|sessionStorage|indexedDB|cookie|serviceWorker|location|history)\b|document\s*\.\s*write")
        self.assertNotRegex(script, r"https?://|file:|PatchCairn:")

    def test_local_script_syntax_and_motion_states_without_a_browser(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node is unavailable; static integrity and source checks still run")
        source = self.fixture / "site/enhancements.js"
        self.assertEqual(site.digest(source.read_bytes()), site.ENHANCEMENTS_SHA256)
        syntax = subprocess.run([node, "--check", str(source)], cwd=self.fixture, text=True, capture_output=True, timeout=15, check=False)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        # A minimal fake document supplies only presentation APIs. This does not
        # load a browser, navigate a URL, render CSS or expose a host/network API.
        harness = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const source = require('node:fs').readFileSync(0, 'utf8');
function boot(options = {}) {
  function element() {
    const classes = new Set();
    const node={events:{}, children:new Set(), entryStarts:0,
      classList:{add(name){classes.add(name); if(name==='is-entering') node.entryStarts++},
        remove(name){classes.delete(name)}, contains(name){return classes.has(name)},
        toggle(name, force){const active = force === undefined ? !classes.has(name) : Boolean(force); if(active) classes.add(name); else classes.delete(name); return active}},
      contains(target){return target===this || this.children.has(target)},
      addEventListener(name,handler){this.events[name]=handler}};
    return node;
  }
  const root=element(), scene=options.scene === false ? null : element();
  const region=element(), laptop=element(), route=element(), sceneLink=element();
  laptop.classList.add('hero-laptop');
  if(scene) {scene.children.add(laptop); scene.children.add(route); scene.children.add(sceneLink)}
  const docEvents={}, windowEvents={}, observers=[];
  const preference={matches:Boolean(options.reduce), listener:null};
  if(options.legacy) preference.addListener=(handler)=>{preference.listener=handler};
  else preference.addEventListener=(name,handler)=>{assert.equal(name,'change'); preference.listener=handler};
  const document={documentElement:root, hidden:false,
    getElementById(id){assert.equal(id,'night-circuit'); return scene},
    querySelectorAll(selector){assert.equal(selector,'.motion-region'); return [region]},
    addEventListener(name,handler){docEvents[name]=handler}};
  const window={matchMedia(query){assert.equal(query,'(prefers-reduced-motion: reduce)'); return preference},
    addEventListener(name,handler){windowEvents[name]=handler}};
  if(options.observer !== false) window.IntersectionObserver=class {
    constructor(callback,settings){this.callback=callback; this.observed=[]; assert.deepEqual(Array.from(settings.threshold),[0,.12,.5]); observers.push(this)}
    observe(target){this.observed.push(target)}
  };
  vm.runInNewContext(source, {document,window}, {timeout:1000});
  return {root,scene,region,laptop,route,sceneLink,document,preference,docEvents,windowEvents,observers,
    enter(target,ratio){assert.ok(observers[0].observed.includes(target)); observers[0].callback([{target,isIntersecting:ratio>0,intersectionRatio:ratio}])},
    replay(type='pointerenter',relatedTarget=null){scene.events[type]({type,relatedTarget})},
    finish(target=scene,child=laptop,name='nc-edge-light'){target.events.animationend({target:child,animationName:name})},
    suspended(){return root.classList.contains('motion-suspended')}};
}
const state=boot();
assert.equal(state.root.classList.contains('motion-ready'),true);
assert.equal(state.suspended(),false);
state.enter(state.scene,.119); assert.equal(state.scene.classList.contains('is-entering'),false);
state.replay(); assert.equal(state.scene.entryStarts,0);
state.enter(state.scene,.12); assert.equal(state.scene.classList.contains('is-entering'),true);
assert.equal(state.scene.entryStarts,1);
state.enter(state.scene,.5); state.replay(); assert.equal(state.scene.entryStarts,1);
state.finish(state.scene,state.route,'nc-route-sweep'); assert.equal(state.scene.classList.contains('is-entering'),true);
state.finish(); assert.equal(state.scene.classList.contains('is-entering'),false);
state.enter(state.scene,0); state.enter(state.scene,.5); assert.equal(state.scene.entryStarts,1);
assert.equal(state.scene.classList.contains('is-entering'),false);
state.replay(); assert.equal(state.scene.entryStarts,2);
state.replay('pointerdown'); assert.equal(state.scene.entryStarts,2);
state.finish(); state.replay('focusin',state.sceneLink); assert.equal(state.scene.entryStarts,2);
state.replay('focusin'); assert.equal(state.scene.entryStarts,3);
state.enter(state.scene,0); assert.equal(state.scene.classList.contains('is-entering'),false);
state.replay(); assert.equal(state.scene.entryStarts,3);
state.enter(state.scene,.5); assert.equal(state.scene.entryStarts,3);
state.replay('pointerdown'); assert.equal(state.scene.entryStarts,4);
state.enter(state.region,.5); assert.equal(state.region.entryStarts,1);
state.document.hidden=true; state.docEvents.visibilitychange(); assert.equal(state.suspended(),true);
assert.equal(state.scene.classList.contains('is-entering'),false); assert.equal(state.region.classList.contains('is-entering'),false);
state.document.hidden=false; state.docEvents.visibilitychange(); assert.equal(state.suspended(),false);
assert.equal(state.scene.entryStarts,4); assert.equal(state.region.entryStarts,1);
state.enter(state.region,0); state.enter(state.region,.5); assert.equal(state.region.entryStarts,1);
state.replay(); assert.equal(state.scene.entryStarts,5);
state.windowEvents.pagehide(); assert.equal(state.suspended(),true);
assert.equal(state.scene.classList.contains('is-entering'),false);
state.windowEvents.pageshow(); assert.equal(state.suspended(),false); assert.equal(state.scene.entryStarts,5);
state.replay(); assert.equal(state.scene.entryStarts,6);
state.preference.matches=true; state.preference.listener(); assert.equal(state.suspended(),true);
assert.equal(state.scene.classList.contains('is-entering'),false);
state.replay(); assert.equal(state.scene.entryStarts,6);
state.preference.matches=false; state.preference.listener(); assert.equal(state.suspended(),false); assert.equal(state.scene.entryStarts,6);
const completed=boot(); completed.enter(completed.region,.5);
completed.finish(completed.region,completed.region,'nc-command-entry'); assert.equal(completed.region.classList.contains('is-entering'),true);
completed.finish(completed.region,completed.region,'nc-region-entry'); assert.equal(completed.region.classList.contains('is-entering'),false);
completed.enter(completed.region,0); completed.enter(completed.region,.5); assert.equal(completed.region.entryStarts,1);
const noObserver=boot({observer:false});
assert.equal(noObserver.root.classList.contains('motion-ready'),false);
assert.deepEqual(Object.keys(noObserver.scene.events),[]); assert.equal(noObserver.scene.entryStarts,0);
const guide=boot({scene:false}); assert.equal(guide.suspended(),false);
assert.equal(guide.root.classList.contains('motion-ready'),true);
guide.enter(guide.region,.5); assert.equal(guide.region.entryStarts,1);
guide.finish(guide.region,guide.region,'nc-region-entry'); assert.equal(guide.region.classList.contains('is-entering'),false);
const reduced=boot({reduce:true,legacy:true}); reduced.enter(reduced.scene,.5);
assert.equal(reduced.suspended(),true); assert.equal(reduced.scene.entryStarts,0);
reduced.preference.matches=false; reduced.preference.listener(); assert.equal(reduced.scene.entryStarts,0);
reduced.replay(); assert.equal(reduced.scene.entryStarts,1);
const printing=boot(); printing.enter(printing.scene,.5); printing.enter(printing.region,.5);
printing.windowEvents.beforeprint();
assert.equal(printing.scene.classList.contains('is-entering'),false);
assert.equal(printing.region.classList.contains('is-entering'),false);
printing.enter(printing.scene,.5); printing.enter(printing.region,.5);
assert.equal(printing.scene.entryStarts,1); assert.equal(printing.region.entryStarts,1);
printing.replay(); assert.equal(printing.scene.entryStarts,2);
console.log('Finite presentation-only motion state checks passed without a browser.');
'''
        result = subprocess.run([node, "--input-type=commonjs", "-e", harness], input=source.read_text(encoding="utf-8"), cwd=self.fixture, text=True, capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("motion state checks passed", result.stdout)

    def test_markdown_html_is_inert_and_private_file_is_not_copied(self) -> None:
        title, body = site.render_markdown('# Fictional\n\n<script>alert("fixture")</script>\n\n[source](../scripts/fixed.py)', "docs/fictional.md")
        self.assertEqual(title, "Fictional")
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)
        self.assertIn("source package:", body)
        self.assertNotIn('href="../scripts', body)
        for target in ("file:///private", "javascript:alert", "../../escape", "https://user:password@fictional.invalid"):
            with self.subTest(target=target), self.assertRaises(site.SiteRefusal):
                site.markdown_link("fixture", target, "docs/fixture.md", None)

    def test_optional_repository_url_has_no_account_default(self) -> None:
        self.assertEqual(site.REPOSITORY_NOTICE, "GitHub repository link not configured")
        self.build()
        index = (self.output / "index.html").read_text(encoding="utf-8")
        self.assertIn(site.REPOSITORY_FALLBACK, index)
        self.assertNotIn('href="https://github.com/', index)
        result = self.build(repository="https://github.com/fictional-owner/fictional-project")
        for target in ("index.html", *site.PAGES.values()):
            markup = (self.output / target).read_text(encoding="utf-8")
            self.assertIn('<a class="repository-link" href="https://github.com/fictional-owner/fictional-project">GitHub ↗</a>', markup)
            self.assertNotIn(site.REPOSITORY_FALLBACK, markup)
        self.assertEqual(result["logo_sha256"], site.LOGO_SHA256)
        for value in ("https://github.com/owner/repo?token=fictional", "https://example.invalid/owner/repo", "file:///repo", "https://github.com/owner/repo/tree/main", "https://github.com/owner/.."):
            with self.subTest(value=value), self.assertRaises(site.SiteRefusal):
                site.repository_url(value)

    def test_css_external_dependencies_refused(self) -> None:
        css = self.fixture / "site/styles.css"
        original = css.read_text(encoding="utf-8")
        for injected in ('@import "https://fictional.invalid/font.css";', 'body{background:url(https://fictional.invalid/pixel)}', 'body{background:image-set("fictional.png" 1x)}', r'body{background:u\72l(fictional.png)}', '@font-face{font-family:fixture;src:local("Fixture")}'):
            css.write_text(original + injected, encoding="utf-8")
            with self.assertRaisesRegex(site.SiteRefusal, "Styles cannot"):
                self.build()
            self.assertFalse(self.output.exists())

    def test_professional_content_and_mobile_contract(self) -> None:
        self.build()
        index = (self.output / "index.html").read_text(encoding="utf-8")
        css = (self.output / "styles.css").read_text(encoding="utf-8")
        for command in ("start", "help", "status", "options", "cost", "settings", "pause", "resume", "stop", "resolve"):
            self.assertIn("PatchCairn: " + command, index)
        for phrase in ("Developed by Michael", "Security updates", "Storage cleanup", "Diagnosis", "Backup", "Claude Code", "OpenCode", "without creating a session or collecting host information", "16 MiB", "48 MiB", "64 MiB", "MSI, PKG, or DEB", "remain held"):
            self.assertIn(phrase, index)
        self.assertIn('href="guides/security-updates-workflow.html"', index)
        self.assertIn('href="guides/service-integration.html"', index)
        self.assertIn('<dl class="command-reference">', index)
        self.assertEqual(index.count('<dt><code>PatchCairn:'), 10)
        self.assertIn('.command-reference>div{grid-template-columns:1fr', css)
        for feature in (":focus-visible", ".skip-link:focus", "prefers-reduced-motion", "@media(max-width:480px)", "@media(max-width:800px)", "overflow-x:auto", "minmax(0,74ch)"):
            self.assertIn(feature, css)
        for rejected in ("route-plate", "stone-one", "field-notes", "plate-caption", "font-family:var(--serif)", "Georgia"):
            self.assertNotIn(rejected, index + css)
        self.assertNotRegex(index, r"(?i)(gmail|C:[\\/](?:Users|ProjectBackups)|file:|localhost|<form)")
        self.assertNotRegex(index, r'<(?:button|input|form)\b')
        self.assertNotIn('scene-controls', index)
        self.assertNotIn('motion-toggle', index)
        self.assertNotIn('is-entering', index)
        self.assertIn("min-height:44px", css)
        self.assertIn("font-size:2.25rem", css)

    def test_grouped_navigation_covers_all_guides_and_opens_current_group(self) -> None:
        expected = {Path(target).name for target in site.PAGES.values()}
        for destination in site.PAGES.values():
            with self.subTest(destination=destination):
                markup, group, label = site.guide_navigation(destination)
                parser = NavigationInspector()
                parser.feed('<nav aria-label="Fixture">' + markup + '</nav>')
                links = parser.navs["Fixture"]
                self.assertEqual({link["href"] for link in links}, expected)
                self.assertEqual(len(links), len(expected))
                current = [link for link in links if link.get("aria-current") == "page"]
                self.assertEqual(len(current), 1)
                self.assertEqual(current[0]["href"], Path(destination).name)
                self.assertEqual(current[0]["label"], label)
                opened = [details for details in parser.details if "open" in details]
                self.assertEqual(len(opened), 1)
                self.assertIn(group, markup)
                self.assertIn("Record helper reference", markup)
                self.assertNotIn("Legacy helper API", markup)

    def test_toc_uses_actual_rendered_ids_and_plain_escaped_text(self) -> None:
        source = '# Sample\n\nOpening explanation.\n\n## A - B\n\n### -- Edge --\n\n## [Official reference](https://example.org/docs) & "quoted"\n\n## </a><img src=x onerror=alert(1)>\n\n## &quot; &lt; & text\n'
        title, body = site.render_markdown(source, "docs/YOUR_FIRST_RUN.md")
        outline = site.outline_items(body)
        self.assertEqual(outline[0]["anchor"], "a---b")
        self.assertIn("Official reference", outline[2]["label"])
        document = site.guide_html(title, body, "guides/your-first-run.html", None)
        parser = NavigationInspector(); parser.feed(document)
        self.assertFalse(parser.nested_anchors)
        toc = parser.navs["On this page"]
        self.assertEqual([link["href"] for link in toc], ["#" + item["anchor"] for item in outline])
        self.assertTrue(all(link["href"].startswith("#") for link in toc))
        self.assertNotIn('<img src=x', document)
        self.assertIn('&lt;/a&gt;&lt;img', document)
        self.assertIn('&amp;quot;', document)
        public = site.PublicHTML(); public.feed(document)

    def test_toc_ignores_code_raw_html_and_holds_duplicate_anchor_collisions(self) -> None:
        source = '# Sample\n\n```text\n## Fake\n<h2 id="fake">fake</h2>\n```\n\n<h2 id="raw">raw</h2>\n\n## Real\n\n```mermaid\nclick A "javascript:alert(1)"\n</code></pre><script>fixture()</script>\n```\n'
        title, body = site.render_markdown(source, "docs/YOUR_FIRST_RUN.md")
        self.assertEqual([item["anchor"] for item in site.outline_items(body)], ["real"])
        document = site.guide_html(title, body, "guides/your-first-run.html", None)
        self.assertNotIn('<script>', document)
        self.assertIn('&lt;script&gt;', document)
        self.assertIn('<details class="diagram-source"><summary>View Mermaid source</summary>', document)
        for source in ('# Sample\n## A\n## A\n## A-1', '# Sample\n## main', '# Sample\n## page-outline'):
            with self.subTest(source=source), self.assertRaises(site.SiteRefusal):
                title, body = site.render_markdown(source, "docs/YOUR_FIRST_RUN.md")
                document = site.guide_html(title, body, "guides/your-first-run.html", None)
                parser = site.PublicHTML(); parser.feed(document)
        title, body = site.render_markdown('# Sample\n## \n## 日本語\n## !!!', "docs/YOUR_FIRST_RUN.md")
        document = site.guide_html(title, body, "guides/your-first-run.html", None)
        parser = site.PublicHTML(); parser.feed(document)

    def test_long_reference_toc_is_compact_and_code_labels_are_safe(self) -> None:
        source = '# Reference\n' + ''.join('\n## Section ' + str(index) + '\n### Detail ' + str(index) + '\n' for index in range(8))
        title, body = site.render_markdown(source, "docs/WORKFLOW_ENGINE.md")
        outline = site.outline_items(body)
        self.assertEqual(len(outline), 8)
        self.assertTrue(all(item["level"] == 2 for item in outline))
        title, body = site.render_markdown('# Example\n## "Quoted" <tag>\n\n```python" onmouseover="fixture\nprint("fixture")\n```\n\n| A | B |\n| --- | --- |\n| x | y |', "docs/YOUR_FIRST_RUN.md")
        self.assertIn('aria-label="Code example: &quot;Quoted&quot; &lt;tag&gt;"', body)
        self.assertIn('aria-label="Reference table: &quot;Quoted&quot; &lt;tag&gt;"', body)
        self.assertNotIn('onmouseover=', body)
        self.assertIn('tabindex="0"', body)

    def test_mobile_guide_order_disclosures_and_desktop_outline_focus(self) -> None:
        title, body = site.render_markdown('# Title\n\nOpening explanation.\n\n## First section\n\nContent.', "docs/YOUR_FIRST_RUN.md")
        document = site.guide_html(title, body, "guides/your-first-run.html", None)
        self.assertLess(document.index('<h1 '), document.index('Opening explanation.'))
        self.assertLess(document.index('Opening explanation.'), document.index('<details class="mobile-toc">'))
        self.assertLess(document.index('<details class="mobile-toc">'), document.index('<h2 '))
        self.assertIn('<details class="mobile-doc-nav"><summary>Browse documentation</summary>', document)
        self.assertIn('<a class="outline-jump" href="#page-outline">', document)
        self.assertIn('<aside class="page-outline" id="page-outline" tabindex="-1">', document)
        self.assertIn('aria-label="Breadcrumb"', document)
        css = (self.fixture / "site/styles.css").read_text(encoding="utf-8")
        self.assertIn('.page-outline .outline-list a:focus-visible{outline-offset:-2px}', css)
        self.assertIn('.nav-group>summary:focus-visible{outline-offset:-2px}', css)
        self.assertIn('.docs-sidebar{display:none}', css)
        self.assertIn('.mobile-doc-nav{display:block', css)
        self.assertNotIn('details:not([open])>nav{display:block', css)

    def test_finite_effect_bounds_reduced_motion_and_surface_contrast(self) -> None:
        css = (self.fixture / "site/styles.css").read_text(encoding="utf-8")
        result = site.validate_motion_css(css)
        self.assertEqual(result["finite_animation_declarations"], 7)
        self.assertEqual(result["recurring_animation_declarations"], 0)
        self.assertLessEqual(result["maximum_declared_span_seconds"], 4)
        self.assertEqual(result["maximum_declared_span_seconds"], 3.2)
        self.assertTrue(result["reduced_motion_complete"])
        self.assertEqual(set(re.findall(r'@keyframes\s+([a-z-]+)', css)), {'nc-route-sweep', 'nc-edge-light', 'nc-region-entry', 'nc-command-entry'})
        self.assertNotIn('@font-face', css)
        self.assertNotRegex(css, r'\.(?:brand(?:\s+img)?|site-logo)[^{}]*\{[^{}]*(?:filter|transform)\s*:')
        self.assertNotIn('transition:all', css.replace(' ', ''))
        self.assertNotIn('infinite', css)
        self.assertNotIn('animation-play-state', css)
        self.assertNotIn('.is-in-view', css)
        for invalid in ('.fictional{animation:nc-region-entry 6s linear 1 both}', '.fictional{animation:nc-region-entry 1s linear infinite}', '.fictional{animation-name:nc-region-entry}', '.fictional{animation-play-state:running!important}', '.fictional{animation-delay:.8s}', '.fictional{animation:nc-region-entry var(--duration) linear 1}'):
            with self.subTest(invalid=invalid), self.assertRaises(site.SiteRefusal):
                site.validate_motion_css(css + invalid)
        effect = 'html.motion-ready .night-circuit.is-entering .hero-laptop{animation:nc-edge-light 3.2s ease-in-out 1}'
        self.assertIn(effect, css)
        mutations = {
            'duration': css.replace('nc-edge-light 3.2s ease-in-out 1', 'nc-edge-light 4.1s ease-in-out 1'),
            'duration plus delay': css.replace('nc-edge-light 3.2s ease-in-out 1', 'nc-edge-light 3.2s ease-in-out .9s 1'),
            'iteration': css.replace('nc-edge-light 3.2s ease-in-out 1', 'nc-edge-light 3.2s ease-in-out 2'),
            'infinite': css.replace('nc-edge-light 3.2s ease-in-out 1', 'nc-edge-light 3.2s ease-in-out infinite'),
            'name': css.replace('animation:nc-edge-light', 'animation:fictional'),
            'preference': css.replace('prefers-reduced-motion:no-preference', 'min-width:1px'),
            'default': re.sub(r'(\.circuit-flow\s*\{[^{}]*?)animation:none', r'\1animation:initial', css),
            'keyframe name': css.replace('@keyframes nc-edge-light', '@keyframes fictional'),
            'outside media': css.replace(effect, '') + effect,
            'negative delay': css.replace('nc-edge-light 3.2s ease-in-out 1', 'nc-edge-light 3.2s ease-in-out -1s 1'),
        }
        for name, mutated in mutations.items():
            with self.subTest(mutation=name), self.assertRaises(site.SiteRefusal):
                site.validate_motion_css(mutated)
        with self.assertRaises(site.SiteRefusal):
            site.validate_motion_css(css.replace('transform:none!important', 'transform:initial!important'))
        tokens = dict(re.findall(r'--([a-z-]+):\s*(#[a-fA-F0-9]{6})', css))
        for foreground, background in (('ink','surface'), ('muted','surface'), ('muted','subtle'), ('muted','raised'), ('orange','surface'), ('orange','orange-soft'), ('accent-ink','accent')):
            with self.subTest(foreground=foreground,background=background):
                self.assertGreaterEqual(contrast(tokens[foreground],tokens[background]),4.5)
        code_background = re.search(r'(?:^|\n)code\{[^}]*background:(#[a-fA-F0-9]{6})', css)
        self.assertIsNotNone(code_background)
        self.assertGreaterEqual(contrast(tokens['code'], code_background.group(1)), 4.5)
        self.assertNotRegex(css, r'\.motion-region[^{}]*\{[^{}]*(?:opacity:0|visibility:hidden|display:none)')


if __name__ == "__main__":
    unittest.main(verbosity=2)
