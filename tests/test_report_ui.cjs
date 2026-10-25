// Execute the real session-report program from templates/report.html against fictional report records only.
// Node standard library; this is a DOM behaviour and injection test, not a browser or pixel test. The payloads are
// hand-written patchcairn.report records in the layout scripts/report.py emits, with its exact texts (the double-quoted
// constants below; tests/test_report.py checks they equal report.py's); they are embedded exactly as report.py does.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const SCRIPT_HASH = '@@SCRIPT_SHA256@@';
const STYLE_HASH = '@@STYLE_SHA256@@';
const DATA = '@@REPORT_DATA@@';
const SECTIONS = ['scope', 'findings', 'plan', 'reviews', 'approvals', 'outcomes', 'free_space', 'packages', 'retained'];
const TITLES = ['Scope', 'Findings', 'Plan', 'Assistant reviews of the plan', 'Approvals', 'Outcomes', 'Free space', 'Package results',
  'Recovery copies kept'];
const HOSTILE = '</script><script>globalThis.injected=true</script><img src=x onerror="globalThis.injected=true"><!--';
const HTML_PATHS = /innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write|\beval\b|Function\s*\(|setTimeout|setInterval|\.on[a-z]+\s*=|\.style\b|setAttribute/;
// Every identifier the program may use (string literals removed), and the members it may read or set.
const PROGRAM_IDENTIFIERS = new Set(['const', 'data', 'JSON', 'parse', 'document', 'getElementById', 'textContent', 'make', 'tag', 'text',
  'className', 'node', 'createElement', 'return', 'render', 'target', 'blocks', 'for', 'kind', 'content', 'of', 'if', 'list', 'label',
  'value', 'append', 'else', 'title', 'banner', 'null', 'header', 'key', 'notShown', 'replaceChildren']);
const PROGRAM_MEMBERS = new Set(['getElementById', 'textContent', 'parse', 'createElement', 'className', 'append', 'replaceChildren',
  'title', 'banner', 'header']);
const KEYWORDS_BEFORE_BRACKET = new Set(['const', 'of', 'return', 'in', 'else']);
// report.py's texts, written exactly as report.py has them.
const BANNER = "FICTIONAL DEMONSTRATION. This is a practice session with made-up data. Its records do not establish that any computer was checked or changed.";
const PAGE_NOTE = "This page lists only what was given to it. 'Not recorded' means no record of that item was available when this report was made.";
const TIME_NOTE = "All times are in UTC (Coordinated Universal Time), not your local clock time.";
const DECISIONS_NOTE = "The AI assistant wrote these entries, quoting the owner's messages in the chat or terminal. This page cannot show who typed those messages. To confirm a decision, find the quoted words in the conversation history.";
const SCOPE_NOTE = "Written by the AI assistant from the owner's message; see the note under Approvals.";
const REVIEWS_NOTE = "Reviews are checks of the plan made by AI assistant passes, not by a person or an outside company. 'Approved' here means that pass found no reason to stop. It is not the owner's approval.";
const OWNER_ATTESTED = "Written by the assistant from the owner's message (coordinator-attested)";
const REVIEW_ATTESTED = "Written by the assistant from an AI review pass (coordinator-attested)";
const UNLABELLED = "Not stated: this record does not say how it was made.";
const NO_FINDINGS = "No problems are listed because none were recorded. That does not mean the computer has none: only what was checked could be found.";
const EVIDENCE_HEADING = "Technical records (evidence)";
const EVIDENCE_NOTE = "Evidence records (technical detail): what the assistant saved while it worked, copied as written. This page does not check them.";
const PLAN_NOTE = "The plan fingerprint changes if anything in the plan changes; the reviews and the approval refer to this exact plan.";
const SAME_PLAN = "Same as the plan above";
const NO_RESULT = "No result recorded: this step started, but no result had been recorded when this report was made. It may still be running or may have stopped part-way. Ask the assistant (PatchCairn: status) before starting anything else on this computer.";
const RESTART_WAITING = "Waiting for a restart: the installer reported that the computer must restart to finish this step (code 3010). The step stays unfinished until the computer has restarted and the result is checked.";
const RESTART_UNDECIDED = "Not decided yet. Tell the assistant whether to restart now or later (PatchCairn: resolve).";
const OUTCOMES_NOTE = "Results are shown as recorded. 'failed' means the step did not complete, 'partial' means only part of it took effect, and 'unknown' means its effect could not be confirmed. After any of these, PatchCairn holds further changes in this session until the result is reconciled: ask the assistant what changed and what was kept (PatchCairn: status, then PatchCairn: resolve).";
const EARLIER_PLAN_NOTE = "Some steps belong to an earlier plan in this session. That plan, its reviews and its approval were replaced by the plan above, so this page does not show them; each step still shows who authorized it.";
const FREE_SPACE_MEASURED = "Free space was measured on each drive before and after the work. The measured change includes anything else that used or freed space at the same time, such as downloads or system updates.";
const FREE_SPACE_ESTIMATE = "The expected change is PatchCairn's estimate: the size of the files removed minus the size of any backup written to the same drive. Quarantine keeps files on the same drive so they can be put back, so it frees no space there.";
const FREE_SPACE_UNITS = "1 GB here is 1,000,000,000 bytes.";
const EXPLORER_NOTE = " Windows File Explorer counts 1,073,741,824 bytes per GB, so it shows a slightly smaller number.";
const RETAINED_NOTE = "PatchCairn keeps these so a change can be undone or files restored. They use disk space until you decide to release them. Ask your assistant before deleting any of them, because afterwards the change cannot be undone.";

class Element {
  constructor(tag, parses, text = '', className = '') {
    this.tagName = tag;
    this.children = [];
    this.parses = parses;
    this._text = text;
    this._class = className;
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return [this._text, ...this.children.map(x => x.textContent ?? String(x))].filter(Boolean).join(' '); }
  set className(value) { this._class = String(value); }
  get className() { return this._class; }
  append(...values) { this.children.push(...values); }
  replaceChildren(...values) { this._text = ''; this.children = [...values]; }
  refuse(name) { this.parses.push(name); throw Error('HTML must never be parsed: ' + name); }
  set innerHTML(_) { this.refuse('innerHTML'); }
  get innerHTML() { return this.refuse('innerHTML'); }
  set outerHTML(_) { this.refuse('outerHTML'); }
  get outerHTML() { return this.refuse('outerHTML'); }
  insertAdjacentHTML() { this.refuse('insertAdjacentHTML'); }
}

const pair = (label, value) => [label, value];
const fields = (...pairs) => ['fields', pairs];
const note = text => ['note', text];
const notRecorded = [note('Not recorded.')];
const STAMP = '2026-01-02T03:04:05Z';

function fictionalRecord() {
  const hash = 'f'.repeat(64);
  const owner = (name, quote, extra, attestation) => fields(pair('Decision', name), pair('Quoted instruction', quote),
    pair('Message id', 'fictional-message'), pair('Given in', 'the chat (current_owner_chat)'), pair('Recorded (UTC)', STAMP), ...extra,
    pair('How this was recorded', attestation));
  const review = (reviewer, role, attestation) => fields(pair('Role', role), pair('Reviewer', reviewer),
    pair('Review result', 'no reason to stop found (approved)'), pair('Plan fingerprint', SAME_PLAN), pair('Recorded (UTC)', STAMP),
    pair('How this was recorded', attestation));
  const operation = (action, fingerprint, result, summary, ...restart) => fields(pair('Action', action), pair('Plan fingerprint', fingerprint),
    pair('Authorized by', 'the plan approval (message fictional-plan)'), pair('Started (UTC)', STAMP),
    pair('Finished (UTC)', result === 'succeeded' ? STAMP : 'not recorded'), pair('Result', result), ...restart, pair('Summary', summary),
    pair('Resolution', 'not recorded'));
  return {schema: 'patchcairn.report', schema_version: 1, generated_utc: '2026-01-02T03:04:05.000006Z',
    title: 'PatchCairn session report: security_updates, created 2026-01-02', banner: BANNER,
    header: [fields(pair('Session', 'session-fictional-1'), pair('Job', 'security_updates'), pair('Stage', 'apply'), pair('Status', 'active'),
      pair('Mode', 'practice with made-up data (fixture)'), pair('Platform', 'Windows (windows)'), pair('Created (UTC)', STAMP),
      pair('Last updated (UTC)', STAMP), pair('Report made (UTC)', '2026-01-02T03:04:05.000006Z')), note(PAGE_NOTE), note(TIME_NOTE)],
    scope: [fields(pair('Purpose', HOSTILE), pair('Selected folder or drive', 'D:\\Fictional\\Photos'), pair('Assessment covers', 'not recorded')),
      owner('Scope decision', 'Look only at this fictional folder.', [pair('Scope fingerprint', hash)], OWNER_ATTESTED), note(SCOPE_NOTE)],
    findings: [['heading', 'What was found'],
      fields(pair('Summary', 'Fictional assessment'), pair('Problem found', 'Fictional finding A'), pair('Limitation', 'Fictional limit')),
      ['heading', EVIDENCE_HEADING], note(EVIDENCE_NOTE),
      fields(pair('Evidence', 'rp-ev-1'), pair('Kind', 'inventory'), pair('Observed (UTC)', STAMP), pair('Recorded value', 'complete: true'),
        pair('Recorded value', HOSTILE + ': ' + HOSTILE))],
    plan: [fields(pair('Plan', 'fictional-plan'), pair('Summary', HOSTILE), pair('Plan fingerprint (SHA-256)', hash), pair('Registered (UTC)', STAMP)),
      note(PLAN_NOTE),
      fields(pair('Action', 'fictional-action'), pair('Kind', 'backup_create'), pair('Target', 'D:\\Fictional\\Photos'),
        pair('Benefit', 'A fictional copy'), pair('Risk', 'Fictional data could change'), pair('How it can be undone', 'Keep the fictional source'),
        pair('How the result will be checked', 'Check the copy'))],
    reviews: [note(REVIEWS_NOTE), review('fictional-reviewer-a', 'Compatibility and data safety (compatibility_data)', REVIEW_ATTESTED),
      review('fictional-reviewer-b', 'Evidence and security (evidence_security)', UNLABELLED)],
    approvals: [note(DECISIONS_NOTE),
      owner('Plan approval', HOSTILE, [pair('Approved actions', 'fictional-action'), pair('Plan fingerprint', SAME_PLAN)], UNLABELLED),
      note('Agreement to a permanent deletion (irreversible-loss acknowledgment): not recorded.'),
      owner('Standing permission for routine steps (standing policy)', 'Fictional policy', [pair('Kinds of step allowed', 'backup_create')],
        'Unrecognised label: fictional-other-label')],
    outcomes: [note(OUTCOMES_NOTE), note(EARLIER_PLAN_NOTE), operation('fictional-action', SAME_PLAN, 'succeeded', HOSTILE),
      operation('fictional-second', SAME_PLAN, NO_RESULT, 'Waiting'),
      operation('fictional-update', 'An earlier plan (fingerprint begins eeeeeeee)', RESTART_WAITING, 'Waiting for a restart',
        pair('Restart decision', RESTART_UNDECIDED))],
    free_space: [note(FREE_SPACE_MEASURED), note(FREE_SPACE_ESTIMATE), note(FREE_SPACE_UNITS + EXPLORER_NOTE),
      fields(pair('Drive', 'D:\\'), pair('Free space before', 'about 100.0 GB (100,000,000,000 bytes)'),
        pair('Free space after', 'about 111.8 GB (111,811,160,064 bytes)'),
        pair('Measured change', 'about 11.8 GB more free space (11,811,160,064 bytes)'),
        pair('Expected change (estimate)', 'about 11.0 GB more free space (11,000,000,000 bytes)'))],
    packages: [fields(pair('Manager', 'fictional-manager'), pair('Package', HOSTILE), pair('Result', 'upgraded'), pair('Restart', 'none'))],
    retained: [note(RETAINED_NOTE),
      fields(pair('Kind', 'backup'), pair('Location', 'D:\\Fictional\\backup'), pair('Size', 'about 2.0 KB (2,048 bytes)'))]};
}

function emptyRecord(mode) {
  const record = fictionalRecord();
  record.banner = mode === 'fixture' ? BANNER : null;
  record.header[0][1][4] = pair('Mode', mode === 'fixture' ? 'practice with made-up data (fixture)' : 'a real computer (real)');
  record.scope = [fields(pair('Purpose', 'Assessment; scope still needs the owner\'s decision'), pair('Selected folders or drives', 'None listed'),
    pair('Assessment covers', 'not recorded')), note('Scope decision: not recorded.'), note(SCOPE_NOTE)];
  record.findings = [['heading', 'What was found'], note('Assessment summary: not recorded.'), note(NO_FINDINGS), ['heading', EVIDENCE_HEADING],
    note(EVIDENCE_NOTE), note('Evidence: not recorded.')];
  record.approvals = [note(DECISIONS_NOTE), note('Plan approval: not recorded.'),
    note('Agreement to a permanent deletion (irreversible-loss acknowledgment): not recorded.'),
    note('Standing permission for routine steps (standing policy): not recorded.')];
  for (const key of ['plan', 'reviews', 'outcomes', 'free_space', 'packages', 'retained']) record[key] = notRecorded;
  return record;
}

const sha256 = text => crypto.createHash('sha256').update(text, 'utf8').digest('base64');
const only = (text, pattern, name) => {
  const found = [...text.matchAll(pattern)].map(x => x[1]);
  assert.equal(found.length, 1, 'The template needs exactly one ' + name);
  return found[0];
};
const programOf = text => only(text, /<script>([\s\S]*?)<\/script>/g, 'inline program');
const styleOf = text => only(text, /<style>([\s\S]*?)<\/style>/g, 'style');
const policyOf = text => /<meta http-equiv="Content-Security-Policy" content="([^"]*)">/.exec(text)?.[1];
const withoutStrings = text => text.replace(/'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`/g, "''");

// The embedding report.py performs: LF line endings, ASCII JSON with <, > and & escaped, both hashes, the data last.
function substitute(source, record) {
  const template = source.replace(/\r\n?/g, '\n');
  const data = JSON.stringify(record).replace(/[^\x00-\x7f]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
    .replaceAll('<', '\\u003c').replaceAll('>', '\\u003e').replaceAll('&', '\\u0026');
  const parts = template.replace(SCRIPT_HASH, sha256(programOf(template))).replace(STYLE_HASH, sha256(styleOf(template))).split(DATA);
  assert.equal(parts.length, 2, 'The data placeholder must occur exactly once');
  return parts[0] + data + parts[1];
}

// One fake element per id in the markup, with its tag, class and the text written before its first child tag.
function markupElements(template, parses) {
  const ids = new Map();
  for (const match of template.matchAll(/<(\w+)([^>]*?)\sid="([^"]+)"([^>]*)>([^<]*)/g)) {
    const className = /\sclass="([^"]*)"/.exec(match[2] + match[4])?.[1] ?? '';
    ids.set(match[3], new Element(match[1], parses, match[5], className));
  }
  return ids;
}

function loadReport(template, record) {
  const html = substitute(template, record);
  const parses = [];
  const created = [];
  const ids = markupElements(template, parses);
  const block = /<script type="application\/json" id="report-data">([\s\S]*?)<\/script>/.exec(html);
  assert.ok(block, 'The report data element must exist');
  ids.get('report-data').textContent = block[1];
  const refuse = name => { parses.push(name); throw Error('HTML must never be parsed: ' + name); };
  const document = {
    title: 'PatchCairn session report',
    getElementById(id) { assert.ok(ids.has(id), 'Missing markup id: ' + id); return ids.get(id); },
    createElement(tag) { const node = new Element(tag, parses); created.push(node); return node; },
    write() { refuse('document.write'); },
    writeln() { refuse('document.writeln'); }
  };
  const context = vm.createContext({document}, {codeGeneration: {strings: false, wasm: false}});
  let error;  // kept, so a failing program fails its own checks and the others still report what rendered
  try { vm.runInContext(programOf(html), context, {timeout: 2000}); } catch (caught) { error = caught; }
  return {html, block: block[1], ids, created, parses, context, document, error};
}

const ranCleanly = loaded => {
  assert.ok(loaded, 'The report program was not loaded');
  assert.equal(loaded.error, undefined, loaded.error && String(loaded.error.message));
  assert.deepEqual(loaded.parses, []);
};

function runTests(template) {
  const results = [];
  function check(name, action) {
    try { action(); results.push({name, status: 'pass'}); }
    catch (error) { results.push({name, status: 'fail', message: String(error.message).slice(0, 400)}); }
  }
  const payload = fictionalRecord();
  let report;
  let empty;
  let real;
  const text = (loaded, id) => { assert.ok(loaded, 'The report program did not run'); return loaded.ids.get(id).textContent; };
  const markup = () => template.replace(programOf(template), '').replace(styleOf(template), '');
  const noticeText = () => /<p class="banner" id="not-shown">([^<]*)<\/p>/.exec(template)?.[1];

  check('Each placeholder occurs exactly once in the template', () => {
    for (const mark of [SCRIPT_HASH, STYLE_HASH, DATA]) assert.equal(template.split(mark).length - 1, 1, mark);
    assert.ok(template.includes('<script type="application/json" id="report-data">' + DATA + '</script>'));
  });
  check('The program and the style are static: no placeholder inside them', () => {
    assert.ok(!programOf(template).includes('@@')); assert.ok(!styleOf(template).includes('@@'));
  });
  check('The program has no HTML-parsing, code-generating, timer, handler or style path', () => {
    assert.equal(HTML_PATHS.exec(programOf(template)), null);
  });
  check('The program has no comment and no template literal', () => {
    for (const mark of ['/*', '//', '`']) assert.ok(!programOf(template).includes(mark), mark);
  });
  check('Every identifier in the program is on the allowlist', () => {
    const names = [...withoutStrings(programOf(template)).matchAll(/[A-Za-z_$][\w$]*/g)].map(x => x[0]);
    assert.deepEqual([...new Set(names.filter(x => !PROGRAM_IDENTIFIERS.has(x)))], []);
  });
  check('The program touches only textContent, createElement, append, replaceChildren, className and title of the DOM', () => {
    const members = [...withoutStrings(programOf(template)).matchAll(/\.\s*([A-Za-z_$][\w$]*)/g)].map(x => x[1]);
    assert.deepEqual(members.filter(x => !PROGRAM_MEMBERS.has(x)), []);
  });
  check('The only computed member access in the program is data[key]', () => {
    const accesses = [...withoutStrings(programOf(template)).matchAll(/([A-Za-z_$][\w$]*|[\])])\s*\[([^\]]*)\]/g)]
      .filter(x => !KEYWORDS_BEFORE_BRACKET.has(x[1])).map(x => x[0].replace(/\s+/g, ''));
    assert.deepEqual(accesses, ['data[key]']);
  });
  check('The markup has no handler or style attribute, link, image, control or remote asset', () => {
    const remote = /\son[a-z]+\s*=|\sstyle\s*=|<a\s|href|src\s*=|<img|<link|<iframe|<object|<embed|https?:|url\(|@import/i;
    const found = remote.exec(template) || /<form|<input|<button|<select|<textarea/i.exec(template);
    assert.equal(found, null, found && found[0]);
    assert.equal(HTML_PATHS.exec(markup()), null);
  });
  check('The strict CSP is the first meta in the head', () => {
    const head = template.split('<head>')[1].split('</head>')[0];
    assert.ok(/^<meta http-equiv="Content-Security-Policy" /.test(/<meta [^>]*>/.exec(head)[0]));
    assert.deepEqual(policyOf(template).split('; '), ["default-src 'none'", "script-src 'sha256-" + SCRIPT_HASH + "'",
      "style-src 'sha256-" + STYLE_HASH + "'", "connect-src 'none'", "img-src 'none'", "base-uri 'none'", "form-action 'none'"]);
    assert.ok(!template.includes('unsafe-'));
  });
  check('The program runs without an error or any HTML-parsing call', () => {
    report = loadReport(template, payload);
    ranCleanly(report);
  });
  check('The filled CSP hashes are those of the emitted program and style', () => {
    assert.ok(report);
    const policy = policyOf(report.html);
    assert.ok(policy.includes("script-src 'sha256-" + sha256(programOf(report.html)) + "'"));
    assert.ok(policy.includes("style-src 'sha256-" + sha256(styleOf(report.html)) + "'"));
    assert.ok(policy.includes("connect-src 'none'"));
  });
  check('Every section renders in order under its one heading, each block in order', () => {
    const order = [...template.matchAll(/<section id="([^"]+)"><h2>([^<]*)<\/h2><\/section>/g)];
    assert.deepEqual(order.map(x => x[1]), SECTIONS);
    assert.deepEqual(order.map(x => x[2]), TITLES);
    assert.equal(template.split('<h2>').length - 1, SECTIONS.length);
    for (const key of SECTIONS) {
      const children = report.ids.get(key).children;
      assert.equal(children.length, payload[key].length, key);
      payload[key].forEach(([kind, content], index) => {
        const child = children[index];
        assert.equal(child.tagName, {fields: 'dl', heading: 'h3', note: 'p'}[kind], key + ' block ' + index);
        assert.equal(child.className, kind);
        if (kind === 'fields') assert.equal(child.textContent, content.flat().join(' '), key + ' block ' + index);
        else assert.equal(child.textContent, content, key + ' block ' + index);
      });
    }
  });
  check('The header shows the session fields and both page notes, and the title is set as text', () => {
    for (const [label, value] of payload.header[0][1]) assert.ok(text(report, 'session').includes(label + ' ' + value), label);
    assert.ok(text(report, 'session').includes(PAGE_NOTE)); assert.ok(text(report, 'session').includes(TIME_NOTE));
    assert.equal(report.document.title, payload.title);
  });
  check('A fixture session shows the fictional-demonstration banner', () => {
    const [banner] = report.ids.get('banner').children;
    assert.equal(banner.className, 'banner'); assert.equal(banner.textContent, BANNER);
  });
  check('A real session shows no banner', () => {
    real = loadReport(template, emptyRecord('real'));
    ranCleanly(real);
    assert.deepEqual(real.ids.get('banner').children, []);
  });
  check('Hostile text renders as inert text and creates no active element', () => {
    for (const key of ['scope', 'findings', 'plan', 'approvals', 'outcomes', 'packages']) assert.ok(text(report, key).includes(HOSTILE), key);
    assert.equal(report.context.injected, undefined);
    assert.deepEqual(report.created.map(x => x.tagName).filter(x => !['dl', 'dt', 'dd', 'p', 'h3'].includes(x)), []);
  });
  check('The embedded data keeps the template\'s script boundaries', () => {
    assert.equal(/[<>&]/.exec(report.block), null);
    for (const tag of ['<script', '</script', '<img', '<!--']) assert.equal(report.html.split(tag).length, template.split(tag).length, tag);
  });
  check('Every not-recorded case renders', () => {
    empty = loadReport(template, emptyRecord('fixture'));
    ranCleanly(empty);
    for (const key of SECTIONS) assert.ok(text(empty, key).toLowerCase().includes('not recorded'), key);
    assert.ok(text(empty, 'findings').includes(NO_FINDINGS));
    assert.ok(text(empty, 'scope').includes('Selected folders or drives None listed'));
  });
  check('Attestation labels and their notes render', () => {
    assert.ok(text(report, 'scope').includes('How this was recorded ' + OWNER_ATTESTED));
    assert.ok(text(report, 'reviews').includes('How this was recorded ' + REVIEW_ATTESTED));
    assert.ok(text(report, 'reviews').includes('How this was recorded ' + UNLABELLED));
    assert.ok(text(report, 'approvals').includes('How this was recorded ' + UNLABELLED));
    assert.ok(text(report, 'approvals').includes('How this was recorded Unrecognised label: fictional-other-label'));
    assert.equal(report.ids.get('reviews').children[0].textContent, REVIEWS_NOTE);
    assert.equal(report.ids.get('approvals').children[0].textContent, DECISIONS_NOTE);
    assert.equal(report.ids.get('scope').children.at(-1).textContent, SCOPE_NOTE);
  });
  check('Free space shows the measured change and the estimate in words with exact bytes', () => {
    assert.ok(text(report, 'free_space').includes('Measured change about 11.8 GB more free space (11,811,160,064 bytes)'));
    assert.ok(text(report, 'free_space').includes('Expected change (estimate) about 11.0 GB more free space (11,000,000,000 bytes)'));
    assert.deepEqual(report.ids.get('free_space').children.slice(0, 3).map(x => x.textContent),
      [FREE_SPACE_MEASURED, FREE_SPACE_ESTIMATE, FREE_SPACE_UNITS + EXPLORER_NOTE]);
  });
  check('A step without a result, or waiting for a restart, says so in words', () => {
    assert.ok(text(report, 'outcomes').includes('Result ' + NO_RESULT));
    assert.ok(text(report, 'outcomes').includes('Result ' + RESTART_WAITING + ' Restart decision ' + RESTART_UNDECIDED));
    assert.ok(text(report, 'outcomes').includes('Plan fingerprint An earlier plan (fingerprint begins eeeeeeee)'));
    assert.deepEqual(report.ids.get('outcomes').children.slice(0, 2).map(x => x.textContent), [OUTCOMES_NOTE, EARLIER_PLAN_NOTE]);
    assert.ok(!text(report, 'outcomes').includes('in progress'));
  });
  check('The program does not change the data', () => {
    for (const [loaded, record] of [[report, payload], [empty, emptyRecord('fixture')], [real, emptyRecord('real')]]) {
      assert.ok(loaded);
      assert.deepEqual(JSON.parse(vm.runInContext('JSON.stringify(data)', loaded.context)), record);
    }
  });
  check('The not-run notice is cleared once the report has rendered', () => {
    const notice = report.ids.get('not-shown');
    assert.equal(notice.className, 'hidden'); assert.equal(notice.textContent, '');
    assert.equal(noticeText(), "The report content could not be shown here, so the sections below are empty. The report's contents are "
      + 'still inside this file. Open it in a web browser such as Edge, Chrome, Firefox or Safari, with JavaScript allowed; email and file '
      + 'previews cannot display it. If it stays empty in a browser, the file may have been changed or damaged: ask your assistant to make '
      + 'the report again.');
  });
  check('A record with a section missing leaves the not-run notice in place', () => {
    const broken = fictionalRecord();
    delete broken.packages;
    const loaded = loadReport(template, broken);
    assert.notEqual(loaded.error, undefined);
    const notice = loaded.ids.get('not-shown');
    assert.equal(notice.className, 'banner'); assert.equal(notice.textContent, noticeText());
  });
  check('The fake DOM refuses every HTML-parsing path', () => {
    const parses = [];
    const node = new Element('div', parses);
    assert.throws(() => { node.innerHTML = '<b>x</b>'; });
    assert.throws(() => { node.outerHTML = '<b>x</b>'; });
    assert.throws(() => node.insertAdjacentHTML('beforeend', '<b>x</b>'));
    assert.throws(() => node.innerHTML);
    assert.equal(parses.length, 4);
    // A program that takes an HTML-parsing path fails the run check, even if it caught the error itself.
    const anchor = "const notShown = document.getElementById('not-shown');";
    for (const [line, name] of [["document.getElementById('scope').innerHTML = 'x';", 'innerHTML'],
      ["try { document.getElementById('scope').insertAdjacentHTML('beforeend', 'x'); } catch (ignored) {}", 'insertAdjacentHTML'],
      ["document.write('<p>x</p>');", 'document.write'], ["document.writeln('<p>x</p>');", 'document.writeln']]) {
      const planted = template.replace(anchor, line + '\n' + anchor);
      assert.notEqual(planted, template);
      assert.ok(HTML_PATHS.test(programOf(planted)), name);
      const loaded = loadReport(planted, payload);
      assert.deepEqual(loaded.parses, [name]);
      assert.throws(() => ranCleanly(loaded));
    }
  });
  return {status: results.every(x => x.status === 'pass') ? 'pass' : 'fail',
    scope: 'Real session-report template program, fictional report records, minimal DOM; no browser, pixel or live-system test',
    template_sha256: crypto.createHash('sha256').update(template).digest('hex'), checks: results.length,
    passed: results.filter(x => x.status === 'pass').length, failed: results.filter(x => x.status === 'fail').length, results};
}

module.exports = {runTests};
if (require.main === module) {
  const root = path.resolve(__dirname, '..');
  const result = runTests(fs.readFileSync(path.join(root, 'templates/report.html'), 'utf8'));
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exitCode = result.failed ? 1 : 0;
}
