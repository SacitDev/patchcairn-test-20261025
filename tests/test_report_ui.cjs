// Execute the actual shared report JavaScript against fictional data only.
// Node standard library; this is a DOM behavior test, not a browser/pixel test.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

class Element {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.children = [];
    this.value = '';
    this.style = {};
    this.listeners = {};
    this._text = '';
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(x => x.textContent ?? String(x)).join(' '); }
  set innerHTML(_) { throw Error('Imported HTML must never be parsed'); }
  insertAdjacentHTML() { throw Error('Imported HTML must never be parsed'); }
  append(...values) { this.children.push(...values); }
  replaceChildren(...values) { this._text = ''; this.children = [...values]; }
  addEventListener(name, handler) { this.listeners[name] = handler; }
}

function fictionalData() {
  const malicious = '</script><script>globalThis.uiInjected=true</script><img src=x onerror="globalThis.uiInjected=true">';
  const evidence = (id, scope) => ({id, relative_path: 'evidence/' + id + '.json', sha256: 'a'.repeat(64),
    kind: 'fictional_receipt', observed_utc: '2026-01-02T03:04:05Z', scope, limits: 'Fictional scope only'});
  const component = (id, name, findingIds) => ({id, name, kind: 'runtime', installed_version: '1.0',
    reviewed_target: null, available_release: null, update_state: 'held', security_state: 'conditional',
    compatibility_state: 'not_tested', owner_scope: 'vendor_bundle', evidence_ids: [], finding_ids: findingIds,
    agent_id: 'fixture-reviewer', next_step: 'Review the fictional compatibility condition.'});
  const ledger = {schema_version: '1.0', toolkit_id: '00000000-0000-4000-8000-000000000000',
    run: {id: 'run-' + '0'.repeat(32), mode: 'fixture', platform: 'unknown', phase: 'assessment', status: 'held',
      created_utc: '2026-01-02T03:04:05Z', updated_utc: '2026-01-02T03:04:05Z',
      purpose: 'Fictional report behavior test', pending_restart: false},
    coverage: [],
    components: [component('component-a', 'Fictional Component A', []), component('component-b', 'Fictional Component B', ['finding-linked'])],
    findings: [
      {id: 'finding-run', component_id: null, title: 'Run-wide recovery concern', kind: 'diagnostic', state: 'held',
        claim: 'A run-wide recovery condition needs review.', conditions: [], evidence_ids: [], source_ids: []},
      {id: 'finding-unlinked', component_id: 'component-a', kind: 'security', state: 'open',
        claim: 'An unbacklinked integrity finding remains open.', conditions: ['Only when the fictional feature is enabled'],
        evidence_ids: ['receipt-unlinked'], source_ids: ['source-fictional']},
      {id: 'finding-linked', component_id: 'component-b', title: 'Backlinked condition', kind: 'compatibility', state: 'conditional',
        claim: 'A linked finding also appears in the complete list.', conditions: ['Fictional compatibility prerequisite'],
        evidence_ids: ['receipt-linked'], source_ids: []},
      {id: 'finding-resolved', component_id: null, title: malicious, kind: 'security', state: 'resolved_scoped',
        claim: malicious, conditions: [malicious], evidence_ids: ['receipt-hostile'], source_ids: []}
    ],
    evidence: [evidence('receipt-unlinked', 'Fictional unbacklinked observation'), evidence('receipt-linked', 'Fictional linked observation'),
      evidence('receipt-hostile', malicious)],
    sources: [{id: 'source-fictional', url: 'https://example.invalid/security', title: 'Fictional publisher advisory',
      authority: 'official_vendor', retrieved_utc: '2026-01-02T03:04:05Z', provenance_verified: false, checks: []}],
    actions: [], approvals: [], diagnosis: {status: 'not_started', hypotheses: [], original_cause: null,
      uncertainty: 'Fictional data only', least_disruptive_fix: null, repair_approved: false}};
  return {ledger, summary: {schema_version: '1.0', run_id: ledger.run.id, mode: 'fixture', ledger_sha256: 'b'.repeat(64),
    component_records: 2, completed_action_records: 0, completed_action_groups: 0, open_finding_records: 3,
    update_states: {held: 2}, security_states: {conditional: 2}, compatibility_states: {not_tested: 2},
    counts_are_not_security_clearance: true, generated_from_one_ledger_snapshot: true}};
}

function loadReport(template, payload) {
  const inert = JSON.stringify(payload).replaceAll('<', '\\u003c').replaceAll('>', '\\u003e').replaceAll('&', '\\u0026');
  const html = template.replace('@@BRAND_LOGO@@', '').replace('@@LEDGER_SHA@@', payload.summary.ledger_sha256).replace('@@DATA@@', inert);
  const dataMatch = /<script id="toolkit-data" type="application\/json">([\s\S]*?)<\/script>/.exec(html);
  assert.ok(dataMatch, 'Actual report data element must exist');
  const program = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
    .map(x => x[1]).find(x => x.includes("'use strict'"));
  assert.ok(program, 'Actual embedded report JavaScript must exist');
  const ids = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(x => [x[1], new Element()]));
  ids.get('toolkit-data').textContent = dataMatch[1];
  for (const match of html.matchAll(/<select[^>]*id="([^"]+)"/g)) ids.get(match[1]).value = 'all';
  const created = [];
  const context = vm.createContext({document: {
    getElementById(id) { assert.ok(ids.has(id), 'Missing actual markup ID: ' + id); return ids.get(id); },
    createElement(tag) { const result = new Element(tag); created.push(result); return result; }
  }, URL}, {codeGeneration: {strings: false, wasm: false}});
  vm.runInContext(program, context, {timeout: 2000});
  return {ids, context, created, html};
}

function runTests(template) {
  const results = [];
  function check(name, action) {
    try { action(); results.push({name, status: 'pass'}); }
    catch (error) { results.push({name, status: 'fail', message: String(error.message).slice(0, 400)}); }
  }
  const payload = fictionalData();
  const {ids, context, created, html} = loadReport(template, payload);
  const element = id => { assert.ok(ids.has(id), 'Required actual report element missing: ' + id); return ids.get(id); };
  const findingCards = () => element('finding-cards').children.filter(x => x.tagName === 'article');
  const componentCards = () => element('cards').children.filter(x => x.tagName === 'article');
  const event = (id, type) => { const target = element(id); assert.equal(typeof target.listeners[type], 'function'); target.listeners[type](); };
  const cardContaining = phrase => findingCards().find(x => x.textContent.includes(phrase));

  check('The all-findings section exists in actual markup', () => element('all-findings'));
  check('Every canonical finding is initially visible exactly once in the complete list', () => assert.equal(findingCards().length, 4));
  check('Finding count uses all records, separately from open findings', () => assert.ok(element('finding-count').textContent.startsWith('4 of 4')));
  check('Run-wide finding claim, title and status are visible', () => {
    const card = cardContaining('A run-wide recovery condition'); assert.ok(card); assert.ok(card.textContent.includes('Run-wide recovery concern'));
    assert.ok(card.textContent.includes('Status: held')); assert.ok(card.textContent.includes('Run-wide finding'));
  });
  check('Unbacklinked component finding is visible with component context', () => {
    const card = cardContaining('An unbacklinked integrity finding'); assert.ok(card); assert.ok(card.textContent.includes('Fictional Component A'));
  });
  check('Missing optional title has an explicit finding-ID fallback', () => assert.ok(cardContaining('An unbacklinked integrity finding').textContent.includes('Finding finding-unlinked')));
  check('Backlinked finding is present once in complete list', () => assert.equal(findingCards().filter(x => x.textContent.includes('A linked finding also')).length, 1));
  check('Evidence reference, observation, scope and limits are visible', () => {
    const text = cardContaining('An unbacklinked integrity finding').textContent;
    for (const expected of ['receipt-unlinked', '2026-01-02T03:04:05Z', 'Fictional unbacklinked observation', 'Fictional scope only']) assert.ok(text.includes(expected));
  });
  check('Conditions are visible', () => assert.ok(cardContaining('An unbacklinked integrity finding').textContent.includes('Only when the fictional feature is enabled')));
  check('Missing evidence and conditions remain explicit unknowns', () => {
    const text = cardContaining('A run-wide recovery condition').textContent;
    assert.ok(text.includes('No evidence recorded')); assert.ok(text.includes('No conditions recorded'));
  });
  check('Optional source context is visible', () => assert.ok(cardContaining('An unbacklinked integrity finding').textContent.includes('Fictional publisher advisory')));
  check('Hostile finding title, claim, condition and evidence remain literal text', () => {
    const card = cardContaining('globalThis.uiInjected=true'); assert.ok(card); assert.ok(card.textContent.includes('<img src=x onerror='));
    assert.equal(context.uiInjected, undefined);
  });
  check('Imported strings create no executable or remote media DOM elements', () => assert.equal(created.filter(x => ['script', 'img', 'iframe', 'object'].includes(x.tagName)).length, 0));
  check('Embedding preserves JSON script boundary and offline policy', () => {
    assert.equal([...html.matchAll(/<script(?:\s[^>]*)?>/g)].length, 2);
    assert.ok(html.includes("connect-src 'none'"));
  });
  check('Component filters cannot hide run-wide or unbacklinked findings', () => {
    element('search').value = 'does-not-match-any-component'; event('search', 'input');
    assert.equal(componentCards().length, 0); assert.equal(findingCards().length, 4);
    assert.ok(cardContaining('An unbacklinked integrity finding'));
  });
  check('Component filters reset independently', () => { element('search').value = ''; event('search', 'input'); assert.equal(componentCards().length, 2); });
  check('Finding status options contain every recorded state', () => {
    const values = element('finding-state').children.map(x => x.value);
    for (const expected of ['held', 'open', 'conditional', 'resolved_scoped']) assert.ok(values.includes(expected));
  });
  check('Finding status filter renders only its selected records', () => {
    element('finding-state').value = 'held'; event('finding-state', 'change');
    assert.equal(findingCards().length, 1); assert.ok(cardContaining('A run-wide recovery condition'));
    assert.ok(element('finding-count').textContent.startsWith('1 of 4'));
  });
  check('Finding search and status compose without changing component cards', () => {
    element('finding-search').value = 'unbacklinked'; event('finding-search', 'input');
    assert.equal(findingCards().length, 0); assert.equal(componentCards().length, 2);
    element('finding-state').value = 'all'; event('finding-state', 'change');
    assert.equal(findingCards().length, 1); assert.ok(cardContaining('An unbacklinked integrity finding'));
  });
  check('Finding search includes evidence text', () => {
    element('finding-search').value = 'receipt-unlinked'; event('finding-search', 'input');
    assert.equal(findingCards().length, 1);
  });
  check('Finding filters reset to the full ledger cardinality', () => {
    element('finding-search').value = ''; event('finding-search', 'input'); assert.equal(findingCards().length, 4);
  });
  check('Open-finding summary stays distinct from all-finding list and filters', () => {
    assert.ok(element('summary').children.some(x => x.textContent.startsWith('3') && x.textContent.includes('Open finding records')));
  });
  check('All-findings rendering does not mutate source findings or component backlinks', () => {
    const stored = vm.runInContext('JSON.stringify(L)', context);
    assert.deepEqual(JSON.parse(stored), payload.ledger);
  });
  check('A zero-component assessment still displays run-wide findings', () => {
    const isolated = fictionalData(); isolated.ledger.components = []; isolated.ledger.findings = [isolated.ledger.findings[0]];
    isolated.summary.component_records = 0; isolated.summary.open_finding_records = 1;
    const report = loadReport(template, isolated);
    assert.equal(report.ids.get('finding-cards').children.filter(x => x.tagName === 'article').length, 1);
  });
  check('An empty findings list does not claim the computer is secure', () => {
    const empty = fictionalData(); empty.ledger.findings = []; empty.ledger.components.forEach(x => {x.finding_ids = [];}); empty.summary.open_finding_records = 0;
    const report = loadReport(template, empty);
    assert.ok(report.ids.get('finding-cards').textContent.includes('does not establish'));
  });
  return {status: results.every(x => x.status === 'pass') ? 'pass' : 'fail', scope: 'Actual shared-template JavaScript, fictional data, minimal DOM; no browser/pixel or live-system test',
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
