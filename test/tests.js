const assert = require('assert');
const { evaluate } = require('../server.js');

function basePayload(overrides = {}) {
  const payload = {
    target: 'preview',
    event: 'push',
    ref: 'refs/heads/feature-x',
    workflow: {
      trigger: 'push',
      permissions: { contents: 'read', packages: 'write', 'id-token': 'none' },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [
        { owner: 'actions', name: 'checkout', ref: 'v4' },
        { owner: 'some-org', name: 'cool-action', ref: 'a'.repeat(40) },
      ],
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: 'none',
      criticalVulnerabilities: 0,
      digestPinned: true,
    },
  };
  return Object.assign({}, payload, overrides);
}

let passed = 0;
let failed = 0;

function check(name, actual, expectedDecision, expectedViolations) {
  try {
    assert.strictEqual(actual.decision, expectedDecision, `${name}: decision mismatch`);
    const a = [...actual.violations].sort();
    const e = [...expectedViolations].sort();
    assert.deepStrictEqual(a, e, `${name}: violations mismatch (got ${JSON.stringify(a)})`);
    console.log(`PASS: ${name}`);
    passed++;
  } catch (err) {
    console.error(`FAIL: ${name} -> ${err.message}`);
    failed++;
  }
}

// 1. Fully clean preview payload -> promote
check('clean preview promotes', evaluate(basePayload()), 'promote', []);

// 2. Fully clean production payload -> promote
check(
  'clean production promotes',
  evaluate(
    basePayload({
      target: 'production',
      event: 'push',
      ref: 'refs/heads/main',
      workflow: Object.assign({}, basePayload().workflow, { environmentApproval: true }),
    })
  ),
  'promote',
  []
);

// 3. Excess permission (extra scope)
{
  const p = basePayload();
  p.workflow.permissions = { contents: 'read', packages: 'write', 'id-token': 'none', issues: 'write' };
  check('excess permission (extra key)', evaluate(p), 'block', ['EXCESS_PERMISSION']);
}

// 4. Wrong permission value
{
  const p = basePayload();
  p.workflow.permissions.contents = 'write';
  check('excess permission (wrong value)', evaluate(p), 'block', ['EXCESS_PERMISSION']);
}

// 5. Unsafe PR trigger
{
  const p = basePayload({ event: 'pull_request', ref: 'refs/pull/1/merge' });
  p.workflow.trigger = 'pull_request_target';
  check('unsafe pr trigger', evaluate(p), 'block', ['UNSAFE_PR_TRIGGER']);
}

// 6. Safe PR
{
  const p = basePayload({ event: 'pull_request', ref: 'refs/pull/1/merge' });
  p.workflow.trigger = 'pull_request';
  check('safe pr', evaluate(p), 'promote', []);
}

// 7. Tests incomplete (matrix not complete)
{
  const p = basePayload();
  p.workflow.matrixComplete = false;
  check('tests incomplete (matrix)', evaluate(p), 'block', ['TESTS_INCOMPLETE']);
}

// 8. Tests incomplete (failFast true)
{
  const p = basePayload();
  p.workflow.failFast = true;
  check('tests incomplete (failFast)', evaluate(p), 'block', ['TESTS_INCOMPLETE']);
}

// 9. Mutable action (third-party using a tag)
{
  const p = basePayload();
  p.workflow.actions = [
    { owner: 'actions', name: 'checkout', ref: 'v4' },
    { owner: 'some-org', name: 'cool-action', ref: 'v1.2.3' },
  ];
  check('mutable action', evaluate(p), 'block', ['MUTABLE_ACTION']);
}

// 10. Mutable action - uppercase SHA rejected
{
  const p = basePayload();
  p.workflow.actions = [{ owner: 'some-org', name: 'cool-action', ref: 'A'.repeat(40) }];
  check('mutable action (uppercase sha rejected)', evaluate(p), 'block', ['MUTABLE_ACTION']);
}

// 11. Single stage image
{
  const p = basePayload();
  p.image.multiStage = false;
  check('single stage image', evaluate(p), 'block', ['SINGLE_STAGE_IMAGE']);
}

// 12. Root runtime
{
  const p = basePayload();
  p.image.runsAsRoot = true;
  check('root runtime', evaluate(p), 'block', ['ROOT_RUNTIME']);
}

// 13. Secret in layer (arg)
{
  const p = basePayload();
  p.image.secretMode = 'arg';
  check('secret in layer (arg)', evaluate(p), 'block', ['SECRET_IN_LAYER']);
}

// 14. Secret in layer (copy)
{
  const p = basePayload();
  p.image.secretMode = 'copy';
  check('secret in layer (copy)', evaluate(p), 'block', ['SECRET_IN_LAYER']);
}

// 15. BuildKit secret is fine
{
  const p = basePayload();
  p.image.secretMode = 'buildkit';
  check('buildkit secret allowed', evaluate(p), 'promote', []);
}

// 16. Critical CVE
{
  const p = basePayload();
  p.image.criticalVulnerabilities = 2;
  check('critical cve', evaluate(p), 'block', ['CRITICAL_CVE']);
}

// 17. Unpinned image
{
  const p = basePayload();
  p.image.digestPinned = false;
  check('unpinned image', evaluate(p), 'block', ['UNPINNED_IMAGE']);
}

// 18. Invalid production ref (wrong branch)
{
  const p = basePayload({ target: 'production', event: 'push', ref: 'refs/heads/develop' });
  p.workflow.environmentApproval = true;
  check('invalid production ref (branch)', evaluate(p), 'block', ['INVALID_PRODUCTION_REF']);
}

// 19. Invalid production ref (wrong event)
{
  const p = basePayload({ target: 'production', event: 'pull_request', ref: 'refs/heads/main' });
  p.workflow.trigger = 'pull_request';
  p.workflow.environmentApproval = true;
  check('invalid production ref (event)', evaluate(p), 'block', ['INVALID_PRODUCTION_REF']);
}

// 20. Approval required
{
  const p = basePayload({ target: 'production', event: 'push', ref: 'refs/heads/main' });
  // no environmentApproval field
  check('approval required', evaluate(p), 'block', ['APPROVAL_REQUIRED']);
}

// 21. Multi-failure combo
{
  const p = basePayload({ target: 'production', event: 'pull_request', ref: 'refs/heads/develop' });
  p.workflow.permissions.issues = 'write';
  p.workflow.trigger = 'pull_request_target';
  p.workflow.matrixComplete = false;
  p.workflow.actions = [{ owner: 'some-org', name: 'x', ref: 'main' }];
  p.image.multiStage = false;
  p.image.runsAsRoot = true;
  p.image.secretMode = 'copy';
  p.image.criticalVulnerabilities = 5;
  p.image.digestPinned = false;
  check(
    'multi-failure combo',
    evaluate(p),
    'block',
    [
      'EXCESS_PERMISSION',
      'UNSAFE_PR_TRIGGER',
      'TESTS_INCOMPLETE',
      'MUTABLE_ACTION',
      'SINGLE_STAGE_IMAGE',
      'ROOT_RUNTIME',
      'SECRET_IN_LAYER',
      'CRITICAL_CVE',
      'UNPINNED_IMAGE',
      'INVALID_PRODUCTION_REF',
      'APPROVAL_REQUIRED',
    ]
  );
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
