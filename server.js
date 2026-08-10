const express = require('express');
const app = express();
app.use(express.json());

const SHA_RE = /^[0-9a-f]{40}$/;
const REQUIRED_PERMS = { contents: 'read', packages: 'write', 'id-token': 'none' };

function evaluate(body) {
  const violations = [];
  body = body || {};
  const target = body.target;
  const event = body.event;
  const ref = body.ref;
  const wf = body.workflow || {};
  const img = body.image || {};
  const perms = wf.permissions || {};

  // 1. Permissions must be exactly least privilege, no more, no less.
  const permKeys = Object.keys(perms);
  const reqKeys = Object.keys(REQUIRED_PERMS);
  const hasExtraKey = permKeys.some((k) => !reqKeys.includes(k));
  const hasMissingKey = reqKeys.some((k) => !(k in perms));
  const hasWrongValue = reqKeys.some((k) => perms[k] !== REQUIRED_PERMS[k]);
  if (hasExtraKey || hasMissingKey || hasWrongValue) {
    violations.push('EXCESS_PERMISSION');
  }

  // 2. PR runs must never be configured on pull_request_target.
  if (event === 'pull_request' && wf.trigger !== 'pull_request') {
    violations.push('UNSAFE_PR_TRIGGER');
  }

  // 3. Full matrix must complete, tests must pass, no fail-fast.
  if (wf.testsPassed !== true || wf.matrixComplete !== true || wf.failFast !== false) {
    violations.push('TESTS_INCOMPLETE');
  }

  // 4. Third-party actions must be pinned to a full 40-char lowercase commit SHA.
  //    Actions owned by "actions" may use a version tag.
  const actions = Array.isArray(wf.actions) ? wf.actions : [];
  const hasMutableAction = actions.some((a) => {
    if (!a) return true;
    if (a.owner === 'actions') return false;
    return !SHA_RE.test(String(a.ref || ''));
  });
  if (hasMutableAction) {
    violations.push('MUTABLE_ACTION');
  }

  // 5. Image hardening checks.
  if (img.multiStage !== true) violations.push('SINGLE_STAGE_IMAGE');
  if (img.runsAsRoot !== false) violations.push('ROOT_RUNTIME');
  if (!['none', 'buildkit'].includes(img.secretMode)) violations.push('SECRET_IN_LAYER');
  if (img.criticalVulnerabilities !== 0) violations.push('CRITICAL_CVE');
  if (img.digestPinned !== true) violations.push('UNPINNED_IMAGE');

  // 6. Production requires push to main and explicit environment approval.
  if (target === 'production') {
    if (event !== 'push' || ref !== 'refs/heads/main') {
      violations.push('INVALID_PRODUCTION_REF');
    }
    if (wf.environmentApproval !== true) {
      violations.push('APPROVAL_REQUIRED');
    }
  }

  return {
    decision: violations.length === 0 ? 'promote' : 'block',
    violations,
  };
}

app.post('/release-gate', (req, res) => {
  res.json(evaluate(req.body));
});

app.get('/', (_req, res) => {
  res.send('release-gate service is up. POST JSON to /release-gate');
});

module.exports = { app, evaluate };

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`release-gate listening on port ${port}`));
}
