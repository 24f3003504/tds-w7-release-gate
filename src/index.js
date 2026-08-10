const REQUIRED_PERMS = {
  contents: "read",
  packages: "write",
  "id-token": "none",
};
const SHA_RE = /^[0-9a-f]{40}$/;

function evaluate(body) {
  const violations = [];
  const { target, event, ref } = body;
  const workflow = body.workflow || {};
  const image = body.image || {};
  const perms = workflow.permissions || {};

  // 1. Least-privilege permissions — must match EXACTLY, no more, no less
  const permKeys = Object.keys(perms);
  const reqKeys = Object.keys(REQUIRED_PERMS);
  const sameKeySet =
    permKeys.length === reqKeys.length &&
    reqKeys.every((k) => permKeys.includes(k));
  const valuesMatch = reqKeys.every((k) => perms[k] === REQUIRED_PERMS[k]);
  if (!sameKeySet || !valuesMatch) violations.push("EXCESS_PERMISSION");

  // 2. PR trigger safety
  const isPR = event === "pull_request";
  const trigger = workflow.trigger;
  if (
    trigger === "pull_request_target" ||
    (isPR && trigger !== "pull_request")
  ) {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  // Tests / matrix — only meaningful in a PR flow
  if (isPR) {
    const ok =
      workflow.testsPassed === true &&
      workflow.matrixComplete === true &&
      workflow.failFast === false;
    if (!ok) violations.push("TESTS_INCOMPLETE");
  }

  // 3. Action pinning
  const actions = Array.isArray(workflow.actions) ? workflow.actions : [];
  const hasMutable = actions.some((a) => {
    if (!a) return true;
    if (a.owner === "actions") return false; // first-party, tag ok
    return !SHA_RE.test(a.ref || "");
  });
  if (hasMutable) violations.push("MUTABLE_ACTION");

  // 4. Image hardening
  if (image.multiStage !== true) violations.push("SINGLE_STAGE_IMAGE");
  if (image.runsAsRoot !== false) violations.push("ROOT_RUNTIME");
  if (!["none", "buildkit"].includes(image.secretMode))
    violations.push("SECRET_IN_LAYER");
  if (image.criticalVulnerabilities !== 0) violations.push("CRITICAL_CVE");
  if (image.digestPinned !== true) violations.push("UNPINNED_IMAGE");

  // 5. Production extras
  if (target === "production") {
    if (!(event === "push" && ref === "refs/heads/main")) {
      violations.push("INVALID_PRODUCTION_REF");
    }
    if (workflow.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations,
  };
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/release-gate") {
      return new Response("Not found", { status: 404 });
    }
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(
        JSON.stringify({ decision: "block", violations: ["INVALID_REQUEST"] }),
        { status: 400, headers: { "content-type": "application/json" } },
      );
    }
    const result = evaluate(body);
    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  },
};
