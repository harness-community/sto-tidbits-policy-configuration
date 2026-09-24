# STO | Tidbits | Policy Configuration

> **Bite-sized how-to** | ~10 min setup

---

> ## ⚠️ This repo pins vulnerable dependencies on purpose
>
> `requirements.txt` is pinned to old versions with known CVEs so the scan has something to fail on. **Do not** copy it into a real project.

---

## What is an STO policy?

An STO **policy** is a rule that runs **after a scan step**. It reads the Security Tests results and either lets the pipeline continue or stops it.

This tidbit’s rule is a simple threshold: **if Critical count is greater than 0, fail.** The scan still finishes (so you can open Security Tests). The **policy** is what turns that into a red pipeline.

The rule lives in [`policies/block-critical.rego`](./policies/block-critical.rego). You attach it to a **Policy Set** (entity **Security Tests**, event **On Step**, action **Error and exit**), then reference that set on the Trivy step with `enforce.policySets`.

---

## Prerequisites

Before you start, make sure you have:

- A Harness account with a **Project** (note org + project identifiers).
- **STO** enabled. Permission to create **Policies** and **Policy Sets**.
- A GitHub connector that can clone this public repo. Set the connector up in the [connector usage tidbit](https://university-registration.harness.io/self-paced-training-tidbit-introduction-to-cd-connector-usage). This tidbit does not cover connector setup.
- Harness Cloud build credits.

---

## Step 1 — Look at the scan target

The scan input is [`requirements.txt`](./requirements.txt). The pipeline clones this public repo. You do not need a fork.

If you do not have a GitHub connector yet, create one in the [connector usage tidbit](https://university-registration.harness.io/self-paced-training-tidbit-introduction-to-cd-connector-usage).

---

## Step 2 — Create the policy

1. **Project Settings → Policies → New Policy** (or Account/Org Policies, same idea).
2. Name it `Block Critical CVEs`.
3. Paste [`policies/block-critical.rego`](./policies/block-critical.rego).
4. Save.

That file is the threshold: `CRITICAL > 0` → deny.

---

## Step 3 — Create the Policy Set and enforce it

1. **Policies → Policy Sets → New Policy Set**.
2. Name: `STO Block Critical`. The identifier must be `STO_Block_Critical`. That is the id the pipeline references.
3. **Entity type:** Security Tests. **Pipeline / On Run** does not see the scan output, so the policy passes.
4. **Event:** On Step.
5. **Add Policy:** `Block Critical CVEs`.
6. **Action:** Error and exit.
7. Finish. Leave the set **Enforced**.

---

## Step 4 — Import the pipeline

1. **Pipelines → Create a Pipeline** → YAML.
2. Paste [`.harness/pipeline.yaml`](./.harness/pipeline.yaml).
3. Set org and project. `repoName` stays `harness-community/sto-tidbits-policy-configuration`.
4. Save.

`fail_on_severity` is `none`, so Trivy publishes results and the scan command itself does not fail the step. `enforce.policySets` lists `STO_Block_Critical`. That set is what blocks the step.

---

## Step 5 — Run (expect a RED build)

**Run.** Git connector, repo, branch `main`.

Trivy finds Critical issues (for example CVE-2020-14343 on PyYAML 5.3.1 — the list follows Trivy’s DB). The scan command finishes. Open the **Trivy SCA** step, then **Policy Enforcement**. The set denies with `Fail: 1 Critical issue(s). Threshold is 0.` The pipeline is red.

**Red is the correct outcome.** The policy blocked the build. This tidbit does not bump the pins or re-run for a green build.

---

## Policy and pipeline reference

[`policies/block-critical.rego`](./policies/block-critical.rego):

```rego
package securityTests

deny[msg] {
  input[i].name == "output"
  critical := to_number(input[i].outcome.outputVariables.CRITICAL)
  critical > 0
  msg := sprintf("Fail: %d Critical issue(s). Threshold is 0.", [critical])
}
```

[`.harness/pipeline.yaml`](./.harness/pipeline.yaml) — Aqua Trivy on this public repo, `fail_on_severity: none`, and `enforce.policySets: STO_Block_Critical`.

---

## Common Issues & Tips

**Scan is green, pipeline is still red.** That is the policy. Open the step’s policy evaluation.

**Pipeline is green with Criticals in Security Tests.** The step’s `enforce.policySets` id does not match the set, the set is not Enforced, the entity is not **Security Tests**, or the event is not **On Step**. **Pipeline / On Run** evaluates the pipeline, not the scan output, so that set stays green.

**Want to block High as well.** Add a second deny on `outputVariables.HIGH`, or change the threshold.

---

## What's next?

- **Warn & continue** on the Policy Set instead of Error and exit — same rule, no hard fail.
- Library samples under **Entity: Security Tests** (CVE id, issue age, occurrence count).
- [Exemptions](https://developer.harness.io/docs/security-testing-orchestration/get-started/key-concepts/exemptions/) for a Critical you accept.

---

## Resources

- [Policy as Code for Security Tests](https://developer.harness.io/docs/platform/governance/policy-as-code/policy-as-code-for-security-tests/)
- [Create OPA policies for STO](https://developer.harness.io/docs/security-testing-orchestration/policies/create-opa-policies/)
- [Aqua Trivy step](https://developer.harness.io/docs/security-testing-orchestration/sto-techref-category/trivy/aqua-trivy-scanner-reference/)
