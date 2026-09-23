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

The rule lives in [`policies/block-critical.rego`](./policies/block-critical.rego). You attach it to a **Policy Set** (entity **Security Tests**, event **On Step**, action **Error and exit**). Enforced sets run automatically after every scan step in scope.

---

## Prerequisites

Before you start, make sure you have:

- A Harness account with a **Project** (note org + project identifiers).
- **STO** enabled. Permission to create **Policies** and **Policy Sets**.
- A Git connector that can clone this repo (or your fork).
- Harness Cloud build credits.

---

## Step 1 — Fork and look at the scan target

The scan input is [`requirements.txt`](./requirements.txt). Fork the repo so your Git connector can read it.

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
2. Name: `STO Block Critical`.
3. **Entity type:** Security Tests.
4. **Event:** On Step.
5. **Add Policy:** `Block Critical CVEs`.
6. **Action:** Error and exit.
7. Finish. Leave the set **Enforced**.

---

## Step 4 — Import the pipeline

1. **Pipelines → Create a Pipeline** → YAML.
2. Paste [`.harness/pipeline.yaml`](./.harness/pipeline.yaml).
3. Set org, project, and `repoName` to your fork.
4. Save.

The Trivy step publishes results and fails the step when it finds a Critical issue. The Policy Set applies the same threshold after the scan.

---

## Step 5 — Run (expect a RED build)

**Run.** Git connector, repo, branch `main`.

Trivy finds Critical issues (for example CVE-2020-14343 on PyYAML 5.3.1 — the list follows Trivy’s DB). The scan step fails because **Fail on Severity** is Critical. The Policy Set evaluates **On Step**, sees `CRITICAL > 0`, and **Error and exit**.

Open **Security Tests** on the execution. Then open the policy evaluation on the step. The pipeline is red.

**Red is the correct outcome.** The policy blocked the build.

---

## Step 6 — Clear Criticals, go green

Bump the pins:

```txt
flask>=3.0.0
pyyaml>=6.0.1
requests>=2.32.0
urllib3>=2.2.2
jinja2>=3.1.4
```

Commit, push, re-run. If Critical is 0, the policy passes and the pipeline is green. High findings can remain; this policy only counts Critical.

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

[`.harness/pipeline.yaml`](./.harness/pipeline.yaml) — Aqua Trivy on the cloned repo; Policy Set is not in the pipeline YAML. It is attached in **Policies**.

---

## Common Issues & Tips

**Scan is green, pipeline is still red.** That is the policy. Open the step’s policy evaluation.

**Pipeline is green with Criticals in Security Tests.** The Policy Set is not Enforced, wrong scope (project vs account), entity is not **Security Tests**, or event is not **On Step**.

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
