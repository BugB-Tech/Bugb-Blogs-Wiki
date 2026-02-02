# The false sense of security from “we run scans in CI”

For a long time, companies felt confident in a simple belief:\
**"We're covered --- we run security scans in CI."**

Static analysis, dependency checks, container scanning, and
Infrastructure-as-Code validation were all wired directly into our
pipelines. Every pull request triggered automated security controls.
Dashboards were green. Reports looked clean. From a development
perspective, security seemed tightly integrated and consistently
enforced.

But over time, incidents and discoveries began to challenge that
confidence. The uncomfortable pattern we noticed was this:

**Our CI pipelines were secure. Our environment was not.**

------------------------------------------------------------------------

## Where the Surprises Came From

### 1. Your External Attack Surface Is Bigger Than Your Repositories

CI pipelines only see what developers commit. Attackers don't operate
within that boundary.

We repeatedly encountered exposures that never appeared in pipeline
scans:

-   Legacy services still running but no longer linked to active
    repositories\
-   Staging environments deployed for short-term testing and never
    decommissioned\
-   Subdomains pointing to systems that no team actively "owned" anymore

From the CI perspective, these assets didn't exist. From an attacker's
perspective, they were fully accessible entry points.

------------------------------------------------------------------------

### 2. Shadow Assets Are Not Edge Cases --- They're Normal

Even in mature organizations with defined processes, infrastructure
often appears outside official workflows:

-   A team spins up a virtual machine for quick testing\
-   A contractor deploys resources in a separate cloud account\
-   Marketing launches a microsite with its own backend

None of these paths necessarily involve code reviews or CI pipelines. As
a result, they operate outside the visibility of traditional DevSecOps
controls.

Internally, everything still looked "green." Externally, the attack
surface had quietly expanded.

------------------------------------------------------------------------

### 3. Many Cloud Misconfigurations Never Touch Code

We invested heavily in scanning what *was* defined as code:

-   Infrastructure-as-Code templates\
-   Dockerfiles and container images\
-   Third-party dependencies

Yet we still uncovered risky exposures such as:

-   Public storage buckets created manually through the cloud console\
-   Security groups opened "temporarily" and never restricted again\
-   Managed services deployed with default or weak security settings

These issues were not introduced through pull requests. No pipeline was
triggered. CI never had a chance to help.

------------------------------------------------------------------------

## The Realization

CI-based security scanning is **repository-centric**.\
Real-world attack surface is **environment-centric**.

Those two worlds overlap, but they are far from identical.

Relying solely on CI security signals can create a dangerous illusion of
full coverage. It's like reinforcing your front door while side
entrances and garage access remain wide open.

------------------------------------------------------------------------

## Moving Forward

CI security scanning remains essential. It reduces risk early, enforces
standards, and prevents many vulnerabilities from ever reaching
production.

But it is only one layer.

To truly understand exposure, organizations also need visibility into:

-   Internet-facing assets that exist outside current repositories\
-   Cloud resources created outside Infrastructure-as-Code workflows\
-   Forgotten environments and services that were never formally retired

Security maturity begins when we stop assuming the pipeline represents
the entire system --- and start treating the live environment as the
source of truth.

------------------------------------------------------------------------

**Question for other security and engineering teams:**\
How are you tracking assets and misconfigurations that never pass
through CI?
