# Haskell Security Response Team - Announcement and Q2 2023 report

The Haskell Security Response Team (SRT) is a volunteer organization
within the Haskell Foundation that is building tools and processes
to aid the entire Haskell ecosystem in assessing and responding to
security risks.  In particular, we maintain a [database][] of
security advisories that can serve as a data source for automated
tooling.

This post announces the SRT membership and the commencement of our
work, and also serves as our first quarterly report.

## How to contact the SRT

For assistance in coordinating a security response to new, high
impact vulnerabilities, contact `security-advisories@haskell.org`.
Due to limited resources, we can only coordinate embargoed
disclosures for high impact vulnerabilities affecting core Haskell
tools and libraries.  We'll decide whether to offer this service on
a case by case basis.

You can submit lower-impact or historical vulnerabilities to the
advisory database via the pull request process.  There are further
details later in this report.

You can also contact the SRT about non-advisory/security-response
topics.  We prefer public communication where possible.  In most
cases, GitHub issues are an appropriate forum.  But the mail address
is there if no other appropriate channel exists.

## SRT membership and kick-off

Fraser Tweedale volunteered to found the team, based on preparatory
work done by the Haskell Foundation's Technical Working Group. After
he came up with an initial set of procedures and the group
structure, we posted a [call for volunteers][] on February 9. We
received many qualified applicants, and it was difficult to choose
the initial committee. We tried to prioritize recruiting people with
non-overlapping technical knowledge as well as substantial
real-world experience managing security processes for open-source
projects.

[call for volunteers]: https://discourse.haskell.org/t/call-for-volunteers-haskell-security-response-team/5770 

The members of the SRT are:

* **Casey Mattingly** - Security Research Scientist at a large
  financial institution, responds to and manages CVEs and
  disclosures, experience with data-driven security governance
  processes, undergoes mandatory annual security trainings with
  employer, implemented three authentication frameworks
* **Fraser Tweedale** - Principal Software Engineer at Red Hat working
  on PKI and identity management solutions.  Organizer of the
  Haskell devroom at FOSDEM and regular speaker at conferences.
* **Gautier Di Folco** - Haskeller for more than a decade, full-time
  for more than two years. Primarily responsible for his companies'
  security policies. Prior experience in secure development in
  networking and telecommunications hardware as well as managing
  security for Web applications.
* **Mihai Maruseac** - Stackage curator, contributor to Stack, former
  contributor to Haskell Communities and Activities Report, founder
  of the TensorFlow security team, member of Google Open Source
  Security Team
* **Tristan de Cacqueray** - Principal Software Engineer at Red Hat.
  Six years of experience on the OpenStack Vulnerability Management
  Team; produced 56 advisories through this process, including
  technical analysis, public communication, and CVE assignment.

Additionally, **David Thrane Christiansen**, Executive Director of
the Haskell Foundation, participates in meetings and helps connect
the group to other Haskell projects.

The first meeting of the SRT was held on May 3.  Most of us were
strangers so we spent some time getting to know each others'
personalities, areas of expertise, and ways of working.  Since then
we've been busy preparing our tools and processes, refining our
database format, and making contact with the broader open source
security response ecosystem.


### Processes

The SRT has a video-conference every 2 weeks.  Meeting notes are
published in the *security-advisories* repository (possibly with
redactions).  Technical discussion is primarily in (public) GitHub
issues and pull requests.  SRT process/management topics and
embargoed vulnerabilities are discussed during our meetings and in a
private mailing list.

### Terms and recruitment

The initial terms of some SRT members will expire at the end of Q3.
We have decided that members wishing to continue may do so.  Closer
to the end of Q3, we will consider whether we should grow the team.
If we decide to do that, and/or there are casual vacancies, we will
put out a new call for volunteers toward the end of Q3.


## Technical work

### Database is open for submissions.

The *security-advisories* [database][] is open for submissions.  So
far, there are only a few historical vulnerabilities, which we used
to test our tool code and submission processes.

We have a list of several known historical advisories ([GitHub
issue][historical advisories]) still to be added.  If you know of
any others, please let us know in the issue (or write and submit the
advisory yourself).

The submission process is detailed in
[`CONTRIBUTING.md`][CONTRIBUTING].  If something goes wrong or the
steps are not sufficiently clear, that is a bug; please let us know
(e.g. create a GitHub issue).

[database]: https://github.com/haskell/security-advisories
[historical advisories]: https://github.com/haskell/security-advisories/issues/32#issuecomment-1588601639
[CONTRIBUTING]: https://github.com/haskell/security-advisories/blob/main/CONTRIBUTING.md

**If you want to submit a new, high-impact vulnerability**, or would
like SRT assistance to coordinate a response, please mail
`security-advisories@haskell.org` with details instead of submitting
a pull request (PRs are public).  Rule of thumb: *a high-severity
vulnerability affecting the GHC toolchain or a popular library*.  If
you think you *might* have a high-impact vulnerability, please
contact the SRT and we will help to assess the impact.

The SRT has not adopted a means of end-to-end encrypted
communication (e.g.  OpenPGP) at this time.


### Advisory format

The advisory format is Markdown with a TOML header containing
metadata, such as affected packages/versions, CVSS scores, and
references.  The [`EXAMPLE_ADVISORY`][EXAMPLE] explains the header
format.

The design followed [RustSec's advisory format][].  During our
initial work, we made some changes to more closely align with the
format used by [OSV](https://osv.dev/), a multi-language repository
of security advisories.  Many systems already read from OSV, making
it even easier for the Haskell community to get value from these
systems.

[EXAMPLE]: https://github.com/haskell/security-advisories/blob/main/EXAMPLE_ADVISORY.md
[RustSec's advisory format]: https://github.com/RustSec/advisory-db#advisory-format


### OSV Export

The [native format](https://ossf.github.io/osv-schema/) of OSV is
generated from our database and published on the
`generated/osv-export` branch.  This makes it easy for systems that
understand OSV to consume our advisories.

We are working with the osv.dev project to get the HSEC source set
up (see [osv.dev issue #1418][]).  As of early July, the OSV test
instance is ingesting HSEC advisories ([results][osv-test]).

[osv.dev issue #1418]: https://github.com/google/osv.dev/issues/1418
[osv-test]: https://oss-vdb-test.appspot.com/list?ecosystem=Hackage


### Automation Improvements

We hope to enable a richer advisory contributor (and reviewer)
experience through GitHub automation.  Ideas are being gathered at
https://github.com/haskell/security-advisories/issues/57.  Community
input or contributions are welcome.  If you have experience
developing GitHub webhook applications, your contributions could be
especially valuable.


### Haskell Development

The `hsec-tools` library and executable live in the
*security-advisories* database, alongside the advisories themselves.
Our code is published under a BSD 3-Clause license.

In Q3 of 2023, we plan to extract the general-purpose OSV-related
datatypes and utilities from our tools into a standalone package and
release it separately on Hackage.  We additionally plan to develop
and release a library for processing [CVSS][] scores.

[CVSS]: https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System


### Rehearsals

We have rehearsed our processes by creating advisories for a number
of already-known security issues in the Haskell ecosystem. This
helped us uncover ways in which our tools, data formats, and
processes were not quite ready.  In addition to the resulting data
being useful, we are now better prepared for incoming reports,
whether confidential or public.


## Future investigations

The [Vulnerability Exploitable eXchange (VEX)][VEX] data model
describes the impact (or lack of) of some vulnerability in a
particular program or component.  The SRT plans to investigate VEX
as a means to suppress false-positives where some dependency of a
program/library contains a vulnerability, but that vulnerability is
mitigated or not present at all in the dependent program.

VEX also requires "action statements" for affected programs, which
are intended to convey possible mitigations, workarounds or
remediations.  Storing and conveying this kind of information in
security tooling could further enhance the Haskell security tooling
story.

[VEX]: https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex


## Opportunities

If you'd like to make it easier for Haskell programmers to avoid
security problems in dependencies, there are many concrete projects
that would be very helpful! The SRT doesn't have the capacity to
take these tasks on, but we're happy to advise.

* Build plan auditing for `cabal-install` would allow users to be
  notified if their build plan depends on a package for which there
  is an advisory, similar to `cargo audit` or `npm audit`. In addition
  to their features, it could also be useful to additionally allow a
  specification of a threat model, so that advisories for attack
  vectors requiring network access would not be shown for offline-only
  applications.

* A tool that scans Stackage snapshots for versions affected by
  advisories, notifying both users and the Stackage maintainers so
  that the snapshot can be updated

* Integration with `hackage-server`, to indicate known-vulnerable
  package versions.

* A tool for project maintainers to generate a skeleton advisory for
  their own project, parsing information out of the Cabal file and
  asking some convenient questions

* Integration with other sources of advisories that don't pull from
  OSV

Generally speaking, we'd like to support every effort to increase
the value that the advisories provide to the Haskell ecosystem.
However, it is not within the capacity or scope of the SRT to
develop all the above ideas.  Instead, we hope to collaborate with
"downstream" projects, evolving both the database content and the
associated tools and libraries to meet their needs.
