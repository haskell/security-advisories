# Haskell Security Response Team Process

> Copyright 2017, OpenStack Vulnerability Management Team
> Copyright 2023, Haskell Security Response Team
> This work is licensed under a Creative Commons Attribution 3.0 Unported License.
>   http://creativecommons.org/licenses/by/3.0/legalcode
> Original version: https://opendev.org/openstack/ossa/src/branch/master/doc/source/vmt-process.rst

The HSRT coordinates responsible disclosure of security vulnerabilities in
the Haskell ecosystem and help Haskell users have an accurate and timely
assessment of risks.

Members of the team are independent and security-minded folks who ensure
that vulnerabilities are dealt with in a timely manner and that
downstream stakeholders are notified in a coordinated and fair manner.
Where a member of the team is employed by a downstream stakeholder, the
member does not give their employer prior notice of any vulnerabilities.
In order to reduce the disclosure of vulnerability in the early stages,
membership of this team is intentionally limited to a small number of
people.

## Process

Each security bug is assigned a HSRT *coordinator* (member from the
haskell security response team) that will coordinate the
disclosure process. Here are the steps we follow.

### Reception

High-impact vulnerabilities can be reported privately to
[security-advisories@haskell.org](mailto:security-advisories@haskell.org).
We do not use PGP.  Alternatively, Haskell vulnerabilities can be
reported via the CERT/CC [VINCE] system.  Use "Haskell Programming
Language" as the vendor name.

[VINCE]: https://kb.cert.org/vince/

As a volunteer effort with limited resources, we coordinate security
response for embargoed vulnerabilities for high impact issues only.
Factors that influence whether we will deal with an issue under
embargo or not include:

- How severe is the vulnerability?
- How widely used is the library or tool in which the issue occurs?
- Does the issue also affect other ecosystems, or is there already a
  security response underway?  (We will not break someone else's
  embargo.)

Public reports can be submitted as a [regular issue or PR on the security-advisories repo](https://github.com/haskell/security-advisories/issues).
In that case, please follow the process defined in
the [Reporting Vulnerabilities](./CONTRIBUTING.md) document.

The first steps performed by the HSRT are to:

-   check that the report indicates the correct project and adjust as
    necessary.
-   contact the project's maintainer for confirmation
    of impact and determination of affected version.

### Draft advisory

In the mean time, the HSRT coordinator works with the reporter to
to refine their draft security advisory using the template defined
in the [Reporting Vulnerabilities](./CONTRIBUTING.md) document.

### Review advisory

The advisory is validated by the reporter and the project's maintainer.

### Vulnerability disclosure

Once the patches are approved, a signed email
with the vulnerability description is sent to the downstream
stakeholders. The notice will state the planned disclosure date.
No stakeholder is supposed to deploy public patches before
disclosure date.

### Open bug, Push patch

In preparation for this, make sure you have a maintainer available to
help pushing the fix at disclosure time.

On the disclosure hour, open bug, push patches for review and
fast-track approvals (referencing the bug).

If a CVE got assigned when the report is still private,
[MITRE's CVE Request form](https://cveform.mitre.org/) should be used
again at this point, but instead select a *request type* of
`Notify CVE about a publication` and fill in the coordinator's *e-mail
address*, provide a *link to the advisory*, the *CVE IDs* covered, and
the *date published*. Once more, fill in the
*security code* at the bottom of the page and *submit request*.

### Publish HSEC

Shortly after pushing the patches (potentially waiting for the first
test runs to complete), publish the advisory to the repository.

### All patches merged

Patches approved in code review do not necessarily merge immediately,
but should be tracked closely until they do.

### Abnormal termination

If a report is held in private for 90 days without a fix, or significant
details of the report are disclosed in a public venue, the report is
terminated by a HSRT coordinator at that time and subsequent process
switches to the public report workflow instead.

## Extent of Disclosure

The science of vulnerability management is somewhere around being able
to assess impact and severity of a report, being able to design security
patches, being an obsessive process-following perfectionist and
respecting the rule of lesser disclosure.

Lesser disclosure is about disclosing the vulnerability details to an
increasing number of people over time, but only to the people that are
necessary to reach the next step.

Vulnerability reporters retain final control over the disclosure of
their findings. If for some reason they are uncomfortable with our
process, their choice of disclosure terms prevails.

### Downstream stakeholders

Haskell packages are used in a number of distributions,
products, private and public service offerings that are negatively
affected by vulnerabilities. In the spirit of responsible disclosure,
this ecosystem, collectively known as the downstream stakeholders, needs
to be warned in advance to be able to prepare patches and roll them out
in a coordinated fashion on disclosure day. The disclosure period is kept
voluntarily small (3-5 business days), as a middle ground between
keeping the vulnerability under cover for too long and not giving a
chance to downstream stakeholders to react.

If you're currently not a referenced stakeholder and think you should
definitely be included on that email distribution list, please submit an
email with a rationale to member(s) of the HSRT.

Currently, we use the following private email lists for responsible
disclosures:

- [security@archlinux.org](mailto:security@archlinux.org)
- [security@debian.org](mailto:security@debian.org)
- [security@ubuntu.org](mailto:security@ubuntu.org)
- [security@lists.fedoraproject.org](mailto:security@lists.fedoraproject.org)
- [secalert@redhat.com](mailto:secalert@redhat.com)

We also have a few personal emails for interested parties which are not
published in the repository, for privacy/anti-spam reasons. If you want your
email to be included here, please send us a PR.

## Templates

### Reception reminder (private issues)

    This issue is being treated as a potential security risk.
    Please do not make any public mention of private
    security vulnerabilities before their coordinated
    publication by the Haskell Security Response Team in the
    form of an official Haskell Security Advisory (HSEC). This includes
    discussion of the bug or associated fixes in public forums such as
    mailing lists, code review systems and bug trackers. Please also
    avoid private disclosure to other individuals not already approved
    for access to this information, and provide this same reminder to
    those who are made aware of the issue prior to publication. All
    discussion should remain confined to this private bug report, and
    any proposed fixes should be added to the bug as attachments. This
    status shall not extend past $NINETY_DAYS and will be made
    public by or on that date even if no fix is identified.

The NINETY_DAYS value should be 90 days from the date the report is
accepted by the coordinator and project reviewers are subscribed. It can
be trivially calculated with the `date -I -d90days` shell command.

### Downstream stakeholders notification email (private issues)

-   *To:* TBD
-   *Subject:* [pre-HSEC] Vulnerability in Haskell $PROJECT ($CVE)

The message body for both emails should be identical: :

    This is an advance warning of a vulnerability discovered in
    Haskell $PROJECT, to give you, as downstream stakeholders, a chance to
    coordinate the release of fixes and reduce the vulnerability window.
    Please treat the following information as confidential until the
    proposed public disclosure date.

    $ADVISORY

    See attached patches. Unless a flaw is discovered in them, these
    patches will be merged to their corresponding branches on the public
    disclosure date.

    Proposed public disclosure date/time:
    $DISCLOSURE, 1500UTC
    Please do not make the issue public (or release public patches)
    before this coordinated disclosure date.

    --
    $HSRT_COORDINATOR_NAME
    Haskell Security Response Team

Proposed patches are attached, email must be GPG-signed. Use something
unique and descriptive for the patch attachment file names, for example
`cve-2013-4183-$project.patch` or
`cve-2013-4183-$project-stable-1.0.patch`.

### Haskell security advisories (HSEC)

Refers to the [./EXAMPLE_ADVISORY.md](./EXAMPLE_ADVISORY.md).
