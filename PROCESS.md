# Haskell Security Response Team Process

> Copyright 2017, OpenStack Vulnerability Management Team
> Copyright 2023, Haskell Security Response Team
> This work is licensed under a Creative Commons Attribution 3.0 Unported License.
>   http://creativecommons.org/licenses/by/3.0/legalcode
> Original version: https://opendev.org/openstack/ossa/src/branch/master/doc/source/vmt-process.rst

The Haskell Security Response Team (HSRT) is responsible for coordinating
the progressive disclosure of a vulnerability.

Members of the team are independent and security-minded folks who ensure
that vulnerabilities are dealt with in a timely manner and that
downstream stakeholders are notified in a coordinated and fair manner.
Where a member of the team is employed by a downstream stakeholder, the
member does not give their employer prior notice of any vulnerabilities.
In order to reduce the disclosure of vulnerability in the early stages,
membership of this team is intentionally limited to a small number of
people.

## Supported versions

The Vulnerability Management team coordinates patches fixing
vulnerabilities in packages published via Hackage.

## Process

Each security bug is assigned a HSRT *coordinator* (member from the
haskell security response team) that will drive the fixing and
disclosure process. Here are the steps we follow.

### Reception

Private report can be received by email to [security-advisories@haskell.org](mailto:security-advisories@haskell.org),
or via a [private issue on the security-advisories repo](https://github.com/haskell/security-advisories/security/advisories/new).

Public report can be submitted as a [regular issue on the security-advisories repo](https://github.com/haskell/security-advisories/issues).

The first steps performed by the HSRT are to:

-   create a bug if one does not yet exist.
-   check that the report indicates the correct project and adjust as
    necessary.
-   contact the project's maintainer for confirmation
    of impact and determination of affected version.

### Patch development

For a private report, the reporter (automatic if reported directly as a
bug) and the affected projects' maintainers plus anyone they deem necessary
to develop and validate a fix are added to the bug's notified list.
A fix is proposed as a patch to the private bug report,
**not sent to the public code review system**.

For public reports, there is no need to directly subscribe anyone and
patches can be submitted directly to the code review system instead of
as bug attachments (though the bug should be referenced in any commit
messages so it will be updated automatically).

If project-side delays are encountered at this or any subsequent stage
of the process, the HSRT and other interested parties may reach out to
that project's maintainers requesting more immediate attention to the issue.

### Patch review

For a private report once the initial patch has been attached to the
bug, core reviewers on the subscription list from the project in
question should review it and suggest updates or pre-approve it for
merging. Privately-developed patches need to be pre-approved so that
they can be fast-tracked through public code review later at disclosure
time.

### Draft advisory

In the mean time, the HSRT coordinator prepares a security advisory
that will be communicated to downstream stakeholders.

The description should properly credit the reporter, specify affected
versions (including unsupported ones) and accurately describe impact and
mitigation mechanisms. The HSRT coordinator should use the template
below.

### Review advisory

The advisory is validated by the reporter and the project's maintainer.

### Send CVE request

To ensure full traceability, we attempt to obtain a CVE assignment
before the issue is communicated to a larger public. This is generally
done as the patch gets nearer to final approval. The approved advisory
is submitted through [MITRE's CVE Request form](https://cveform.mitre.org/).
The *request type* is `Request a CVE ID`, the *e-mail address* should be
that of the requester (generally the assigned HSRT coordinator),
and for embargoed reports the coordinator's OpenPGP key should be pasted
into the field provided.

In the *required* section set the checkboxes indicating the product is
not CNA-covered and that no prior CVE ID has been assigned, select an
appropriate *vulnerability type* (using `Other or Unknown` to enter a
freeform type if there is nothing relevant on the drop-down), set the
*vendor* to `Haskell`, and the *product* and *version* fields to match
the `$PROJECTS` and `$AFFECTED_VERSIONS` from the advisory. In
the *optional* section set the radio button for *confirmed/acknowledged*
to `Yes`, choose an appropriate *attack type* in the drop-down (often
this is `Context-dependent` for our cases), check the relevant *impact*
checkboxes, attempt to fill in the *affected components* and *attack
vector* fields if possible, paste in the *suggested description* from
the prose of the advisory (usually omitting the first sentence
as it's redundant with other fields), put the `$CREDIT` details in the
*discoverer/credits* field, and the bug URL in the *references* field.
If the report is still private, note that in the *additional information*
field like
`This report is currently under embargo and no disclosure date has been scheduled at this time.`

At the bottom of the page, fill in the *security code* and click the
*submit request* button. If some fields contain invalid data they will
be highlighted red; correct these, update the *security code* and
*submit request* again until you get a confirmation page.

### Get assigned CVE

MITRE returns the assigned CVE. It is added to the advisory,
and the bug is retitled to `$TITLE ($CVE)`.

### Embargoed disclosure

Once the patches are approved and the CVE is assigned, a signed email
with the vulnerability description is sent to the downstream
stakeholders. The disclosure date is set to 3-5 business days, excluding
Monday/Friday and holiday periods, at 1500 UTC. No stakeholder is
supposed to deploy public patches before disclosure date. Once the email
is sent, any stakeholders who reply requesting subscription to the
report may be added.

For non-embargoed, public vulnerabilities no separate downstream advance
notification is sent.

### Open bug, Push patch

In preparation for this, make sure you have a maintainer available to
help pushing the fix at disclosure time.

On the disclosure hour, open bug, push patches for review and
fast-track approvals (referencing the bug).

Update the bug title to `[HSEC-$NUM] $TITLE`.

Embargo reminder can be removed at that point.

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
but should be tracked closely until they do (if the bug number is
correctly identified in commit messages then it will be automatically
updated to reflect this as well). Subsequent security point releases of
affected software may then be tagged if warranted.

### Abnormal embargo termination

If a report is held in embargo for 90 days without a fix, or significant
details of the report are disclosed in a public venue, the embargo is
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

### Embargo exceptions

To keep the embargo period short and effective, the HSRT may choose to
open bug reports. Issues that take too much time to be fixed (e.g., more
than 2 weeks) or issues that require a complex patch are usually better
solved in the open. Only under unusual circumstances should any embargo
extend past 90 days.

### Downstream stakeholders

Haskell packages are used in a number of distributions,
products, private and public service offerings that are negatively
affected by vulnerabilities. In the spirit of responsible disclosure,
this ecosystem, collectively known as the downstream stakeholders, needs
to be warned in advance to be able to prepare patches and roll them out
in a coordinated fashion on disclosure day. The embargo period is kept
voluntarily small (3-5 business days), as a middle ground between
keeping the vulnerability under cover for too long and not giving a
chance to downstream stakeholders to react.

If you're currently not a referenced stakeholder and think you should
definitely be included on that email distribution list, please submit an
email with a rationale to member(s) of the HSRT.

## Templates

### Reception embargo reminder (private issues)

    This issue is being treated as a potential security risk under
    embargo. Please do not make any public mention of embargoed
    (private) security vulnerabilities before their coordinated
    publication by the Haskell Security Response Team in the
    form of an official Haskell Security Advisory (HSEC). This includes
    discussion of the bug or associated fixes in public forums such as
    mailing lists, code review systems and bug trackers. Please also
    avoid private disclosure to other individuals not already approved
    for access to this information, and provide this same reminder to
    those who are made aware of the issue prior to publication. All
    discussion should remain confined to this private bug report, and
    any proposed fixes should be added to the bug as attachments. This
    embargo shall not extend past $NINETY_DAYS and will be made
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
    before this coordinated embargo date.

    Original private report:
    https://github.com/haskell/security-advisories/issues/$BUG
    For access to read and comment on this report, please reply to me
    with your GitHub username and I will subscribe you.
    --
    $HSRT_COORDINATOR_NAME
    Haskell Security Response Team

Proposed patches are attached, email must be GPG-signed. Use something
unique and descriptive for the patch attachment file names, for example
`cve-2013-4183-main-havana.patch` or
`cve-2013-4183-stable-grizzly.patch`.

### Haskell security advisories (HSEC)

Refers to the [./EXAMPLE_ADVISORY.md](./EXAMPLE_ADVISORY.md).
