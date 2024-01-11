# Haskell Security Response Team - 2023 July–December report

The Haskell Security Response Team (SRT) is a volunteer organization
within the Haskell Foundation that is building tools and processes
to aid the entire Haskell ecosystem in assessing and responding to
security risks.  In particular, we maintain a [database][repo] of
security advisories that can serve as a data source for security
tooling.

This report details the SRT activities from July to December 2023.
The SRT is supposed to report quarterly, but we missed giving a Q3
report.  We'll try not to let that happen again.

The SRT is:

- Casey Mattingly
- Fraser Tweedale
- Gautier Di Folco
- Mihai Maruseac
- Tristan de Cacqueray


## How to contact the SRT

For assistance in coordinating a security response to newly
discovered, high impact vulnerabilities, contact
`security-advisories@haskell.org`.  Due to limited resources, we can
only coordinate embargoed disclosures for high impact
vulnerabilities affecting current versions of core Haskell tools and
libraries.

You can submit lower-impact or historical vulnerabilities to the
advisory database via a pull request to our [GitHub
repository][repo].

You can also contact the SRT about non-advisory/security-response
topics.  We prefer public communication where possible.  In most
cases, [GitHub issues][gh-new-issue] are an appropriate forum.  But
the mail address is there if no other appropriate channel exists.


## Advisory database

3 contemporary advisories were added to the database during the
reporting period.

9 historical advisories were added to the database during the
reporting period.  Most of these were found by searching established
CVE and vulnerability databases.  It is important to record
historical vulnerabilities so if you know of any, please submit a
pull request or let the SRT know!


## Coordinated disclosure and downstream stakeholders

[`HSEC-2023-0015`][HSEC-2023-0015] was a medium severity theoretical
attack against `cabal-install`.  This was the SRT's first embargoed
vulnerability where we coordinated disclosure with downstream
distributions.  Unfortunately, we missed an important
distributor—GHCup—causing some stress and embarrassment.  We have
added GHCup to our list of distributors.

The SRT maintains a public [list of downstream
stakeholders][stakeholders], as well as some private stakeholder
addresses.  If you want to add a contact point to either the public
or private list, please let us know.


## osv.dev integration

The OSV project aggregates the security advisories for many open
source languages, ecosystems and projects.  In addition to exporting
our advisory content in the OSV data format and requesting osv.dev
to import our advisories, we delivered [an enhancement][pr-osv] to
OSV itself to enable it to understand Haskell package and GHC
version numbers.

As a result of these efforts, all HSEC security advisories are now
published in OSV (see https://osv.dev/list?ecosystem=Hackage).


## Tooling development

- HSEC IDs can now be reserved (e.g. allocate an ID for an embargoed
  vulnerability).

- Gautier implemented the `hsec-tools query` subcommand for querying
  whether a package/version is affected by any advisories.

- Gautier extracted core advisory data types and functions as the
  `hsec-core` library, separating it from the `hsec-tools`
  executable.  We have not yet published it on Hackage, but intend
  to do so.

- Gautier extracted the OSV modules to the `osv` library.  We have
  not yet published it on Hackage, but will certainly do so,
  probably in Q1.

- Tristan implemented a library for CVSS parsing, printing and
  calculations.  As with the others, it is not yet on Hackage, but
  watch this space.

- Tristian implemented library support for mapping CWE numbers and
  descriptions.

- `hsec-tools` CLI help has been improved.

- Eric Mertens (non-SRT contributor) migrated us to a richer TOML
  library which includes generation, enabling us to print as well as
  parse advisories.

- The `generate-index` subcommand generates an HTML index of the
  advisories.  For now it is fairly basic.  We plan to publish this
  index somewhere prominent, e.g.  within the `haskell.org` site,
  and are currently working through the details.


## Future work

We plan to develop GitHub tooling (e.g. webhooks or GitHub app) to
improve the contributor (and maintainer) experience.  For example,
we can expand CVSS and CWE definitions, or provide contextual help
to fill out missing fields in the advisory TOML.

As mentioned above, we have several libraries awaiting publication
on Hackage.  We hope that CVSS, CWE and OSV libraries will be
broadly useful, and the `hsec-core` library will be useful in
developing enhanced security tooling for Haskell development.

The SRT is eager to provide whatever is needed on our side to
support the development of "downstream" tooling.  In particular, we
would love to see integration with package repositories (Hackage,
Flora), and tooling for analysing dependency contraints, build
plans, freeze files, GHC package databases or similar artifacts to
detect and advise users of vulnerable packages in (potential) use.
See also David Christiansen's [call to action][].

Development of downstream tooling is not in the SRT's current scope
of work, but it *is* in our charter to do whatever we can to support
such development.  This could include things like advisory schema
changes, enhancing our libraries, or consultation and co-design.  If
you want to contribute to these important efforts, and especially if
you are a developer/maintainer of an obvious integration target, the
SRT would love to hear from you and support you.


[repo]: https://github.com/haskell/security-advisories
[gh-new-issue]: https://github.com/haskell/security-advisories/issues/new/choose
[pr-osv]: https://github.com/google/osv.dev/pull/1463
[HSEC-2023-0015]: https://osv.dev/vulnerability/HSEC-2023-0015
[stakeholders]: https://github.com/haskell/security-advisories/blob/main/PROCESS.md#downstream-stakeholders
[call to action]: https://discourse.haskell.org/t/would-you-like-to-write-a-security-advisory-analyzer/7638
