# Haskell Security Advisory DB

The Haskell Security Advisory Database is a repository of security advisories filed
against packages published via Hackage.

This database is still new. If you develop a tool or database that uses its information,
please open a PR listing it here.

## Reporting Vulnerabilities

To report a new vulnerability, open a pull request using the template below.
See [CONTRIBUTING.md] for more information.

## Advisory Format

See [EXAMPLE_ADVISORY.md] for a template.

Advisories are formatted in [Markdown] with machine-readable [TOML] "front matter".

Below is the schema of the [TOML] "front matter" section of an advisory. If you base
your advisory on this explanation rather than on [EXAMPLE_ADVISORY.md], please remember
to remove the explanatory comments for each field.

```toml

[advisory]
# Identifier for the advisory (mandatory). Will be assigned a "HSEC-YYYY-NNNN"
# identifier e.g. HSEC-2022-0001. Please use "HSEC-0000-0000" in PRs.
id = "HSEC-0000-0000"

# Publication date of the advisory as an RFC 3339 date.
# DO NOT INCLUDE THIS in files committed to Git.
# It will be derived from the Git commit history.
date = 2021-01-31

# Optional: Classification of the advisory with respect to the Common Weakness Enumeration.
cwe = [820]

# Optional: Classification of the advisory with respect to the Common Attack Pattern Enumerations and Classifications.
capec = [123]

# Arbitrary keywords.  We recommend to include keywords relating
# to the protocols, data formats or services pertaining to the
# affected package (e.g. "json", "tls", "aws").  You can also
# include keywords describing the vulnerability or impact (e.g.
# "dos", "sqli" "csrf").  Just think, "what keywords would I use
# if I was searching for issues affecting this package, or a
# particular class of vulnerabilities?"
keywords = ["ssl", "mitm"]

# Vulnerability aliases, e.g. CVE IDs (optional but recommended)
# Request a CVE for your HSec vulns: https://iwantacve.org/
#aliases = ["CVE-2018-XXXX"]

# Related vulnerabilities (optional)
# e.g. CVE for a C library wrapped by a Haskell library
#related = ["CVE-2018-YYYY", "CVE-2018-ZZZZ"]

# References to articles, issues/PRs, etc.  Recognised types:
# ADVISORY, ARTICLE, DETECTION, DISCUSSION, REPORT,
# FIX, INTRODUCED, PACKAGE, EVIDENCE, WEB
[[references]]
type = "REPORT"
url = "https://github.com/username/package/issues/123"
[[references]]
type = "FIX"
url = "https://github.com/username/package/pull/139"

# Affected package(s).  You can declare one or more packages.
# Sub-fields are `package`, `cvss`, `arch`, `os`, `declarations`
# and the `versions` table.
[[affected]]

# Mandatory: name of the affected package on Hackage
package = "acme-broken"

# Mandatory: a Common Vulnerability Scoring System score. More information
# can be found on the CVSS website, https://www.first.org/cvss/.
# The committee will assist advisory authors in constructing an appropriate CVSS if necessary.
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Optional: CPU architectures impacted by this vulnerability
# Only use this if the vulnerability is specific to a particular CPU architecture,
# e.g. the vulnerability is in x86 assembly.
# For a list of CPU architecture strings, see the documentation for System.Info.arch:
# <https://hackage.haskell.org/package/base-4.16.1.0/docs/System-Info.html>
#arch = ["x86", "x86_64"]

# Optional: Operating systems impacted by this vulnerability
# Only use this if the vulnerable is specific to a particular OS, e.g. it was
# located in a binding to a Windows-specific API.
# For a list of OS strings, see the documentation for System.Info.os:
# <https://hackage.haskell.org/package/base-4.16.1.0/docs/System-Info.html>
#os = ["mingw32"]

# Optional: Table of canonical paths to vulnerable declarations in the package
# that describes which versions impacted by this advisory used that particular
# name (e.g. if an affected function or datatype was renamed between versions).
# The path syntax is the module import path, without any type signatures or
# additional information, followed by the affected versions.
#declarations = { "Acme.Broken.function" = ">= 1.1.0 && < 1.2.0", "Acme.Broken.renamedFunction" = ">= 1.2.0 && < 1.2.0.5"}

# Versions affected by the vulnerability.
#
# The `fixed` field is optional.  You can specify multiple ranges
# (for example, if the issue was introduced in multiple releases
# series).  In the case of multiple ranges, use `fixed` to "close"
# a range, even when the release series does not actually have a
# fix.  For example, if an issue was introduced in 1.0.8 and 1.1.2
# (but 1.1 is unaffected), and a fix has not been released for the
# 1.0.x series, specify:
[[affected.versions]]
introduced = "1.0.8"
fixed = "1.1"
[[affected.versions]]
introduced = "1.1.2"
```

The above [TOML] "front matter" is followed by the long description in [Markdown] format.

## Current Members

- [Tristan de Cacqueray](mailto:tristan.cacqueray@gmail.com)
- [Gautier Di Folco](mailto:gautier.difolco@gmail.com)
- [Mihai Maruseac](mailto:mihai.maruseac@gmail.com)
- [Casey Mattingly](mailto:case@capsulecorp.org)
- [David Thrane Christiansen](mailto:david@haskell.foundation)
- [Fraser Tweedale](mailto:frase@frase.id.au)

## Processes

Please see [Contributing](./CONTRIBUTING.md) for details.

## Acknowledgments

The process and documentation in this repository are based off the work of the [RustSec](https://rustsec.org/) team.

## License

All security advisory content in this repository is placed in the public domain, including metadata, descriptions, and example code.

[![Public Domain](http://i.creativecommons.org/p/zero/1.0/88x31.png)](https://github.com/haskell/security-advisories/LICENSE.txt)

The contents of the `code` subdirectory, which contains tools and libraries for working with the advisory data format in Haskell, are licensed under a three-clause BSD license. Please refer to [that subdirectory's LICENSE file](code/LICENSE.txt) for details.

[EXAMPLE_ADVISORY.md]: https://github.com/haskell/security-advisories/blob/main/EXAMPLE_ADVISORY.md
[Markdown]: https://www.markdownguide.org/
[TOML]: https://github.com/toml-lang/toml
[CONTRIBUTING.md]: https://github.com/haskell/security-advisories/blob/main/CONTRIBUTING.md
[RustSec]: https://github.com/rustsec/advisory-db
