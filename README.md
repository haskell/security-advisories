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

# Name of the affected package on Hackage (mandatory)
package = "acme-broken"

# Disclosure date of the advisory as an RFC 3339 date (mandatory)
date = 2021-01-31

# URL to a long-form description of this issue, e.g. a GitHub issue/PR,
# a change log entry, or a blogpost announcing the release (optional)
url = "https://github.com/username/package/issues/123"

# Optional: Classification of the advisory with respect to the Common Weakness Enumeration.
cwe = [820]

# Mandatory: a Common Vulnerability Scoring System score. More information
# can be found on the CVSS website, https://www.first.org/cvss/.
# The committee will assist advisory authors in constructing an appropriate CVSS if necessary.
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# Freeform keywords which describe this vulnerability (optional)
keywords = ["ssl", "mitm"]

# Vulnerability aliases, e.g. CVE IDs (optional but recommended)
# Request a CVE for your HSec vulns: https://iwantacve.org/
#aliases = ["CVE-2018-XXXX"]

# Related vulnerabilities (optional)
# e.g. CVE for a C library wrapped by a Haskell library
#related = ["CVE-2018-YYYY", "CVE-2018-ZZZZ"]

# Optional: metadata which narrows the scope of what this advisory affects
[affected]
# CPU architectures impacted by this vulnerability (optional).
# Only use this if the vulnerability is specific to a particular CPU architecture,
# e.g. the vulnerability is in x86 assembly.
# For a list of CPU architecture strings, see the documentation for System.Info.arch:
# <https://hackage.haskell.org/package/base-4.16.1.0/docs/System-Info.html>
#arch = ["x86", "x86_64"]

# Operating systems impacted by this vulnerability (optional)
# Only use this if the vulnerable is specific to a particular OS, e.g. it was
# located in a binding to a Windows-specific API.
# For a list of OS strings, see the documentation for System.Info.os:
# <https://hackage.haskell.org/package/base-4.16.1.0/docs/System-Info.html>
#os = ["mingw32"]

# Table of canonical paths to vulnerable declarations in the package (optional)
# that describes which versions impacted by this advisory used that particular
# name (e.g. if an affected function or datatype was renamed between versions). 
# The path syntax is the module import path, without any type signatures or
# additional information, followed by the affected versions.
#declarations = { "Acme.Broken.function" = ">= 1.1.0 && < 1.2.0", "Acme.Broken.renamedFunction" = ">= 1.2.0 && < 1.2.0.5"}

# Versions affected by the vulnerability
[versions]
affected = ">= 1.1.0 && < 1.2.0.5"
```

The above [TOML] "front matter" is followed by the long description in [Markdown] format.

## Current Members

- [Tristan de Cacqueray](tristan.cacqueray@gmail.com)
- [Gautier di Folco](mailto:gautier.difolco@gmail.com)
- [Mihai Maruseac](mailto:mihai.maruseac@gmail.com)
- [Casey Mattingly](mailto:case@capsulecorp.org)
- [David Christiansen Thrane](david@haskell.foundation)
- [Fraser Tweedale](frase@frase.id.au)

## Processes

Haskell Security Advisory Database is a for security vulnerabilities. Here are some examples:

- RCE
- Memory Corruption
- Privilege Escalation
- Cryptography issues
- Various injection issues (SQL, Command, etc.)
- Use of broken algorithms
- Use of obsolete libraries

When in doubt, submit a PR. As a group, we will review and decide to promote the vulnerability in the Database.
If there are issues regarding confidentiality and you would like to disclose an issue in a more private setting, please use the [Mailing List](mailto:security-advisories@haskell.org)

As a group, we will review the submission and collectively decide whether or not we'll issue an advisory.

## Acknowledgments

The process and documentation in this repository are based off the work of the [RustSec][RustSec] team.

## License

All security advisory content in this repository is placed in the public domain, including metadata, descriptions, and example code.

[![Public Domain](http://i.creativecommons.org/p/zero/1.0/88x31.png)](https://github.com/haskell/security-advisories/LICENSE.txt)

The contents of the `code` subdirectory, which contains tools and libraries for working with the advisory data format in Haskell, are licensed under a three-clause BSD license. Please refer to [that subdirectory's LICENSE file](code/LICENSE.txt) for details.

[EXAMPLE_ADVISORY.md]: https://github.com/haskell/security-advisories/blob/main/EXAMPLE_ADVISORY.md
[Markdown]: https://www.markdownguide.org/
[TOML]: https://github.com/toml-lang/toml
[CONTRIBUTING.md]: https://github.com/haskell/security-advisories/blob/main/CONTRIBUTING.md
[RustSec]: https://github.com/rustsec/advisory-db
