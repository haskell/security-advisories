```toml

[advisory]
id = "HSEC-0000-0000"
cwe = []

# Arbitrary keywords.  We recommend to include keywords relating
# to the protocols, data formats or services pertaining to the
# affected package (e.g. "json", "tls", "aws").  You can also
# include keywords describing the vulnerability or impact (e.g.
# "dos", "sqli" "csrf").  Just think, "what keywords would I use
# if I was searching for issues affecting this package, or a
# particular class of vulnerabilities?"
keywords = ["example", "freeform", "keywords"]

# Corresponding and related advisory IDs.  You could include
# CVE, GHSA or other well known databases, as well as other
# HSEC IDs in the `related` field.
aliases = ["CVE-2022-XXXX"]
related = ["CVE-2022-YYYY", "CVE-2022-ZZZZ"]

# You can declare multiple affected packages
[[affected]]
package = "package-name"
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# arch = ["x86", "x86_64"]
# os = ["mingw32"]
# declarations = { "Acme.Broken.function" = ">= 1.1.0 && < 1.2.0", "Acme.Broken.renamedFunction" = ">= 1.2.0 && < 1.2.0.5"}

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

# References to articles, issues/PRs, etc.  Recognised types:
# ADVISORY, ARTICLE, DETECTION, DISCUSSION, REPORT,
# FIX, INTRODUCED, PACKAGE, EVIDENCE, WEB
[[references]]
type = "ARTICLE"
url = "https://example.com"
```

# Advisory Template - Title Goes Here

This is an example template for an advisory. Please copy this to packages/<package-name> and rename it to HSEC-0000-0000.md.

In this section of the advisory you can write an extended description of the vulnerability.

 * Markdown formatted
 * TOML "front matter". See README.md for schema.
 * Please include as much detail as you'd like.

A well structured advisory will include information like:

 > Acme Broken implements safe internal mutation using `unsafePerformIO`. However, in a multithreaded context, an attacker can cause a service to return the wrong answer by forcing an interleaving of writes that violates internal invariants. The flaw was corrected by replacing uses of `IORef` with `MVar` in commit abc123.
