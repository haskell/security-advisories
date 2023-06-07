```toml

[advisory]
id = "HSEC-0000-0000"
package = "package-name"
date = 2021-01-31
url = "https://example.com"
cwe = []
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
keywords = ["example", "freeform", "keywords"]
# aliases = ["CVE-2022-XXXX"]
# related = ["CVE-2022-YYYY", "CVE-2022-ZZZZ"]

[affected]
# arch = ["x86", "x86_64"]
# os = ["mingw32"]
# declarations = { "Acme.Broken.function" = ">= 1.1.0 && < 1.2.0", "Acme.Broken.renamedFunction" = ">= 1.2.0 && < 1.2.0.5"}

# Versions affected by the vulnerability. Multiple range should not overlap.
[[versions]]
introduced = "1.1.0"
fixed = "1.2.0.5"
```

# Advisory Template - Title Goes Here

This is an example template for an advisory. Please copy this to packages/<package-name> and rename it to HSEC-0000-0000.md.

In this section of the advisory you can write an extended description of the vulnerability.

 * Markdown formatted
 * TOML "front matter". See README.md for schema.
 * Please include as much detail as you'd like.

A well structured advisory will include information like:

 > Acme Broken implements safe internal mutation using `unsafePerformIO`. However, in a multithreaded context, an attacker can cause a service to return the wrong answer by forcing an interleaving of writes that violates internal invariants. The flaw was corrected by replacing uses of `IORef` with `MVar` in commit abc123.
