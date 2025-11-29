```toml

[advisory]
id = "HSEC-0000-0000"
cwe = []
keywords = ["example", "freeform", "keywords"]
aliases = ["CVE-2022-XXXX"]
related = ["CVE-2022-YYYY", "CVE-2022-ZZZZ"]

[[affected]]
repository-url = "https//hackage.example.org/"
repository-name = "example"
package = "package-name"
cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

[[affected.versions]]
introduced = "1.0.8"
fixed = "1.1"
[[affected.versions]]
introduced = "1.1.2"

[[references]]
type = "ARTICLE"
url = "https://example.com"
```

# Advisory Template - Title Goes Here

This is an example template.

 * Markdown
 * TOML "front matter".

 > Acme Broken.
