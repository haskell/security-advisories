# Reporting Vulnerabilities

To add an advisory to the database, open a [Pull Request] against
[this](https://github.com/haskell/security-advisories/pulls) repository containing the new advisory:

## Required Steps

1. Create a file named `HSEC-0000-0000.md` in the `advisories/hackage/<your-package-name>`
   subdirectory of the repository (you may need to create it if it doesn't exist)
2. Copy and paste the [TOML advisory template] from the README.md file in this repo.
   Delete the comments and additional whitespace, and fill it out with the
   details of the advisory. Surround the TOML data with <code>\```toml</code> and <code>\```</code> markers.
3. Write a human-readable Markdown description in the same file, after the <code>\```</code> marker and a newline. Use [this example advisory][example] as a reference.
4. Open a [Pull Request]. After being reviewed your advisory will be assigned
   a `HSEC-*` advisory identifier and be published to the database.

### Optional Steps

Feel free to do either or both of these as you see fit (we recommend you do both):

4. Deprecate the affected versions of the package on Hackage.
5. Request a CVE for your vulnerability. See for details:
   <https://cve.mitre.org/cve/request_id.html> and <https://cveform.mitre.org> .
   Alternatively, you can create a GitHub Security Advisory (GHSA) and let them request
   a CVE for you. In this case, you can add the GHSA ID to the advisory via the
   `aliases` field.

### License

All published security advisories are released under [CC0](https://creativecommons.org/share-your-work/public-domain/cc0/). By contributing an advisory, you agree to release the entire content of the advisory (including machine-readable metadata, example code, and textual descriptions) under CC0.

## Criteria

This is a database of security vulnerabilities. The following are
examples of qualifying vulnerabilities:

* Code Execution (i.e. RCE)
* Denial of service opportunities
* Memory Corruption
* Privilege Escalation (either at OS level or inside of an app/library)
* File Disclosure / Directory Traversal
* Web Security (e.g. XSS, CSRF)
* Format Injection, e.g. shell escaping, SQL injection (and also XSS)
* Cryptography Failure (e.g. confidentiality breakage, integrity breakage, key leakage)
* Covert Channels (e.g. Spectre, Meltdown)

## FAQ

**Q: Do I need to be the maintainer of a package to file an advisory?**

A:  No, anyone can file an advisory against any package. The legitimacy of
    vulnerabilities will be determined prior to merging. If a vulnerability
    turns out to be incorrect then it will be corrected or removed from the
    database.

**Q: Can I file an advisory without creating a pull request?**

A: Yes, instead of creating a full advisory yourself you can also
   [open an issue on the security-advisories repo](https://github.com/haskell/security-advisories/issues)
   or email information about the vulnerability to
   [security-advisories@haskell.org](mailto:security-advisories@haskell.org).

**Q: Does this project have a GPG key or other means of handling embargoed vulnerabilities?**

A: We do not presently handle embargoed vulnerabilities. Please ensure embargoes
   have been lifted and details have been disclosed to the public prior to filing
   them here.

[Pull Request]: https://github.com/haskell/security-advisories/pulls
[TOML advisory template]: https://github.com/haskell/security-advisories/blob/main/README.md#advisory-format
[example]: https://raw.githubusercontent.com/haskell/security-advisories/main/EXAMPLE_ADVISORY.md
