## Unreleased

* Move to `lucid2`
* Remove compilation warnings by introducing `RepresentableAffectedApi` and renaming variables
* Update GHC support to GHC 9.6.7, 9.8.4, 9.10.3, 9.12.4, and 9.14.1
* Relax dependency bounds for `Cabal-syntax`, `commonmark`, `commonmark-pandoc`, `containers`, `data-default`, `pandoc`, `template-haskell`, `time`, and `optparse-applicative`

## 0.5.0.0

* Add `HsecEcosystemSpecific` with `affected_api` in OSV exports
* Add TOML parsing/rendering for `api` key in affected sections
* Add HTML rendering for affected APIs
* Update `hsec-core` to `0.5.0.0`

## 0.4.0.0

* Update `hsec-core` to `0.4.0.0`

## 0.3.0.2

* Update `cvss` dependency bounds

## 0.3.0.1

* Bump `hsec-core` `0.3.0.0`

## 0.3.0.0

* Move `isVersionAffectedBy` and `isVersionRangeAffectedBy` to `Security.Advisories.Core` (`hsec-core`)
* Add support for GHC component in `query is-affected`
* Add `model.database_specific.{repository,osvs,home}` and `model.affected.database_specific.{osv,human_link}` in OSV exports
* Adapt to new security-advisories layout
* Drop `Security.Advisories.Filesystem.parseComponentIdentifier`
* Drop `Security.Advisories.Parse.OutOfBandAttributes.oobComponentIdentifier`
* Drop `Security.Advisories.Parse.OOBError.PathHasNoComponentIdentifier`

## 0.2.0.2

* Update `tasty` dependency bounds
* Update `osv` dependency bounds

## 0.2.0.1

- Rework HTML/Atom generation, use `atom-conduit` instead of `feed`

## 0.1.1.0

- Redesign index
