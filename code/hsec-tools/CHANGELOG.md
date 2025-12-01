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
