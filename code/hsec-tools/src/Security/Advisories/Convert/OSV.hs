{-# LANGUAGE OverloadedStrings #-}

module Security.Advisories.Convert.OSV
  ( convert
  )
  where

import qualified Data.Text as T
import Data.Void
import Distribution.Pretty (prettyShow)

import Security.Advisories
import qualified Security.OSV as OSV

convert :: Advisory -> OSV.Model Void Void Void Void
convert adv =
  ( OSV.newModel'
    (T.pack . printHsecId $ advisoryId adv)
    (advisoryModified adv)
  )
  { OSV.modelPublished = Just $ advisoryPublished adv
  , OSV.modelAliases = advisoryAliases adv
  , OSV.modelRelated = advisoryRelated adv
  , OSV.modelSummary = Just $ advisorySummary adv
  , OSV.modelDetails = Just $ advisoryDetails adv
  , OSV.modelReferences = advisoryReferences adv
  , OSV.modelAffected = fmap mkAffected (advisoryAffected adv)
  }

mkAffected :: Affected -> OSV.Affected Void Void Void
mkAffected aff =
  OSV.Affected
    { OSV.affectedPackage = mkPackage (affectedComponentIdentifier aff)
    , OSV.affectedRanges = pure $ mkRange (affectedVersions aff)
    , OSV.affectedSeverity = [OSV.Severity (affectedCVSS aff)]
    , OSV.affectedEcosystemSpecific = Nothing
    , OSV.affectedDatabaseSpecific = Nothing
    }

mkPackage :: ComponentIdentifier -> OSV.Package
mkPackage ecosystem = OSV.Package
  { OSV.packageName = packageName
  , OSV.packageEcosystem = ecosystemName
  , OSV.packagePurl = Nothing
  }
  where
    (ecosystemName, packageName) = case ecosystem of
        Hackage n -> ("Hackage", n)
        GHC c -> ("GHC", ghcComponentToText c)

mkRange :: [AffectedVersionRange] -> OSV.Range Void
mkRange ranges =
    OSV.RangeEcosystem (foldMap mkEvs ranges) Nothing
  where
    mkEvs :: AffectedVersionRange -> [OSV.Event T.Text]
    mkEvs range =
      OSV.EventIntroduced (T.pack $ prettyShow $ affectedVersionRangeIntroduced range)
      : maybe [] (pure . OSV.EventFixed . T.pack . prettyShow) (affectedVersionRangeFixed range)
