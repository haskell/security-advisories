{-# LANGUAGE OverloadedStrings #-}

module Security.Advisories.Convert.OSV
  ( convert
  )
  where

import qualified Data.Text as T
import Data.Time (zonedTimeToUTC)
import Data.Void
import Distribution.Pretty (prettyShow)

import Security.Advisories
import qualified Security.OSV as OSV

convert :: Advisory -> OSV.Model Void Void Void Void
convert adv =
  ( OSV.newModel'
    (T.pack . printHsecId $ advisoryId adv)
    (zonedTimeToUTC $ advisoryModified adv)
  )
  { OSV.modelPublished = Just $ zonedTimeToUTC (advisoryPublished adv)
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
    { OSV.affectedPackage = mkPackage (affectedPackage aff)
    , OSV.affectedRanges = pure $ mkRange (affectedVersions aff)
    , OSV.affectedSeverity = [OSV.Severity (affectedCVSS aff)]
    , OSV.affectedEcosystemSpecific = Nothing
    , OSV.affectedDatabaseSpecific = Nothing
    }

mkPackage :: T.Text -> OSV.Package
mkPackage name = OSV.Package
  { OSV.packageName = name
  , OSV.packageEcosystem = "Hackage"
  , OSV.packagePurl = Nothing
  }

mkRange :: [AffectedVersionRange] -> OSV.Range Void
mkRange ranges =
    OSV.RangeEcosystem (foldMap mkEvs ranges) Nothing
  where
    mkEvs :: AffectedVersionRange -> [OSV.Event T.Text]
    mkEvs range =
      OSV.EventIntroduced (T.pack $ prettyShow $ affectedVersionRangeIntroduced range)
      : maybe [] (pure . OSV.EventFixed . T.pack . prettyShow) (affectedVersionRangeFixed range)
