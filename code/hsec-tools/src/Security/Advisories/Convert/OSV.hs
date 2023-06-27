{-# LANGUAGE OverloadedStrings #-}

module Security.Advisories.Convert.OSV
  ( convert
  )
  where

import qualified Data.Text as T
import Data.Time (zonedTimeToUTC)
import Data.Void

import Security.Advisories
import qualified Security.OSV as OSV

convert :: Advisory -> OSV.Model Void Void Void Void
convert adv =
  ( OSV.newModel'
    (advisoryId adv)
    (zonedTimeToUTC $ advisoryModified adv)
  )
  { OSV.modelPublished = Just $ zonedTimeToUTC (advisoryPublished adv)
  , OSV.modelAliases = advisoryAliases adv
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
    , OSV.affectedSeverity = mkSeverity (affectedCVSS aff)
    , OSV.affectedEcosystemSpecific = Nothing
    , OSV.affectedDatabaseSpecific = Nothing
    }

mkPackage :: T.Text -> OSV.Package
mkPackage name = OSV.Package
  { OSV.packageName = name
  , OSV.packageEcosystem = "Hackage"
  , OSV.packagePurl = Nothing
  }

-- NOTE: This is unpleasant.  But we will eventually switch to a
-- proper CVSS type and the unpleasantness will go away.
--
mkSeverity :: T.Text -> [OSV.Severity]
mkSeverity s = case T.take 6 s of
  "CVSS:2" -> [OSV.SeverityCvss2 s]
  "CVSS:3" -> [OSV.SeverityCvss3 s]
  _        -> []  -- unexpected; don't include severity

mkRange :: [AffectedVersionRange] -> OSV.Range Void
mkRange ranges = OSV.RangeEcosystem (foldMap mkEvs ranges) Nothing
  where
  mkEvs range =
    OSV.EventIntroduced (affectedVersionRangeIntroduced range)
    : maybe [] (pure . OSV.EventFixed) (affectedVersionRangeFixed range)
