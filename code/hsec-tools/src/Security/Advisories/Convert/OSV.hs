{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Security.Advisories.Convert.OSV (
    convert,
    convertWithLinks,
    DbLinks (..),
    AffectedLinks (..),
    haskellLinks,
)
where

import Data.Aeson
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
mkPackage ecosystem =
    OSV.Package
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

convertWithLinks :: DbLinks -> Advisory -> OSV.Model DbLinks AffectedLinks Void Void
convertWithLinks links adv =
    OSV.Model
        { OSV.modelDatabaseSpecific = Just links
        , OSV.modelAffected = mkAffectedWithLinks links (advisoryId adv) <$> advisoryAffected adv
        , ..
        }
  where
    OSV.Model{..} = convert adv

data DbLinks = DbLinks
    { dbLinksRepository :: T.Text
    , dbLinksOSVs :: T.Text
    , dbLinksHome :: T.Text
    }

instance ToJSON DbLinks where
    toJSON DbLinks{..} =
        object
            [ "repository" .= dbLinksRepository
            , "osvs" .= dbLinksOSVs
            , "home" .= dbLinksHome
            ]

haskellLinks :: DbLinks
haskellLinks =
    DbLinks
        { dbLinksRepository = "https://github.com/haskell/security-advisories"
        , dbLinksOSVs = "https://raw.githubusercontent.com/haskell/security-advisories/refs/heads/generated/osv-export"
        , dbLinksHome = "https://github.com/haskell/security-advisories"
        }

data AffectedLinks = AffectedLinks
    { affectedLinksOSV :: T.Text
    , affectedLinksHumanLink :: T.Text
    }

instance ToJSON AffectedLinks where
    toJSON AffectedLinks{..} =
        object
            [ "osv" .= affectedLinksOSV
            , "human_link" .= affectedLinksHumanLink
            ]

mkAffectedWithLinks :: DbLinks -> HsecId -> Affected -> OSV.Affected AffectedLinks Void Void
mkAffectedWithLinks links hsecId aff =
    OSV.Affected
        { OSV.affectedDatabaseSpecific =
            Just
                AffectedLinks
                    { affectedLinksOSV = stripSlash (dbLinksOSVs links) <> "/" <> T.pack (show $ hsecIdYear hsecId) <> "/" <> T.pack (printHsecId hsecId) <> ".json"
                    , affectedLinksHumanLink = stripSlash (dbLinksHome links) <> "/tree/main/advisories/published/" <> T.pack (show $ hsecIdYear hsecId) <> "/" <> T.pack (show $ hsecIdSerial hsecId) <> ".md"
                    }
        , ..
        }
  where
    OSV.Affected{..} = mkAffected aff
    stripSlash = T.dropWhileEnd (== '/')
