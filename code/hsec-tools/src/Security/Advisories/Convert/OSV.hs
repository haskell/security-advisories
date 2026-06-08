{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Security.Advisories.Convert.OSV
  ( convert,
    convertWithLinks,
    DbLinks (..),
    AffectedLinks (..),
    HsecEcosystemSpecific (..),
    haskellLinks,
  )
where

import Data.Aeson
import qualified Data.Text as T
import Data.Void
import Distribution.Pretty (prettyShow)
import Security.Advisories
import Security.Advisories.Core.OsvId (printOsvId)
import qualified Security.OSV as OSV

convert :: Advisory -> OSV.Model Void Void HsecEcosystemSpecific Void
convert adv =
  ( OSV.newModel'
      (T.pack . printHsecId $ advisoryId adv)
      (advisoryModified adv)
  )
    { OSV.modelPublished = Just $ advisoryPublished adv,
      OSV.modelAliases = map printOsvId (advisoryAliases adv),
      OSV.modelRelated = map printOsvId (advisoryRelated adv),
      OSV.modelSummary = Just $ advisorySummary adv,
      OSV.modelDetails = Just $ advisoryDetails adv,
      OSV.modelReferences = advisoryReferences adv,
      OSV.modelAffected = fmap mkAffected (advisoryAffected adv)
    }

mkAffected :: Affected -> OSV.Affected Void HsecEcosystemSpecific Void
mkAffected aff =
  OSV.Affected
    { OSV.affectedPackage = mkPackage (affectedComponentIdentifier aff),
      OSV.affectedRanges = pure $ mkRange (affectedVersions aff),
      OSV.affectedSeverity = [OSV.Severity (affectedCVSS aff)],
      OSV.affectedEcosystemSpecific =
        if null (affectedApi aff)
          then Nothing
          else Just (HsecEcosystemSpecific (affectedApi aff)),
      OSV.affectedDatabaseSpecific = Nothing
    }

mkPackage :: ComponentIdentifier -> OSV.Package
mkPackage ecosystem =
  OSV.Package
    { OSV.packageName = packageName,
      OSV.packageEcosystem = ecosystemName,
      OSV.packagePurl = Nothing
    }
  where
    (ecosystemName, packageName) = case ecosystem of
      Repository _ repoName pkg
        | ecosystem == hackage pkg -> ("Hackage", T.pack $ unPackageName pkg)
        | otherwise -> (unRepositoryName repoName, T.pack $ unPackageName pkg)
      GHC c -> ("GHC", ghcComponentToText c)

mkRange :: [AffectedVersionRange] -> OSV.Range Void
mkRange ranges =
  OSV.RangeEcosystem (foldMap mkEvs ranges) Nothing
  where
    mkEvs :: AffectedVersionRange -> [OSV.Event T.Text]
    mkEvs range =
      OSV.EventIntroduced (T.pack $ prettyShow $ affectedVersionRangeIntroduced range)
        : maybe [] (pure . OSV.EventFixed . T.pack . prettyShow) (affectedVersionRangeFixed range)

convertWithLinks :: DbLinks -> Advisory -> OSV.Model DbLinks AffectedLinks HsecEcosystemSpecific Void
convertWithLinks links adv =
  OSV.Model
    { OSV.modelDatabaseSpecific = Just links,
      OSV.modelAffected = mkAffectedWithLinks links (advisoryId adv) <$> advisoryAffected adv,
      ..
    }
  where
    OSV.Model {..} = convert adv

data DbLinks = DbLinks
  { dbLinksRepository :: T.Text,
    dbLinksOSVs :: T.Text,
    dbLinksHome :: T.Text
  }

instance ToJSON DbLinks where
  toJSON DbLinks {..} =
    object
      [ "repository" .= dbLinksRepository,
        "osvs" .= dbLinksOSVs,
        "home" .= dbLinksHome
      ]

instance FromJSON DbLinks where
  parseJSON = withObject "DbLinks" $ \o -> do
    dbLinksRepository <- o .: "repository"
    dbLinksOSVs <- o .: "osvs"
    dbLinksHome <- o .: "home"
    pure DbLinks {..}

haskellLinks :: DbLinks
haskellLinks =
  DbLinks
    { dbLinksRepository = "https://github.com/haskell/security-advisories",
      dbLinksOSVs = "https://raw.githubusercontent.com/haskell/security-advisories/refs/heads/generated/osv-export",
      dbLinksHome = "https://github.com/haskell/security-advisories"
    }

data AffectedLinks = AffectedLinks
  { affectedLinksOSV :: T.Text,
    affectedLinksHumanLink :: T.Text
  }

instance ToJSON AffectedLinks where
  toJSON AffectedLinks {..} =
    object
      [ "osv" .= affectedLinksOSV,
        "human_link" .= affectedLinksHumanLink
      ]

instance FromJSON AffectedLinks where
  parseJSON = withObject "AffectedLinks" $ \o -> do
    affectedLinksOSV <- o .: "osv"
    affectedLinksHumanLink <- o .: "human_link"
    pure AffectedLinks {..}

newtype HsecEcosystemSpecific = HsecEcosystemSpecific
  { hsecEcosystemAffectedApi :: [AffectedApi]
  }
  deriving stock (Eq, Show)

instance ToJSON HsecEcosystemSpecific where
  toJSON (HsecEcosystemSpecific apis) =
    object
      [ "affected_api" .= apis
      ]

instance FromJSON HsecEcosystemSpecific where
  parseJSON = withObject "HsecEcosystemSpecific" $ \o -> do
    hsecEcosystemAffectedApi <- o .: "affected_api"
    pure HsecEcosystemSpecific {..}

instance ToJSON AffectedApi where
  toJSON AffectedApi {..} =
    object
      [ "module" .= affectedApiModule,
        "name" .= affectedApiName
      ]

instance FromJSON AffectedApi where
  parseJSON = withObject "AffectedApi" $ \o -> do
    affectedApiModule <- o .: "module"
    affectedApiName <- o .: "name"
    pure AffectedApi {..}

mkAffectedWithLinks :: DbLinks -> HsecId -> Affected -> OSV.Affected AffectedLinks HsecEcosystemSpecific Void
mkAffectedWithLinks links hsecId aff =
  OSV.Affected
    { OSV.affectedDatabaseSpecific =
        Just
          AffectedLinks
            { affectedLinksOSV = osvLink,
              affectedLinksHumanLink = humanLink
            },
      ..
    }
  where
    OSV.Affected {..} = mkAffected aff
    stripSlash = T.dropWhileEnd (== '/')
    osvLink =
      stripSlash (dbLinksOSVs links)
        <> "/"
        <> T.pack (show $ hsecIdYear hsecId)
        <> "/"
        <> T.pack (printHsecId hsecId)
        <> ".json"
    humanLink =
      stripSlash (dbLinksHome links)
        <> "/tree/main/advisories/published/"
        <> T.pack (show $ hsecIdYear hsecId)
        <> "/"
        <> T.pack (printHsecId hsecId)
        <> ".md"
