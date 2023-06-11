-- | This module contains the OSV datatype and its ToJSON instance.
-- The module was initialized with http://json-to-haskell.chrispenner.ca/
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
module Security.OSV where

import Data.Aeson (ToJSON(..), FromJSON(..), Value(..), (.:), (.=), object)
import Data.Aeson.Types (prependFailure, typeMismatch)
import Data.Text (Text)

data Affected = Affected
  { affectedRanges :: [Ranges]
  , affectedPackage :: Package
  , affectedEcosystemSpecific :: EcosystemSpecific
  , affectedDatabaseSpecific :: DatabaseSpecific
  } deriving (Show, Eq, Ord)

data Affects = Affects
  { affectsOs :: [Value]
  , affectsArch :: [Value]
  , affectsFunctions :: [Value]
  } deriving (Show, Eq, Ord)

data DatabaseSpecific = DatabaseSpecific
  { databaseSpecificCvss :: Maybe Value
  , databaseSpecificCategories :: [Value]
  , databaseSpecificInformational :: Text
  } deriving (Show, Eq, Ord)

data EcosystemSpecific = EcosystemSpecific
  { ecosystemSpecificAffects :: Affects
  } deriving (Show, Eq, Ord)

data Events = Events
  { eventsIntroduced :: Text
  } deriving (Show, Eq, Ord)

data Model = Model
  { modelDetails :: Text
  , modelId :: Text
  , modelSummary :: Text
  , modelRelated :: [Value]
  , modelAffected :: [Affected]
  , modelAliases :: [Value]
  , modelPublished :: Text
  , modelReferences :: [References]
  , modelSeverity :: [Value]
  , modelModified :: Text
  } deriving (Show, Eq, Ord)

data Package = Package
  { packageName :: Text
  , packageEcosystem :: Text
  , packagePurl :: Text
  } deriving (Show, Eq, Ord)

data Ranges = Ranges
  { rangesEvents :: [Events]
  , rangesType :: Text
  } deriving (Show, Eq, Ord)

data References = References
  { referencesType :: Text
  , referencesUrl :: Text
  } deriving (Show, Eq, Ord)

instance ToJSON Affected where
  toJSON Affected{..} = object
    [ "ranges" .= affectedRanges
    , "package" .= affectedPackage
    , "ecosystem_specific" .= affectedEcosystemSpecific
    , "database_specific" .= affectedDatabaseSpecific
    ]

instance ToJSON Affects where
  toJSON Affects{..} = object
    [ "os" .= affectsOs
    , "arch" .= affectsArch
    , "functions" .= affectsFunctions
    ]

instance ToJSON DatabaseSpecific where
  toJSON DatabaseSpecific{..} = object
    [ "cvss" .= databaseSpecificCvss
    , "categories" .= databaseSpecificCategories
    , "informational" .= databaseSpecificInformational
    ]

instance ToJSON EcosystemSpecific where
  toJSON EcosystemSpecific{..} = object
    [ "affects" .= ecosystemSpecificAffects
    ]

instance ToJSON Events where
  toJSON Events{..} = object
    [ "introduced" .= eventsIntroduced
    ]

instance ToJSON Model where
  toJSON Model{..} = object
    [ "details" .= modelDetails
    , "id" .= modelId
    , "summary" .= modelSummary
    , "related" .= modelRelated
    , "affected" .= modelAffected
    , "aliases" .= modelAliases
    , "published" .= modelPublished
    , "references" .= modelReferences
    , "severity" .= modelSeverity
    , "modified" .= modelModified
    ]

instance ToJSON Package where
  toJSON Package{..} = object
    [ "name" .= packageName
    , "ecosystem" .= packageEcosystem
    , "purl" .= packagePurl
    ]

instance ToJSON Ranges where
  toJSON Ranges{..} = object
    [ "events" .= rangesEvents
    , "type" .= rangesType
    ]

instance ToJSON References where
  toJSON References{..} = object
    [ "type" .= referencesType
    , "url" .= referencesUrl
    ]

instance FromJSON Affected where
  parseJSON (Object v) = do
    affectedRanges <- v .: "ranges"
    affectedPackage <- v .: "package"
    affectedEcosystemSpecific <- v .: "ecosystem_specific"
    affectedDatabaseSpecific <- v .: "database_specific"
    pure $ Affected{..}
  parseJSON invalid = do
    prependFailure "parsing Affected failed, "
      (typeMismatch "Object" invalid)

instance FromJSON Affects where
  parseJSON (Object v) = do
    affectsOs <- v .: "os"
    affectsArch <- v .: "arch"
    affectsFunctions <- v .: "functions"
    pure $ Affects{..}
  parseJSON invalid = do
    prependFailure "parsing Affects failed, "
      (typeMismatch "Object" invalid)

instance FromJSON DatabaseSpecific where
  parseJSON (Object v) = do
    databaseSpecificCvss <- v .: "cvss"
    databaseSpecificCategories <- v .: "categories"
    databaseSpecificInformational <- v .: "informational"
    pure $ DatabaseSpecific{..}
  parseJSON invalid = do
    prependFailure "parsing DatabaseSpecific failed, "
      (typeMismatch "Object" invalid)

instance FromJSON EcosystemSpecific where
  parseJSON (Object v) = do
    ecosystemSpecificAffects <- v .: "affects"
    pure $ EcosystemSpecific{..}
  parseJSON invalid = do
    prependFailure "parsing EcosystemSpecific failed, "
      (typeMismatch "Object" invalid)

instance FromJSON Events where
  parseJSON (Object v) = do
    eventsIntroduced <- v .: "introduced"
    pure $ Events{..}
  parseJSON invalid = do
    prependFailure "parsing Events failed, "
      (typeMismatch "Object" invalid)

instance FromJSON Model where
  parseJSON (Object v) = do
    modelDetails <- v .: "details"
    modelId <- v .: "id"
    modelSummary <- v .: "summary"
    modelRelated <- v .: "related"
    modelAffected <- v .: "affected"
    modelAliases <- v .: "aliases"
    modelPublished <- v .: "published"
    modelReferences <- v .: "references"
    modelSeverity <- v .: "severity"
    modelModified <- v .: "modified"
    pure $ Model{..}
  parseJSON invalid = do
    prependFailure "parsing Model failed, "
      (typeMismatch "Object" invalid)

instance FromJSON Package where
  parseJSON (Object v) = do
    packageName <- v .: "name"
    packageEcosystem <- v .: "ecosystem"
    packagePurl <- v .: "purl"
    pure $ Package{..}
  parseJSON invalid = do
    prependFailure "parsing Package failed, "
      (typeMismatch "Object" invalid)

instance FromJSON Ranges where
  parseJSON (Object v) = do
    rangesEvents <- v .: "events"
    rangesType <- v .: "type"
    pure $ Ranges{..}
  parseJSON invalid = do
    prependFailure "parsing Ranges failed, "
      (typeMismatch "Object" invalid)

instance FromJSON References where
  parseJSON (Object v) = do
    referencesType <- v .: "type"
    referencesUrl <- v .: "url"
    pure $ References{..}
  parseJSON invalid = do
    prependFailure "parsing References failed, "
      (typeMismatch "Object" invalid)
