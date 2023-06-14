-- | This module contains the OSV datatype and its ToJSON instance.
-- The module was initialized with http://json-to-haskell.chrispenner.ca/
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
module Security.OSV where

import Data.Aeson
  ( ToJSON(..), FromJSON(..), Value(..)
  , (.:), (.=), object, withText
  )
import Data.Aeson.Types (prependFailure, typeMismatch)
import Data.Text (Text)
import Data.Tuple (swap)

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

newtype EcosystemSpecific = EcosystemSpecific
  { ecosystemSpecificAffects :: Affects
  } deriving (Show, Eq, Ord)

newtype Events = Events
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
  , modelReferences :: [Reference]
  , modelSeverity :: [Value]
  , modelModified :: Text
  } deriving (Show, Eq)

data Package = Package
  { packageName :: Text
  , packageEcosystem :: Text
  , packagePurl :: Text
  } deriving (Show, Eq, Ord)

data Ranges = Ranges
  { rangesEvents :: [Events]
  , rangesType :: Text
  } deriving (Show, Eq, Ord)

data ReferenceType
  = ReferenceTypeAdvisory
  -- ^ A published security advisory for the vulnerability.
  | ReferenceTypeArticle
  -- ^ An article or blog post describing the vulnerability.
  | ReferenceTypeDetection
  -- ^ A tool, script, scanner, or other mechanism that allows for detection of
  -- the vulnerability in production environments. e.g. YARA rules, hashes,
  -- virus signature, or other scanners.
  | ReferenceTypeDiscussion
  -- ^ A social media discussion regarding the vulnerability, e.g. a Twitter,
  -- Mastodon, Hacker News, or Reddit thread.
  | ReferenceTypeReport
  -- ^ A report, typically on a bug or issue tracker, of the vulnerability.
  | ReferenceTypeFix
  -- ^ A source code browser link to the fix (e.g., a GitHub commit) Note that
  -- the @Fix@ type is meant for viewing by people using web browsers. Programs
  -- interested in analyzing the exact commit range would do better to use the
  -- GIT-typed affected 'Ranges' entries.
  | ReferenceTypeIntroduced
  -- ^ A source code browser link to the introduction of the vulnerability
  -- (e.g., a GitHub commit) Note that the introduced type is meant for viewing
  -- by people using web browsers. Programs interested in analyzing the exact
  -- commit range would do better to use the GIT-typed affected  'Ranges'
  -- entries.
  | ReferenceTypePackage
  -- ^ A home web page for the package.
  | ReferenceTypeEvidence
  -- ^ A demonstration of the validity of a vulnerability claim, e.g.
  -- @app.any.run@ replaying the exploitation of the vulnerability.
  | ReferenceTypeWeb
  -- ^ A web page of some unspecified kind.
  deriving (Show, Eq)

-- | Bijection of reference types and their string representations
referenceTypes :: [(ReferenceType, Text)]
referenceTypes =
  [ (ReferenceTypeAdvisory    , "ADVISORY")
  , (ReferenceTypeArticle     , "ARTICLE")
  , (ReferenceTypeDetection   , "DETECTION")
  , (ReferenceTypeDiscussion  , "DISCUSSION")
  , (ReferenceTypeReport      , "REPORT")
  , (ReferenceTypeFix         , "FIX")
  , (ReferenceTypeIntroduced  , "INTRODUCED")
  , (ReferenceTypePackage     , "PACKAGE")
  , (ReferenceTypeEvidence    , "EVIDENCE")
  , (ReferenceTypeWeb         , "WEB")
  ]

instance FromJSON ReferenceType where
  parseJSON = withText "references.type" $ \s ->
    case lookup s (fmap swap referenceTypes) of
      Just v  -> pure v
      Nothing -> typeMismatch "references.type" (String s)

instance ToJSON ReferenceType where
  toJSON v = String $ fromMaybe "WEB" (lookup v referenceTypes)

data Reference = Reference
  { referencesType :: ReferenceType
  , referencesUrl :: Text
  } deriving (Show, Eq)

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

instance ToJSON Reference where
  toJSON Reference{..} = object
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

instance FromJSON Reference where
  parseJSON (Object v) = do
    referencesType <- v .: "type"
    referencesUrl <- v .: "url"
    pure $ Reference{..}
  parseJSON invalid = do
    prependFailure "parsing References failed, "
      (typeMismatch "Object" invalid)
