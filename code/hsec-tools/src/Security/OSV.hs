-- | This module contains the OSV datatype and its ToJSON instance.
-- The module was initialized with http://json-to-haskell.chrispenner.ca/
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
module Security.OSV where

import Control.Applicative ((<|>))
import Control.Monad (when)
import Data.Maybe (catMaybes, fromMaybe)
import Data.Aeson
  ( ToJSON(..), FromJSON(..), Value(..)
  , (.:), (.:?), (.=), object, withObject, withText
  )
import Data.Aeson.Types
  ( Key, Object, Parser
  , explicitParseField, explicitParseFieldMaybe, prependFailure, typeMismatch
  )
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime)
import Data.Time.Format.ISO8601 (iso8601ParseM)
import Data.Tuple (swap)

data Affected = Affected
  { affectedRanges :: [Range]
  , affectedPackage :: Package
  , affectedEcosystemSpecific :: EcosystemSpecific
  , affectedDatabaseSpecific :: DatabaseSpecific
  } deriving (Show, Eq)

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

data Event a
  = EventIntroduced a
  | EventFixed a
  | EventLastAffected a
  | EventLimit a
  deriving (Eq, Ord, Show)

instance (FromJSON a) => FromJSON (Event a) where
  parseJSON = withObject "events[]" $ \o -> do
    -- there must exactly one key
    when (length o /= 1) $ typeMismatch "events[]" (Object o)
    prependFailure "unknown event type" $
      EventIntroduced <$> o .: "introduced"
      <|> EventFixed <$> o .: "fixed"
      <|> EventLastAffected <$> o .: "last_affected"
      <|> EventLimit <$> o .: "limit"

instance (ToJSON a) => ToJSON (Event a) where
  toJSON ev = object . pure $ case ev of
    EventIntroduced a   -> "introduced"    .= a
    EventFixed a        -> "fixed"         .= a
    EventLastAffected a -> "last_affected" .= a
    EventLimit a        -> "limit"         .= a

-- | OSV model parameterised over the @database_specific@ field.
--
data Model a = Model
  { modelSchemaVersion :: Text  -- TODO make it a proper semver version type
  , modelId :: Text             -- TODO we should newtype it
  , modelModified :: UTCTime
  , modelPublished :: Maybe UTCTime
  , modelWithdrawn :: Maybe UTCTime
  , modelAliases :: [Text]
  , modelRelated :: [Text]
  , modelSummary :: Maybe Text
    -- ^ A one-line, English textual summary of the vulnerability. It is
    -- recommended that this field be kept short, on the order of no more than
    -- 120 characters.
  , modelDetails :: Maybe Text
    -- ^ CommonMark markdown giving additional English textual details about
    -- the vulnerability.
  , modelSeverity :: [Value]  -- TODO refine type
  , modelAffected :: [Affected]
  , modelReferences :: [Reference]
  , modelCredits :: [Value] -- TODO refine
  , modelDatabaseSpecific :: Maybe a
  } deriving (Show, Eq)

-- | Schema version implemented by this library.  Currently @1.5.0@.
defaultSchemaVersion :: Text
defaultSchemaVersion = "1.5.0"

-- | Construct a new model with only the required fields
newModel
  :: Text -- ^ schema version
  -> Text -- ^ id
  -> UTCTime -- ^ modified
  -> Model a
newModel ver ident modified = Model
  ver
  ident
  modified
  Nothing
  Nothing
  []
  []
  Nothing
  Nothing
  []
  []
  []
  []
  Nothing

-- | Construct a new model given @id@ and @modified@ values,
-- using 'defaultSchemaVersion'.
newModel'
  :: Text -- ^ id
  -> UTCTime -- ^ modified
  -> Model a
newModel' = newModel defaultSchemaVersion

data Package = Package
  { packageName :: Text
  , packageEcosystem :: Text
  , packagePurl :: Text
  } deriving (Show, Eq, Ord)

data Range
  = RangeSemVer [Event Text {- TODO refine -}]
  | RangeEcosystem [Event Text]
  | RangeGit
      [Event Text {- TODO refine -}]
      Text -- ^ Git repo URL
  deriving (Eq, Show)

instance FromJSON Range where
  parseJSON = withObject "ranges[]" $ \o -> do
    typ <- o .: "type" :: Parser Text
    case typ of
      "SEMVER" -> RangeSemVer <$> o .: "events"
      "ECOSYSTEM" -> RangeEcosystem <$> o .: "events"
      "GIT" -> RangeGit <$> o .: "events" <*> o .: "repo"
      s ->
        prependFailure ("unregognised range type: " <> show s)
          $ typeMismatch "ranges[]" (Object o)

instance ToJSON Range where
  toJSON range = object $ case range of
    RangeSemVer evs -> ["type" .= ("SEMVER" :: Text), "events" .= evs]
    RangeEcosystem evs -> ["type" .= ("ECOSYSTEM" :: Text), "events" .= evs]
    RangeGit evs repo -> ["type" .= ("GIT" :: Text), "events" .= evs, "repo" .= repo]

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
  -- GIT-typed affected 'Range' entries.
  | ReferenceTypeIntroduced
  -- ^ A source code browser link to the introduction of the vulnerability
  -- (e.g., a GitHub commit) Note that the introduced type is meant for viewing
  -- by people using web browsers. Programs interested in analyzing the exact
  -- commit range would do better to use the GIT-typed affected  'Range'
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

instance (ToJSON a) => ToJSON (Model a) where
  toJSON Model{..} = object $
    [ "schema_version" .= modelSchemaVersion
    , "id" .= modelId
    , "modified" .= modelModified
    ]
    <> catMaybes
      [ ("published" .=) <$> modelPublished
      , ("withdrawn" .=) <$> modelWithdrawn
      , ("aliases" .=) <$> omitEmptyList modelAliases
      , ("related" .=) <$> omitEmptyList modelRelated
      , ("summary" .=) <$> modelSummary
      , ("details" .=) <$> modelDetails
      , ("severity" .=) <$> omitEmptyList modelSeverity
      , ("affected" .=) <$> omitEmptyList modelAffected
      , ("references" .=) <$> omitEmptyList modelReferences
      , ("credits" .=) <$> omitEmptyList modelReferences
      , ("database_specific" .=) <$> modelDatabaseSpecific
    ]
    where
      omitEmptyList [] = Nothing
      omitEmptyList xs = Just xs

instance ToJSON Package where
  toJSON Package{..} = object
    [ "name" .= packageName
    , "ecosystem" .= packageEcosystem
    , "purl" .= packagePurl
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

-- | Explicit parser for 'UTCTime', stricter than the @FromJSON@
-- instance for that type.
--
parseUTCTime :: Value -> Parser UTCTime
parseUTCTime = withText "UTCTime" $ \s ->
  case iso8601ParseM (T.unpack s) of
    Nothing -> typeMismatch "UTCTime" (String s)
    Just t -> pure t

-- | Parse helper for optional lists.  If the key is absent,
-- it will be interpreted as an empty list.
--
(.::?) :: FromJSON a => Object -> Key -> Parser [a]
o .::? k = fromMaybe [] <$> o .:? k

instance (FromJSON a) => FromJSON (Model a) where
  parseJSON = withObject "osv-schema" $ \v -> do
    modelSchemaVersion <- v .: "schema_version"
    modelId <- v .: "id"
    modelModified <- explicitParseField parseUTCTime v "modified"
    modelPublished <- explicitParseFieldMaybe parseUTCTime v "published"
    modelWithdrawn <- explicitParseFieldMaybe parseUTCTime v "withdrawn"
    modelAliases <- v .::? "aliases"
    modelRelated <- v .::? "related"
    modelSummary <- v .:? "summary"
    modelDetails <- v .:? "details"
    modelSeverity <- v .::? "severity"
    modelAffected <- v .::? "affected"
    modelReferences <- v .::? "references"
    modelCredits <- v .::? "credits"
    modelDatabaseSpecific <- v .:? "database_specific"
    pure $ Model{..}

instance FromJSON Package where
  parseJSON (Object v) = do
    packageName <- v .: "name"
    packageEcosystem <- v .: "ecosystem"
    packagePurl <- v .: "purl"
    pure $ Package{..}
  parseJSON invalid = do
    prependFailure "parsing Package failed, "
      (typeMismatch "Object" invalid)

instance FromJSON Reference where
  parseJSON (Object v) = do
    referencesType <- v .: "type"
    referencesUrl <- v .: "url"
    pure $ Reference{..}
  parseJSON invalid = do
    prependFailure "parsing References failed, "
      (typeMismatch "Object" invalid)
