-- | This module contains the OSV datatype and its ToJSON instance.
-- The module was initialized with http://json-to-haskell.chrispenner.ca/
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Security.OSV
  (
  -- * Top-level data type
    Model(..)
  , newModel
  , newModel'
  , defaultSchemaVersion

  -- * Subsidiary data types
  , Affected(..)
  , Credit(..)
  , CreditType(..)
  , creditTypes
  , Event(..)
  , Package(..)
  , Range(..)
  , Reference(..)
  , ReferenceType(..)
  , referenceTypes
  , Severity(..)
  )
  where

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

import qualified Security.CVSS as CVSS

data Affected dbSpecific ecosystemSpecific rangeDbSpecific = Affected
  { affectedRanges :: [Range rangeDbSpecific]
  , affectedPackage :: Package
  , affectedSeverity :: [Severity]
  , affectedEcosystemSpecific :: Maybe ecosystemSpecific
  , affectedDatabaseSpecific :: Maybe dbSpecific
  } deriving (Show, Eq)

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

-- | OSV model parameterised over database-specific and
-- ecosystem-specific fields.
--
-- A naïve consumer can parse @'Model' 'Value' Value Value Value@
-- for no loss of information.
--
-- A producer can instantiate unused database/ecosystem-specific
-- fields at @Data.Void.Void@.  '()' is not recommended, because
-- @'Just' ()@ will serialise as an empty JSON array.
--
data Model dbSpecific affectedEcosystemSpecific affectedDbSpecific rangeDbSpecific = Model
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
  , modelSeverity :: [Severity]
  , modelAffected :: [Affected affectedEcosystemSpecific affectedDbSpecific rangeDbSpecific]
  , modelReferences :: [Reference]
  , modelCredits :: [Credit]
  , modelDatabaseSpecific :: Maybe dbSpecific
  } deriving (Show, Eq)

-- | Schema version implemented by this library.  Currently @1.5.0@.
defaultSchemaVersion :: Text
defaultSchemaVersion = "1.5.0"

-- | Construct a new model with only the required fields
newModel
  :: Text -- ^ schema version
  -> Text -- ^ id
  -> UTCTime -- ^ modified
  -> Model dbs aes adbs rdbs
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
  -> Model dbs aes adbs rdbs
newModel' = newModel defaultSchemaVersion

-- | Severity.  There is no 'Ord' instance.  Severity scores should be
-- calculated and compared in a more nuanced way than 'Ord' can provide
-- for.
--
newtype Severity = Severity CVSS.CVSS
  deriving (Show)

instance Eq Severity where
  Severity s1 == Severity s2 = CVSS.cvssVectorString s1 == CVSS.cvssVectorString s2

instance FromJSON Severity where
  parseJSON = withObject "severity" $ \o -> do
    typ <- o .: "type" :: Parser Text
    score <- o .: "score" :: Parser Text
    cvss <- case CVSS.parseCVSS score of
      Right cvss -> pure cvss
      Left err ->
        prependFailure ("unregognised severity score: " <> show err)
          $ typeMismatch "severity" (Object o)
    case typ of
      "CVSS_V2" | CVSS.cvssVersion cvss == CVSS.CVSS20 -> pure $ Severity cvss
      "CVSS_V3" | CVSS.cvssVersion cvss `elem` [CVSS.CVSS30, CVSS.CVSS31] -> pure $ Severity cvss
      s ->
        prependFailure ("unregognised severity type: " <> show s)
          $ typeMismatch "severity" (Object o)

instance ToJSON Severity where
  toJSON (Severity cvss) = object ["score" .= CVSS.cvssVectorString cvss, "type" .= typ]
    where
      typ :: Text
      typ = case CVSS.cvssVersion cvss of
        CVSS.CVSS31 -> "CVSS_V3"
        CVSS.CVSS30 -> "CVSS_V3"
        CVSS.CVSS20 -> "CVSS_V2"

data Package = Package
  { packageName :: Text
  , packageEcosystem :: Text
  , packagePurl :: Maybe Text  -- TODO refine type
  } deriving (Show, Eq, Ord)

data Range dbSpecific
  = RangeSemVer [Event Text {- TODO refine -}] (Maybe dbSpecific)
  | RangeEcosystem [Event Text] (Maybe dbSpecific)
  | RangeGit
      [Event Text {- TODO refine -}]
      Text -- ^ Git repo URL
      (Maybe dbSpecific)
  deriving (Eq, Show)

instance (FromJSON dbSpecific) => FromJSON (Range dbSpecific) where
  parseJSON = withObject "ranges[]" $ \o -> do
    typ <- o .: "type" :: Parser Text
    case typ of
      "SEMVER" -> RangeSemVer <$> o .: "events" <*> o .:? "database_specific"
      "ECOSYSTEM" -> RangeEcosystem <$> o .: "events" <*> o .:? "database_specific"
      "GIT" -> RangeGit <$> o .: "events" <*> o .: "repo" <*> o .:? "database_specific"
      s ->
        prependFailure ("unregognised range type: " <> show s)
          $ typeMismatch "ranges[]" (Object o)

instance (ToJSON dbSpecific) => ToJSON (Range dbSpecific) where
  toJSON range = object $ case range of
    RangeSemVer evs dbs -> [typ "SEMVER", "events" .= evs] <> mkDbSpecific dbs
    RangeEcosystem evs dbs -> [typ "ECOSYSTEM", "events" .= evs] <> mkDbSpecific dbs
    RangeGit evs repo dbs -> [typ "GIT", "events" .= evs, "repo" .= repo] <> mkDbSpecific dbs
    where
      mkDbSpecific = maybe [] (\v -> ["database_specific" .= v])
      typ s = "type" .= (s :: Text)

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


-- | Types of individuals or entities to be credited in relation to
-- an advisory.
data CreditType
  = CreditTypeFinder
  -- ^ Identified the vulnerability
  | CreditTypeReporter
  -- ^ Notified the vendor of the vulnerability to a CNA
  | CreditTypeAnalyst
  -- ^ Validated the vulnerability to ensure accuracy or severity
  | CreditTypeCoordinator
  -- ^ Facilitated the coordinated response process
  | CreditTypeRemediationDeveloper
  -- ^ prepared a code change or other remediation plans
  | CreditTypeRemediationReviewer
  -- ^ Reviewed vulnerability remediation plans or code changes for effectiveness and completeness
  | CreditTypeRemediationVerifier
  -- ^ Tested and verified the vulnerability or its remediation
  | CreditTypeTool
  -- ^ Names of tools used in vulnerability discovery or identification
  | CreditTypeSponsor
  -- ^ Supported the vulnerability identification or remediation activities
  | CreditTypeOther
  -- ^ Any other type or role that does not fall under the categories described above
  deriving (Show, Eq)

-- | Bijection of credit types and their string representations
creditTypes :: [(CreditType, Text)]
creditTypes =
  [ (CreditTypeFinder               , "FINDER")
  , (CreditTypeReporter             , "REPORTER")
  , (CreditTypeAnalyst              , "ANALYST")
  , (CreditTypeCoordinator          , "COORDINATOR")
  , (CreditTypeRemediationDeveloper , "REMEDIATION_DEVELOPER")
  , (CreditTypeRemediationReviewer  , "REMEDIATION_REVIEWER")
  , (CreditTypeRemediationVerifier  , "REMEDIATION_VERIFIER")
  , (CreditTypeTool                 , "TOOL")
  , (CreditTypeSponsor              , "SPONSOR")
  , (CreditTypeOther                , "OTHER")
  ]

instance FromJSON CreditType where
  parseJSON = withText "credits[].type" $ \s ->
    case lookup s (fmap swap creditTypes) of
      Just v  -> pure v
      Nothing -> typeMismatch "credits[].type" (String s)

instance ToJSON CreditType where
  toJSON v = String $ fromMaybe "OTHER" (lookup v creditTypes)

data Credit = Credit
  { creditType :: CreditType
  , creditName :: Text
    -- ^ The name, label, or other identifier of the individual or entity
    -- being credited, using whatever notation the creditor prefers.
  , creditContacts :: [Text] -- TODO refine tpye
    -- ^ Fully qualified, plain-text URLs at which the credited can be reached.
  }
  deriving (Show, Eq)

instance FromJSON Credit where
  parseJSON = withObject "credits[]" $ \o -> do
    creditType <- o .: "type"
    creditName <- o .: "name"
    creditContacts <- o .::? "contact"
    pure $ Credit{..}

instance ToJSON Credit where
  toJSON Credit{..} = object $
    [ "type" .= creditType
    , "name" .= creditName
    ]
    <> omitEmptyList "contact" creditContacts
    where
      omitEmptyList _ [] = []
      omitEmptyList k xs = [k .= xs]


instance
    (ToJSON ecosystemSpecific, ToJSON dbSpecific, ToJSON rangeDbSpecific)
    => ToJSON (Affected ecosystemSpecific dbSpecific rangeDbSpecific) where
  toJSON Affected{..} = object $
    [ "ranges" .= affectedRanges
    , "package" .= affectedPackage
    ]
    <> omitEmptyList "severity" affectedSeverity
    <> maybe [] (pure . ("ecosystem_specific" .=)) affectedEcosystemSpecific
    <> maybe [] (pure . ("database_specific" .=)) affectedDatabaseSpecific
    where
      omitEmptyList _ [] = []
      omitEmptyList k xs = [k .= xs]

instance
  ( ToJSON dbSpecific
  , ToJSON affectedEcosystemSpecific
  , ToJSON affectedDbSpecific
  , ToJSON rangeDbSpecific
  ) => ToJSON (Model dbSpecific affectedEcosystemSpecific affectedDbSpecific rangeDbSpecific)
  where
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
      , ("credits" .=) <$> omitEmptyList modelCredits
      , ("database_specific" .=) <$> modelDatabaseSpecific
    ]
    where
      omitEmptyList [] = Nothing
      omitEmptyList xs = Just xs

instance ToJSON Package where
  toJSON Package{..} = object $
    [ "name" .= packageName
    , "ecosystem" .= packageEcosystem
    ]
    <> maybe [] (pure . ("purl" .=)) packagePurl

instance ToJSON Reference where
  toJSON Reference{..} = object
    [ "type" .= referencesType
    , "url" .= referencesUrl
    ]

instance
    (FromJSON ecosystemSpecific, FromJSON dbSpecific, FromJSON rangeDbSpecific)
    => FromJSON (Affected ecosystemSpecific dbSpecific rangeDbSpecific) where
  parseJSON (Object v) = do
    affectedRanges <- v .: "ranges"
    affectedPackage <- v .: "package"
    affectedSeverity <- v .::? "severity"
    affectedEcosystemSpecific <- v .:? "ecosystem_specific"
    affectedDatabaseSpecific <- v .:? "database_specific"
    pure $ Affected{..}
  parseJSON invalid = do
    prependFailure "parsing Affected failed, "
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

instance
  ( FromJSON dbSpecific
  , FromJSON affectedEcosystemSpecific
  , FromJSON affectedDbSpecific
  , FromJSON rangeDbSpecific
  ) => FromJSON (Model dbSpecific affectedEcosystemSpecific affectedDbSpecific rangeDbSpecific) where
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
    packagePurl <- v .:? "purl"
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
