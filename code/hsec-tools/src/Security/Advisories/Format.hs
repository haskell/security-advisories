{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Security.Advisories.Format
  ( FrontMatter (..),
    codecFrontMatter,
    fromAdvisory,
    toAdvisory,
    OutOfBandAttributes (..),
    emptyOutOfBandAttributes,
    AttributeOverridePolicy (..),
    AdvisoryMetadata (..),
  )
where

import Commonmark.Types (HasAttributes (..), IsBlock (..), IsInline (..), Rangeable (..), SourceRange (..))
import Data.Bifunctor (first)
import Data.Either.Extra (maybeToEither)
import Data.Foldable (toList)
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import Data.Monoid (First (..))
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.Text as T
import Data.Time (ZonedTime (..))
import Data.Tuple (swap)
import Distribution.Parsec (eitherParsec)
import Distribution.Pretty (pretty)
import Distribution.Types.Version (Version)
import Distribution.Types.VersionRange (VersionRange)
import GHC.Generics (Generic)
import Security.Advisories.Core.Advisory
import Security.Advisories.Core.HsecId
import qualified Security.CVSS as CVSS
import Security.OSV (Reference (..), ReferenceType, referenceTypes)
import Text.Pandoc.Definition (Pandoc (..))
import qualified Text.PrettyPrint as Pretty
import Toml ((.=))
import qualified Toml

-- | A source of attributes supplied out of band from the advisory
-- content.  Values provided out of band are treated according to
-- the 'AttributeOverridePolicy'.
--
-- The convenient way to construct a value of this type is to start
-- with 'emptyOutOfBandAttributes', then use the record accessors to
-- set particular fields.
data OutOfBandAttributes = OutOfBandAttributes
  { oobModified :: Maybe ZonedTime,
    oobPublished :: Maybe ZonedTime
  }
  deriving (Show)

emptyOutOfBandAttributes :: OutOfBandAttributes
emptyOutOfBandAttributes =
  OutOfBandAttributes
    { oobModified = Nothing,
      oobPublished = Nothing
    }

data AttributeOverridePolicy
  = PreferInBand
  | PreferOutOfBand
  | -- | Parse error if attribute occurs both in-band and out-of-band
    NoOverrides
  deriving (Show, Eq)

toAdvisory ::
  OutOfBandAttributes ->
  AttributeOverridePolicy ->
  -- | parsed document (without frontmatter)
  Pandoc ->
  -- | summary
  T.Text ->
  -- | details
  T.Text ->
  -- | rendered HTML
  T.Text ->
  FrontMatter ->
  Either [Toml.TomlDecodeError] Advisory
toAdvisory oob policy doc summary details html fm = do
  published <-
    mergeOobMandatory
      policy
      (oobPublished oob)
      "advisory.date"
      (amdPublished (frontMatterAdvisory fm))
      (Left . return . Toml.ParseError . Toml.TomlParseError)
  modified <-
    fromMaybe published
      <$> mergeOobOptional
        policy
        (oobPublished oob)
        "advisory.modified"
        (amdModified (frontMatterAdvisory fm))
        (Left . return . Toml.ParseError . Toml.TomlParseError)
  pure
    Advisory
      { advisoryId = amdId $ frontMatterAdvisory fm,
        advisoryPublished = published,
        advisoryModified = modified,
        advisoryCAPECs = amdCAPECs $ frontMatterAdvisory fm,
        advisoryCWEs = amdCWEs $ frontMatterAdvisory fm,
        advisoryKeywords = amdKeywords $ frontMatterAdvisory fm,
        advisoryAliases = amdAliases $ frontMatterAdvisory fm,
        advisoryRelated = amdRelated $ frontMatterAdvisory fm,
        advisoryAffected = frontMatterAffected fm,
        advisoryReferences = frontMatterReferences fm,
        advisoryPandoc = doc,
        advisoryHtml = html,
        advisorySummary = summary,
        advisoryDetails = details
      }

fromAdvisory :: Advisory -> FrontMatter
fromAdvisory advisory =
  FrontMatter
    { frontMatterAdvisory =
        AdvisoryMetadata
          { amdId = advisoryId advisory,
            amdPublished = Just $ advisoryPublished advisory,
            amdModified = Just $ advisoryModified advisory,
            amdCAPECs = advisoryCAPECs advisory,
            amdCWEs = advisoryCWEs advisory,
            amdKeywords = advisoryKeywords advisory,
            amdAliases = advisoryAliases advisory,
            amdRelated = advisoryRelated advisory
          },
      frontMatterReferences = advisoryReferences advisory,
      frontMatterAffected = advisoryAffected advisory
    }

-- | Internal type corresponding to the complete raw TOML content of an
-- advisory markdown file.
data FrontMatter = FrontMatter
  { frontMatterAdvisory :: AdvisoryMetadata,
    frontMatterReferences :: [Reference],
    frontMatterAffected :: [Affected]
  }
  deriving (Generic)

codecFrontMatter :: Toml.TomlCodec FrontMatter
codecFrontMatter =
  FrontMatter
    <$> codecAdvisoryMetadata "advisory"
    .= frontMatterAdvisory
    <*> Toml.list codecReference "references"
    .= frontMatterReferences
    <*> mandatoryList codecAffected "affected"
    .= frontMatterAffected

-- | Internal type corresponding to the @[advisory]@ subsection of the
-- TOML frontmatter in an advisory markdown file.
data AdvisoryMetadata = AdvisoryMetadata
  { amdId :: HsecId,
    amdModified :: Maybe ZonedTime,
    amdPublished :: Maybe ZonedTime,
    amdCAPECs :: [CAPEC],
    amdCWEs :: [CWE],
    amdKeywords :: [Keyword],
    amdAliases :: [T.Text],
    amdRelated :: [T.Text]
  }

codecAdvisoryMetadata :: Toml.Key -> Toml.TomlCodec AdvisoryMetadata
codecAdvisoryMetadata = Toml.table go
  where
    go :: Toml.TomlCodec AdvisoryMetadata
    go =
      AdvisoryMetadata
        <$> codecHsecId "id"
        .= amdId
        <*> Toml.dioptional (Toml.zonedTime "date")
        .= amdModified
        <*> Toml.dioptional (Toml.zonedTime "modified")
        .= amdPublished
        <*> Toml.dimap (map unCAPEC) (map CAPEC) (defaultingArrayOf Toml._Integer "capec")
        .= amdCAPECs
        <*> Toml.dimap (map unCWE) (map CWE) (defaultingArrayOf Toml._Integer "cwe")
        .= amdCWEs
        <*> Toml.dimap (map unKeyword) (map Keyword) (defaultingArrayOf Toml._Text "keywords")
        .= amdKeywords
        <*> defaultingArrayOf Toml._Text "aliases"
        .= amdAliases
        <*> defaultingArrayOf Toml._Text "related"
        .= amdRelated

codecHsecId :: Toml.Key -> Toml.Codec HsecId HsecId
codecHsecId =
  Toml.textBy
    (T.pack . printHsecId)
    (maybeToEither "invalid HSEC-ID: expected HSEC-[0-9]{4,}-[0-9]{4,}" . parseHsecId . T.unpack)

codecAffected :: Toml.TomlCodec Affected
codecAffected =
  Affected
    <$> Toml.text "package"
    .= affectedPackage
    <*> codecCVSS "cvss"
    .= affectedCVSS
    <*> Toml.list codecAffectedVersionRange "versions"
    .= affectedVersions
    <*> Toml.dioptional (defaultingArrayOf codecArchitecture "arch")
    .= affectedArchitectures
    <*> Toml.dioptional (defaultingArrayOf codecOS "os")
    .= affectedOS
    <*> Toml.dimap Map.fromList Map.toList (Toml.tableMap Toml._KeyText codecVersionRange "declarations")
    .= affectedDeclarations

codecVersionRange :: Toml.Key -> Toml.TomlCodec VersionRange
codecVersionRange =
  Toml.textBy
    (T.pack . Pretty.render . pretty)
    (first (T.pack . show) . eitherParsec . T.unpack)

codecReference :: Toml.TomlCodec Reference
codecReference =
  Reference
    <$> codecReferenceType "type"
    .= referencesType
    <*> Toml.text "url"
    .= referencesUrl

codecCVSS :: Toml.Key -> Toml.TomlCodec CVSS.CVSS
codecCVSS = Toml.textBy (T.pack . show) (first (T.pack . show) . CVSS.parseCVSS)

codecAffectedVersionRange :: Toml.TomlCodec AffectedVersionRange
codecAffectedVersionRange =
  AffectedVersionRange
    <$> codecVersion "introduced"
    .= affectedVersionRangeIntroduced
    <*> Toml.dioptional (codecVersion "fixed")
    .= affectedVersionRangeFixed

codecVersion :: Toml.Key -> Toml.TomlCodec Version
codecVersion =
  Toml.textBy
    (T.pack . Pretty.render . pretty)
    (first (T.pack . show) . eitherParsec . T.unpack)

codecArchitecture :: Toml.TomlBiMap Architecture Toml.AnyValue
codecArchitecture = Toml._TextBy toStr fromStr
  where
    toStr =
      \case
        AArch64 -> "aarch64"
        Alpha -> "alpha"
        Arm -> "arm"
        HPPA -> "hppa"
        HPPA1_1 -> "hppa1_1"
        I386 -> "i386"
        IA64 -> "ia64"
        M68K -> "m68k"
        MIPS -> "mips"
        MIPSEB -> "mipseb"
        MIPSEL -> "mipsel"
        NIOS2 -> "nios2"
        PowerPC -> "powerpc"
        PowerPC64 -> "powerpc64"
        PowerPC64LE -> "powerpc64le"
        RISCV32 -> "riscv32"
        RISCV64 -> "riscv64"
        RS6000 -> "rs6000"
        S390 -> "s390"
        S390X -> "s390x"
        SH4 -> "sh4"
        SPARC -> "sparc"
        SPARC64 -> "sparc64"
        VAX -> "vax"
        X86_64 -> "x86_64"
    fromStr =
      \case
        "aarch64" -> pure AArch64
        "alpha" -> pure Alpha
        "arm" -> pure Arm
        "hppa" -> pure HPPA
        "hppa1_1" -> pure HPPA1_1
        "i386" -> pure I386
        "ia64" -> pure IA64
        "m68k" -> pure M68K
        "mips" -> pure MIPS
        "mipseb" -> pure MIPSEB
        "mipsel" -> pure MIPSEL
        "nios2" -> pure NIOS2
        "powerpc" -> pure PowerPC
        "powerpc64" -> pure PowerPC64
        "powerpc64le" -> pure PowerPC64LE
        "riscv32" -> pure RISCV32
        "riscv64" -> pure RISCV64
        "rs6000" -> pure RS6000
        "s390" -> pure S390
        "s390x" -> pure S390X
        "sh4" -> pure SH4
        "sparc" -> pure SPARC
        "sparc64" -> pure SPARC64
        "vax" -> pure VAX
        "x86_64" -> pure X86_64
        other -> Left $ "Invalid architecture: " <> T.pack (show other)

codecOS :: Toml.TomlBiMap OS Toml.AnyValue
codecOS = Toml._TextBy toStr fromStr
  where
    toStr =
      \case
        MacOS -> "darwin"
        FreeBSD -> "freebsd"
        Linux -> "linux"
        Android -> "linux-android"
        Windows -> "mingw32"
        NetBSD -> "netbsd"
        OpenBSD -> "openbsd"
    fromStr =
      \case
        "darwin" -> pure MacOS
        "freebsd" -> pure FreeBSD
        "linux" -> pure Linux
        "linux-android" -> pure Android
        "mingw32" -> pure Windows
        "netbsd" -> pure NetBSD
        "openbsd" -> pure OpenBSD
        other -> Left $ "Invalid OS: " <> T.pack (show other)

codecReferenceType :: Toml.Key -> Toml.TomlCodec ReferenceType
codecReferenceType = Toml.textBy toStr fromStr
  where
    toStr x =
      case lookup x referenceTypes of
        Just a -> a
        Nothing -> error $ "Cannot render reference.type " <> show x
    fromStr x =
      case lookup x (swap <$> referenceTypes) of
        Just a -> pure a
        Nothing -> Left $ "'" <> x <> "' reference.type should be one of: " <> T.intercalate ", " (snd <$> referenceTypes)

defaultingArrayOf :: Toml.TomlBiMap a Toml.AnyValue -> Toml.Key -> Toml.TomlCodec [a]
defaultingArrayOf d = Toml.dimap Just (fromMaybe mempty) . Toml.dioptional . Toml.arrayOf d

mandatoryList :: forall a. Toml.TomlCodec a -> Toml.Key -> Toml.TomlCodec [a]
mandatoryList codec key = Toml.Codec
    { Toml.codecRead = fmap toList . Toml.codecRead nonEmptyCodec
    , Toml.codecWrite = \case
        [] -> pure []
        l@(x:xs) -> l <$ Toml.codecWrite nonEmptyCodec (x :| xs)
    }
  where
    nonEmptyCodec :: Toml.TomlCodec (NonEmpty a)
    nonEmptyCodec = Toml.nonEmpty codec key

mergeOob ::
  AttributeOverridePolicy ->
  -- | out-of-band value
  Maybe a ->
  -- | key
  T.Text ->
  -- | in-band-value
  Maybe a ->
  -- | when key and out-of-band value absent
  b ->
  -- | when value present
  (a -> b) ->
  -- | when an error occurs
  (T.Text -> b) ->
  b
mergeOob policy oob k ib absent present sendError = do
  case (oob, ib) of
    (Just l, Just r) -> case policy of
      NoOverrides -> sendError $ "illegal out of band override: " <> k
      PreferOutOfBand -> present l
      PreferInBand -> present r
    (Just a, Nothing) -> present a
    (Nothing, Just a) -> present a
    (Nothing, Nothing) -> absent

mergeOobOptional ::
  Applicative f =>
  AttributeOverridePolicy ->
  -- | out-of-band value
  Maybe a ->
  -- | key
  T.Text ->
  -- | in-band-value
  Maybe a ->
  -- | when an error occurs
  (T.Text -> f (Maybe a)) ->
  f (Maybe a)
mergeOobOptional policy oob k ib =
  mergeOob policy oob k ib (pure Nothing) (pure . Just)

mergeOobMandatory ::
  Applicative f =>
  AttributeOverridePolicy ->
  -- | out-of-band value
  Maybe a ->
  -- | key
  T.Text ->
  -- | in-band value
  Maybe a ->
  -- | when an error occurs
  (T.Text -> f a) ->
  f a
mergeOobMandatory policy oob k ib sendError =
  mergeOob policy oob k ib (sendError $ "missing mandatory key: " <> k) pure sendError

-- | A solution to an awkward problem: how to delete the TOML
-- block.  We parse into this type to get the source range of
-- the first block element.  We can use it to delete the lines
-- from the input.
newtype FirstSourceRange = FirstSourceRange (First SourceRange)
  deriving stock (Show)
  deriving newtype (Semigroup, Monoid)

instance Rangeable FirstSourceRange where
  ranged range = (FirstSourceRange (First (Just range)) <>)

instance HasAttributes FirstSourceRange where
  addAttributes _ = id

instance IsBlock FirstSourceRange FirstSourceRange where
  paragraph _ = mempty
  plain _ = mempty
  thematicBreak = mempty
  blockQuote _ = mempty
  codeBlock _ = mempty
  heading _ = mempty
  rawBlock _ = mempty
  referenceLinkDefinition _ = mempty
  list _ = mempty

instance IsInline FirstSourceRange where
  lineBreak = mempty
  softBreak = mempty
  str _ = mempty
  entity _ = mempty
  escapedChar _ = mempty
  emph = id
  strong = id
  link _ _ _ = mempty
  image _ _ _ = mempty
  code _ = mempty
  rawInline _ _ = mempty
