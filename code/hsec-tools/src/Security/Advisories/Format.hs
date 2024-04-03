{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Security.Advisories.Format
  ( FrontMatter (..),
    fromAdvisory,
    AdvisoryMetadata (..),
    Toml.ToTable (..),
    Toml.ToValue (..),
    Toml.FromValue (..),
  )
where

import Commonmark.Types (HasAttributes (..), IsBlock (..), IsInline (..), Rangeable (..), SourceRange (..))
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import Data.Monoid (First (..))
import Data.List (intercalate)
import Data.Tuple (swap)
import GHC.Generics (Generic)

import qualified Data.Text as T
import Data.Time (ZonedTime (..), LocalTime (LocalTime), midnight, utc)
import Distribution.Parsec (eitherParsec)
import Distribution.Pretty (pretty)
import Distribution.Types.Version (Version)
import Distribution.Types.VersionRange (VersionRange)
import qualified Text.PrettyPrint as Pretty
import qualified Toml
import qualified Toml.Schema as Toml

import Security.Advisories.Core.Advisory
import Security.Advisories.Core.HsecId
import qualified Security.CVSS as CVSS
import Security.OSV (Reference (..), ReferenceType, referenceTypes)

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

-- advisory markdown file.
data FrontMatter = FrontMatter {
  frontMatterAdvisory :: AdvisoryMetadata,
  frontMatterReferences :: [Reference],
  frontMatterAffected :: [Affected]
} deriving (Show, Generic)

instance Toml.FromValue FrontMatter where
  fromValue = Toml.parseTableFromValue $
   do advisory   <- Toml.reqKey "advisory"
      affected   <- Toml.reqKey "affected"
      references <- fromMaybe [] <$> Toml.optKey "references"
      pure FrontMatter {
        frontMatterAdvisory = advisory,
        frontMatterAffected = affected,
        frontMatterReferences = references
        }

instance Toml.ToValue FrontMatter where
  toValue = Toml.defaultTableToValue

instance Toml.ToTable FrontMatter where
  toTable x = Toml.table
    [ "advisory" Toml..= frontMatterAdvisory x
    , "affected" Toml..= frontMatterAffected x
    , "references" Toml..= frontMatterReferences x
    ]

-- | Internal type corresponding to the @[advisory]@ subsection of the
-- TOML frontmatter in an advisory markdown file.
data AdvisoryMetadata = AdvisoryMetadata
  { amdId         :: HsecId
  , amdModified   :: Maybe ZonedTime
  , amdPublished  :: Maybe ZonedTime
  , amdCAPECs     :: [CAPEC]
  , amdCWEs       :: [CWE]
  , amdKeywords   :: [Keyword]
  , amdAliases    :: [T.Text]
  , amdRelated    :: [T.Text]
  }
  deriving (Show, Generic)

instance Toml.FromValue AdvisoryMetadata where
  fromValue = Toml.parseTableFromValue $
   do identifier  <- Toml.reqKey "id"
      published   <- Toml.optKeyOf "date" getDefaultedZonedTime
      modified    <- Toml.optKeyOf "modified"  getDefaultedZonedTime
      let optList key = fromMaybe [] <$> Toml.optKey key
      capecs      <- optList "capec"
      cwes        <- optList "cwe"
      kwds        <- optList "keywords"
      aliases     <- optList "aliases"
      related     <- optList "related"
      pure AdvisoryMetadata
        { amdId = identifier
        , amdModified = modified
        , amdPublished = published
        , amdCAPECs = capecs
        , amdCWEs = cwes
        , amdKeywords = kwds
        , amdAliases = aliases
        , amdRelated = related
        }

instance Toml.ToValue AdvisoryMetadata where
  toValue = Toml.defaultTableToValue

instance Toml.ToTable AdvisoryMetadata where
  toTable x = Toml.table $
    ["id"        Toml..= amdId x] ++
    ["modified"  Toml..= y | Just y <- [amdModified x]] ++
    ["date"      Toml..= y | Just y <- [amdPublished x]] ++
    ["capec"     Toml..= amdCAPECs x | not (null (amdCAPECs x))] ++
    ["cwe"       Toml..= amdCWEs x | not (null (amdCWEs x))] ++
    ["keywords"  Toml..= amdKeywords x | not (null (amdKeywords x))] ++
    ["aliases"   Toml..= amdAliases x | not (null (amdAliases x))] ++
    ["related"   Toml..= amdRelated x | not (null (amdRelated x))]

instance Toml.FromValue Affected where
  fromValue = Toml.parseTableFromValue $
   do package   <- Toml.reqKey "package"
      cvss      <- Toml.reqKey "cvss" -- TODO validate CVSS format
      os        <- Toml.optKey "os"
      arch      <- Toml.optKey "arch"
      decls     <- maybe [] Map.toList <$> Toml.optKey "declarations"
      versions  <- Toml.reqKey "versions"
      pure $ Affected
        { affectedPackage = package
        , affectedCVSS = cvss
        , affectedVersions = versions
        , affectedArchitectures = arch
        , affectedOS = os
        , affectedDeclarations = decls
        }

instance Toml.ToValue Affected where
  toValue = Toml.defaultTableToValue

instance Toml.ToTable Affected where
  toTable x = Toml.table $
    [ "package" Toml..= affectedPackage x
    , "cvss"    Toml..= affectedCVSS x
    , "versions" Toml..= affectedVersions x
    ] ++
    [ "os"   Toml..= y | Just y <- [affectedOS x]] ++
    [ "arch" Toml..= y | Just y <- [affectedArchitectures x]] ++
    [ "declarations" Toml..= asTable (affectedDeclarations x) | not (null (affectedDeclarations x))]
    where
      asTable kvs = Map.fromList [(T.unpack k, v) | (k,v) <- kvs]

instance Toml.FromValue AffectedVersionRange where
  fromValue = Toml.parseTableFromValue $
   do introduced <- Toml.reqKey "introduced"
      fixed      <- Toml.optKey "fixed"
      pure AffectedVersionRange {
        affectedVersionRangeIntroduced = introduced,
        affectedVersionRangeFixed = fixed
        }

instance Toml.ToValue AffectedVersionRange where
  toValue = Toml.defaultTableToValue

instance Toml.ToTable AffectedVersionRange where
  toTable x = Toml.table $
    ("introduced" Toml..= affectedVersionRangeIntroduced x) :
    ["fixed" Toml..= y | Just y <- [affectedVersionRangeFixed x]]


instance Toml.FromValue HsecId where
  fromValue v =
   do s <- Toml.fromValue v
      case parseHsecId s of
        Nothing -> Toml.failAt (Toml.valueAnn v) "invalid HSEC-ID: expected HSEC-[0-9]{4,}-[0-9]{4,}"
        Just x -> pure x

instance Toml.ToValue HsecId where
  toValue = Toml.toValue . printHsecId

instance Toml.FromValue CAPEC where
  fromValue v = CAPEC <$> Toml.fromValue v

instance Toml.ToValue CAPEC where
  toValue (CAPEC x) = Toml.toValue x

instance Toml.FromValue CWE where
  fromValue v = CWE <$> Toml.fromValue v

instance Toml.ToValue CWE where
  toValue (CWE x) = Toml.toValue x

instance Toml.FromValue Keyword where
  fromValue v = Keyword <$> Toml.fromValue v

instance Toml.ToValue Keyword where
  toValue (Keyword x) = Toml.toValue x

-- | Get a datetime with the timezone defaulted to UTC and the time defaulted to midnight
getDefaultedZonedTime :: Toml.Value' l -> Toml.Matcher l ZonedTime
getDefaultedZonedTime (Toml.ZonedTime' _ x) = pure x
getDefaultedZonedTime (Toml.LocalTime' _ x) = pure (ZonedTime x utc)
getDefaultedZonedTime (Toml.Day' _       x) = pure (ZonedTime (LocalTime x midnight) utc)
getDefaultedZonedTime v                     = Toml.failAt (Toml.valueAnn v) "expected a date with optional time and timezone"

instance Toml.FromValue Reference where
  fromValue = Toml.parseTableFromValue $
   do refType <- Toml.reqKey "type"
      url     <- Toml.reqKey "url"
      pure (Reference refType url)

instance Toml.FromValue ReferenceType where
  fromValue (Toml.Text' _ refTypeStr)
    | Just a <- lookup refTypeStr (fmap swap referenceTypes) = pure a
  fromValue v =
    Toml.failAt (Toml.valueAnn v) $
      "reference.type should be one of: " ++ intercalate ", " (T.unpack . snd <$> referenceTypes)

instance Toml.ToValue Reference where
  toValue = Toml.defaultTableToValue

instance Toml.ToTable Reference where
  toTable x = Toml.table
    [ "type" Toml..= fromMaybe "UNKNOWN" (lookup (referencesType x) referenceTypes)
    , "url" Toml..= referencesUrl x
    ]

instance Toml.FromValue OS where
  fromValue v =
   do s <- Toml.fromValue v
      case s :: String of
        "darwin" -> pure MacOS
        "freebsd" -> pure FreeBSD
        "linux" -> pure Linux
        "linux-android" -> pure Android
        "mingw32" -> pure Windows
        "netbsd" -> pure NetBSD
        "openbsd" -> pure OpenBSD
        other -> Toml.failAt (Toml.valueAnn v) ("Invalid OS: " ++ show other)

instance Toml.ToValue OS where
  toValue x =
    Toml.toValue $
    case x of
      MacOS -> "darwin" :: String
      FreeBSD -> "freebsd"
      Linux -> "linux"
      Android -> "linux-android"
      Windows -> "mingw32"
      NetBSD -> "netbsd"
      OpenBSD -> "openbsd"

instance Toml.FromValue Architecture where
  fromValue v =
   do s <- Toml.fromValue v
      case s :: String of
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
        other -> Toml.failAt (Toml.valueAnn v) ("Invalid architecture: " ++ show other)

instance Toml.ToValue Architecture where
  toValue x =
    Toml.toValue $
    case x of
        AArch64 -> "aarch64" :: String
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

instance Toml.FromValue Version where
  fromValue v =
   do s <- Toml.fromValue v
      case eitherParsec s of
        Left err -> Toml.failAt (Toml.valueAnn v) ("parse error in version: " ++ err)
        Right affected -> pure affected

instance Toml.ToValue Version where
  toValue = Toml.toValue . Pretty.render . pretty

instance Toml.FromValue VersionRange where
  fromValue v =
   do s <- Toml.fromValue v
      case eitherParsec s of
        Left err -> Toml.failAt (Toml.valueAnn v) ("parse error in version range: " ++ err)
        Right affected -> pure affected

instance Toml.ToValue VersionRange where
  toValue = Toml.toValue . Pretty.render . pretty

instance Toml.FromValue CVSS.CVSS where
  fromValue v =
    do s <- Toml.fromValue v
       case CVSS.parseCVSS s of
         Left err -> Toml.failAt (Toml.valueAnn v) ("parse error in cvss: " ++ show err)
         Right cvss -> pure cvss

instance Toml.ToValue CVSS.CVSS where
  toValue = Toml.toValue . CVSS.cvssVectorString

-- | A solution to an awkward problem: how to delete the TOML
-- block.  We parse into this type to get the source range of
-- the first block element.  We can use it to delete the lines
-- from the input.
--
newtype FirstSourceRange = FirstSourceRange (First SourceRange)
  deriving (Show, Semigroup, Monoid)

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
