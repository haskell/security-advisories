{-# LANGUAGE DerivingVia #-}

module Security.Advisories.Definition
  ( Advisory(..)
    -- * Supporting types
  , CWE(..)
  , Architecture(..)
  , AffectedVersionRange(..)
  , OS(..)
  , Keyword(..)
  )
  where

import Data.Text (Text)
import Data.Time (ZonedTime)
import Distribution.Types.VersionRange (VersionRange)

import Text.Pandoc.Definition (Pandoc)

import Security.OSV (Reference)

data Advisory = Advisory
  { advisoryId :: Text
  , advisoryModified :: ZonedTime
  , advisoryPublished :: ZonedTime
  , advisoryPackage :: Text
  , advisoryCWEs :: [CWE]
  , advisoryKeywords :: [Keyword]
  , advisoryAliases :: [Text]
  , advisoryCVSS :: Text
  , advisoryVersions :: [AffectedVersionRange]
  , advisoryArchitectures :: Maybe [Architecture]
  , advisoryOS :: Maybe [OS]
  , advisoryNames :: [(Text, VersionRange)]
  , advisoryReferences :: [Reference]
  , advisoryPandoc :: Pandoc  -- ^ Parsed document, without TOML front matter
  , advisoryHtml :: Text
  , advisorySummary :: Text
  }
  deriving stock (Show)

newtype CWE = CWE {unCWE :: Integer}
  deriving stock (Show)

data Architecture
  = AArch64
  | Alpha
  | Arm
  | HPPA
  | HPPA1_1
  | I386
  | IA64
  | M68K
  | MIPS
  | MIPSEB
  | MIPSEL
  | NIOS2
  | PowerPC
  | PowerPC64
  | PowerPC64LE
  | RISCV32
  | RISCV64
  | RS6000
  | S390
  | S390X
  | SH4
  | SPARC
  | SPARC64
  | VAX
  | X86_64
  deriving stock (Show)

data OS
  = Windows
  | MacOS
  | Linux
  | FreeBSD
  | Android
  | NetBSD
  | OpenBSD
  deriving stock (Show)

newtype Keyword = Keyword Text
  deriving stock (Eq, Ord)
  deriving (Show) via Text

data AffectedVersionRange = AffectedVersionRange
  { affectedVersionRangeIntroduced :: Text,
    affectedVersionRangeFixed :: Maybe Text
  }
  deriving stock (Show)
