{-# LANGUAGE DerivingVia #-}

module Security.Advisories.Core.Advisory
  ( Advisory(..)
    -- * Supporting types
  , Affected(..)
  , CAPEC(..)
  , CWE(..)
  , Architecture(..)
  , AffectedVersionRange(..)
  , OS(..)
  , Keyword(..)
  )
  where

import Data.Text (Text)
import Data.Time (ZonedTime)
import Distribution.Types.Version (Version)
import Distribution.Types.VersionRange (VersionRange)

import Text.Pandoc.Definition (Pandoc)

import Security.Advisories.Core.HsecId
import qualified Security.CVSS as CVSS
import Security.OSV (Reference)

data Advisory = Advisory
  { advisoryId :: HsecId
  , advisoryModified :: ZonedTime
  , advisoryPublished :: ZonedTime
  , advisoryCAPECs :: [CAPEC]
  , advisoryCWEs :: [CWE]
  , advisoryKeywords :: [Keyword]
  , advisoryAliases :: [Text]
  , advisoryRelated :: [Text]
  , advisoryAffected :: [Affected]
  , advisoryReferences :: [Reference]
  , advisoryPandoc :: Pandoc  -- ^ Parsed document, without TOML front matter
  , advisoryHtml :: Text
  , advisorySummary :: Text
    -- ^ A one-line, English textual summary of the vulnerability
  , advisoryDetails :: Text
    -- ^ Details of the vulnerability (CommonMark), without TOML front matter
  }
  deriving stock (Show)

-- | An affected package (or package component).  An 'Advisory' must
-- mention one or more packages.
data Affected = Affected
  { affectedPackage :: Text
  , affectedCVSS :: CVSS.CVSS
  , affectedVersions :: [AffectedVersionRange]
  , affectedArchitectures :: Maybe [Architecture]
  , affectedOS :: Maybe [OS]
  , affectedDeclarations :: [(Text, VersionRange)]
  }
  deriving stock (Show)

newtype CAPEC = CAPEC {unCAPEC :: Integer}
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
  { affectedVersionRangeIntroduced :: Version,
    affectedVersionRangeFixed :: Maybe Version
  }
  deriving stock (Show)
