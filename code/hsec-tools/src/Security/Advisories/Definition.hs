{-# LANGUAGE DerivingVia #-}

module Security.Advisories.Definition
  ( Advisory(..)
    -- * Supporting types
  , Affected(..)
  , CWE(..)
  , Architecture(..)
  , AffectedVersionRange(..)
  , VersionRangeTerminal(..)
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
  , advisoryCWEs :: [CWE]
  , advisoryKeywords :: [Keyword]
  , advisoryAliases :: [Text]
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
  , affectedCVSS :: Text -- TODO refine type
  , affectedVersions :: [AffectedVersionRange]
  , affectedArchitectures :: Maybe [Architecture]
  , affectedOS :: Maybe [OS]
  , affectedDeclarations :: [(Text, VersionRange)]
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

data VersionRangeTerminal
  = Limit Text  -- ^ closes a range without a fix
  | Fixed Text
  deriving (Show, Eq)

-- | Specify a version range.
--
-- In most cases, a range is either open (no fix yet) or closed via
-- the 'Fixed' terminal.  Scenarios that require 'Limit' include
-- those where a vulnerability has been introduced on multiple
-- branches.  For example, if an issue was introduced in 1.0.8 and
-- 1.1.2 (but 1.1 is unaffected), and a fix has not been released
-- for the 1.0.x series, then you need:
--
-- @
-- [ 'AffectedVersionRange' "1.0.8" (Just ('Limit' "1.1"))
-- , 'AffectedVersionRange' "1.1.2" Nothing ]
-- @
--
data AffectedVersionRange = AffectedVersionRange
  { affectedVersionRangeIntroduced :: Text
  , affectedVersionRangeTerminal :: Maybe VersionRangeTerminal
  }
  deriving stock (Show, Eq)
