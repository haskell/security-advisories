{-# LANGUAGE DerivingVia, OverloadedStrings #-}

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
  , ComponentIdentifier(..)
  , GHCComponent(..)
  , ghcComponentToText
  , ghcComponentFromText
  )
  where

import Data.Text (Text)
import Data.Time (UTCTime)
import Distribution.Types.Version (Version)
import Distribution.Types.VersionRange (VersionRange)

import Text.Pandoc.Definition (Pandoc)

import Security.Advisories.Core.HsecId (HsecId)
import qualified Security.CVSS as CVSS
import Security.OSV (Reference)

data Advisory = Advisory
  { advisoryId :: HsecId
  , advisoryModified :: UTCTime
  , advisoryPublished :: UTCTime
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

data ComponentIdentifier = Hackage Text | GHC GHCComponent
  deriving stock (Show, Eq)

-- Keep this list in sync with the 'ghcComponentFromText' below
data GHCComponent = GHCCompiler | GHCi | GHCRTS | GHCPkg | RunGHC | IServ | HP2PS | HPC | HSC2HS | Haddock
  deriving stock (Show, Eq, Enum, Bounded)

ghcComponentToText :: GHCComponent -> Text
ghcComponentToText c = case c of
  GHCCompiler -> "ghc"
  GHCi -> "ghci"
  GHCRTS -> "rts"
  GHCPkg -> "ghc-pkg"
  RunGHC -> "runghc"
  IServ -> "ghc-iserv"
  HP2PS -> "hp2ps"
  HPC -> "hpc"
  HSC2HS -> "hsc2hs"
  Haddock -> "haddock"

ghcComponentFromText :: Text -> Maybe GHCComponent
ghcComponentFromText c = case c of
  "ghc" -> Just GHCCompiler
  "ghci" -> Just GHCi
  "rts" -> Just GHCRTS
  "ghc-pkg" -> Just GHCPkg
  "runghc" -> Just RunGHC
  "ghc-iserv" -> Just IServ
  "hp2ps" -> Just HP2PS
  "hpc" -> Just HPC
  "hsc2hs" -> Just HSC2HS
  "haddock" -> Just Haddock
  _ -> Nothing

-- | An affected package (or package component).  An 'Advisory' must
-- mention one or more packages.
data Affected = Affected
  { affectedComponentIdentifier :: ComponentIdentifier
  , affectedCVSS :: CVSS.CVSS
  , affectedVersions :: [AffectedVersionRange]
  , affectedArchitectures :: Maybe [Architecture]
  , affectedOS :: Maybe [OS]
  , affectedDeclarations :: [(Text, VersionRange)]
  }
  deriving stock (Eq, Show)

newtype CAPEC = CAPEC {unCAPEC :: Integer}
  deriving stock (Eq, Show)

newtype CWE = CWE {unCWE :: Integer}
  deriving stock (Eq, Show)

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
  deriving stock (Eq, Show, Enum, Bounded)

data OS
  = Windows
  | MacOS
  | Linux
  | FreeBSD
  | Android
  | NetBSD
  | OpenBSD
  deriving stock (Eq, Show, Enum, Bounded)

newtype Keyword = Keyword {unKeyword :: Text}
  deriving stock (Eq, Ord)
  deriving (Show) via Text

data AffectedVersionRange = AffectedVersionRange
  { affectedVersionRangeIntroduced :: Version,
    affectedVersionRangeFixed :: Maybe Version
  }
  deriving stock (Eq, Show)
