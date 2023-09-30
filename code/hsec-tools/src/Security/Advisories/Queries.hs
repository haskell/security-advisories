{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Security.Advisories.Queries
  ( listVersionRangeAffectedBy
  , isVersionRangeAffectedBy
  , parseVersionRange
  )
where

import Control.Monad (forM_)
import Data.Bifunctor (first)
import System.Exit (exitFailure)
import System.IO (stderr, hPrint)

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Distribution.Parsec (eitherParsec)
import Distribution.Types.VersionInterval (asVersionIntervals)
import Distribution.Types.VersionRange (VersionRange, anyVersion, earlierVersion, intersectVersionRanges, noVersion, orLaterVersion, unionVersionRanges)
import Validation (Validation(..))

import Security.Advisories.Definition
import Security.Advisories.Filesystem

-- | Check whether a package and a version range is concerned by an advisory
isVersionRangeAffectedBy :: Text -> VersionRange -> Advisory -> Bool
isVersionRangeAffectedBy queryPackageName queryVersionRange =
    any checkAffected . advisoryAffected
    where
        checkAffected :: Affected -> Bool
        checkAffected affected =
          queryPackageName == affectedPackage affected
            && isSomeVersion (fromAffected affected `intersectVersionRanges` queryVersionRange)

        fromAffected :: Affected -> VersionRange
        fromAffected = foldr (unionVersionRanges . fromAffectedVersionRange) noVersion . affectedVersions

        fromAffectedVersionRange :: AffectedVersionRange -> VersionRange
        fromAffectedVersionRange avr = intersectVersionRanges
          (orLaterVersion (affectedVersionRangeIntroduced avr))
          (maybe anyVersion earlierVersion (affectedVersionRangeFixed avr))

        isSomeVersion :: VersionRange -> Bool
        isSomeVersion range
            | [] <- asVersionIntervals range = False
            | otherwise = True

-- | List the advisories matching package/version range
listVersionRangeAffectedBy :: FilePath -> Text -> VersionRange -> IO [Advisory]
listVersionRangeAffectedBy root queryPackageName queryVersionRange =
    listAdvisories root >>= \case
      Failure errors -> do
        T.hPutStrLn stderr "Cannot parse some advisories"
        forM_ errors $
          hPrint stderr
        exitFailure
      Success advisories ->
        return $ filter (isVersionRangeAffectedBy queryPackageName queryVersionRange) advisories

-- | Parse 'VersionRange' as given to the CLI
parseVersionRange :: Maybe Text -> Either Text VersionRange
parseVersionRange  = maybe (return anyVersion) (first T.pack . eitherParsec . T.unpack)
