{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Security.Advisories.Queries
  ( listVersionAffectedBy
  , listVersionRangeAffectedBy
  , isVersionAffectedBy
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
import Distribution.Types.Version (Version)
import Distribution.Types.VersionInterval (asVersionIntervals)
import Distribution.Types.VersionRange (VersionRange, anyVersion, earlierVersion, intersectVersionRanges, noVersion, orLaterVersion, unionVersionRanges, withinRange)
import Validation (Validation(..))

import Security.Advisories.Definition
import Security.Advisories.Filesystem

-- | Check whether a package and a version is concerned by an advisory
isVersionAffectedBy :: Text -> Version -> Advisory -> Bool
isVersionAffectedBy = isAffectedByHelper withinRange

-- | Check whether a package and a version range is concerned by an advisory
isVersionRangeAffectedBy :: Text -> VersionRange -> Advisory -> Bool
isVersionRangeAffectedBy = isAffectedByHelper $
  \queryVersionRange affectedVersionRange ->
    isSomeVersion (affectedVersionRange `intersectVersionRanges` queryVersionRange)
  where
    isSomeVersion :: VersionRange -> Bool
    isSomeVersion range
      | [] <- asVersionIntervals range = False
      | otherwise = True

-- | Helper function for 'isVersionAffectedBy' and 'isVersionRangeAffectedBy'
isAffectedByHelper :: (a -> VersionRange -> Bool) -> Text -> a -> Advisory -> Bool
isAffectedByHelper checkWithRange queryPackageName queryVersionish =
    any checkAffected . advisoryAffected
    where
      checkAffected :: Affected -> Bool
      checkAffected affected =
        queryPackageName == affectedPackage affected
          && checkWithRange queryVersionish (fromAffected affected)

      fromAffected :: Affected -> VersionRange
      fromAffected = foldr (unionVersionRanges . fromAffectedVersionRange) noVersion . affectedVersions

      fromAffectedVersionRange :: AffectedVersionRange -> VersionRange
      fromAffectedVersionRange avr = intersectVersionRanges
        (orLaterVersion (affectedVersionRangeIntroduced avr))
        (maybe anyVersion earlierVersion (affectedVersionRangeFixed avr))

-- | List the advisories matching a package name and a version
listVersionAffectedBy :: FilePath -> Text -> Version -> IO [Advisory]
listVersionAffectedBy = listAffectedByHelper isVersionAffectedBy

-- | List the advisories matching a package name and a version range
listVersionRangeAffectedBy :: FilePath -> Text -> VersionRange -> IO [Advisory]
listVersionRangeAffectedBy = listAffectedByHelper isVersionRangeAffectedBy

-- | Helper function for 'listVersionAffectedBy' and 'listVersionRangeAffectedBy'
listAffectedByHelper :: (Text -> a -> Advisory -> Bool) -> FilePath -> Text -> a -> IO [Advisory]
listAffectedByHelper checkAffectedBy root queryPackageName queryVersionish =
  listAdvisories root >>= \case
    Failure errors -> do
      T.hPutStrLn stderr "Cannot parse some advisories"
      forM_ errors $
        hPrint stderr
      exitFailure
    Success advisories ->
      return $ filter (checkAffectedBy queryPackageName queryVersionish) advisories

-- | Parse 'VersionRange' as given to the CLI
parseVersionRange :: Maybe Text -> Either Text VersionRange
parseVersionRange  = maybe (return anyVersion) (first T.pack . eitherParsec . T.unpack)
