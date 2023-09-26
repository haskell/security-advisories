{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Security.Advisories.Queries
  ( isAffectedBy
  , parseVersionRange
  , listAffectedBy
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
import Distribution.Types.VersionRange (VersionRange, VersionRangeF(..), anyVersion, earlierVersion, intersectVersionRanges, majorUpperBound, orLaterVersion, projectVersionRange)
import Validation (Validation(..))

import Security.Advisories.Definition
import Security.Advisories.Filesystem

-- | Check whether a package and a version range is concerned by an advisory
isAffectedBy :: Text -> VersionRange -> Advisory -> Bool
isAffectedBy queryPackageName queryVersionRange =
    any checkAffected . advisoryAffected
  where checkAffected :: Affected -> Bool
        checkAffected affected =
          queryPackageName == affectedPackage affected
          && any
              (intersectsWith (projectVersionRange queryVersionRange) . projectVersionRange . mkVersionRange)
              (affectedVersions affected)
        mkVersionRange :: AffectedVersionRange -> VersionRange
        mkVersionRange x =
          case affectedVersionRangeFixed x of
            Nothing ->
              orLaterVersion (affectedVersionRangeIntroduced x)
            Just affectedVersionRangeFixed' ->
              orLaterVersion (affectedVersionRangeIntroduced x) `intersectVersionRanges` earlierVersion affectedVersionRangeFixed'
        intersectsWith :: VersionRangeF VersionRange -> VersionRangeF VersionRange -> Bool
        intersectsWith left right =
          case (left, right) of
            (ThisVersionF x, ThisVersionF y) -> x == y
            (ThisVersionF x, LaterVersionF y) -> x < y
            (ThisVersionF x, OrLaterVersionF y) -> x >= y
            (ThisVersionF x, EarlierVersionF y) -> x < y
            (ThisVersionF x, OrEarlierVersionF y) -> x <= y
            (LaterVersionF x, ThisVersionF y) -> x < y
            (LaterVersionF _, LaterVersionF _) -> True
            (LaterVersionF _, OrLaterVersionF _) -> True
            (LaterVersionF x, EarlierVersionF y) -> x < y
            (LaterVersionF x, OrEarlierVersionF y) -> x < y
            (OrLaterVersionF x, ThisVersionF y) -> x <= y
            (OrLaterVersionF _, LaterVersionF _) -> True
            (OrLaterVersionF _, OrLaterVersionF _) -> True
            (OrLaterVersionF x, EarlierVersionF y) -> x < y
            (OrLaterVersionF x, OrEarlierVersionF y) -> x <= y
            (EarlierVersionF x, ThisVersionF y) -> x > y
            (EarlierVersionF x, LaterVersionF y) -> x > y
            (EarlierVersionF x, OrLaterVersionF y) -> x > y
            (EarlierVersionF _, EarlierVersionF _) -> True
            (EarlierVersionF _, OrEarlierVersionF _) -> True
            (OrEarlierVersionF x, ThisVersionF y) -> x >= y
            (OrEarlierVersionF x, LaterVersionF y) -> x > y
            (OrEarlierVersionF x, OrLaterVersionF y) -> x >= y
            (OrEarlierVersionF _, EarlierVersionF _) -> True
            (OrEarlierVersionF _, OrEarlierVersionF _) -> True
            (MajorBoundVersionF x, _) -> intersectsWith (OrLaterVersionF x) right && intersectsWith (EarlierVersionF $ majorUpperBound x) right
            (UnionVersionRangesF x y, _) -> intersectsWith (projectVersionRange x) right || intersectsWith (projectVersionRange y) right
            (IntersectVersionRangesF x y, _) -> intersectsWith (projectVersionRange x) right && intersectsWith (projectVersionRange y) right
            (_, UnionVersionRangesF x y) -> intersectsWith left (projectVersionRange x) || intersectsWith left (projectVersionRange y)
            (_, IntersectVersionRangesF x y) -> intersectsWith left (projectVersionRange x) && intersectsWith left (projectVersionRange y)
            (_, MajorBoundVersionF x) -> intersectsWith left (OrLaterVersionF x) && intersectsWith left (EarlierVersionF $ majorUpperBound x)

-- | Parse 'VersionRange' as given to the CLI
parseVersionRange :: Maybe Text -> Either Text VersionRange
parseVersionRange  = maybe (return anyVersion) (first T.pack . eitherParsec . T.unpack)

-- | List the advisories matching package/version range
listAffectedBy :: FilePath -> Text -> VersionRange -> IO [Advisory]
listAffectedBy root queryPackageName queryVersionRange = do
  advisories <-
    listAdvisories root >>= \case
      Failure errors -> do
        T.hPutStrLn stderr "Cannot parse some advisories"
        forM_ errors $
          hPrint stderr
        exitFailure
      Success advisories ->
        return advisories


  return $ filter (isAffectedBy queryPackageName queryVersionRange) advisories
