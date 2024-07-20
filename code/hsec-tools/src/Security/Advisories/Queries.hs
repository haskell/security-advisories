module Security.Advisories.Queries
  ( listVersionAffectedBy
  , listVersionRangeAffectedBy
  , isVersionAffectedBy
  , isVersionRangeAffectedBy
  )
where

import Control.Monad.IO.Class (MonadIO)
import Data.Text (Text)
import Distribution.Types.Version (Version)
import Distribution.Types.VersionInterval (asVersionIntervals)
import Distribution.Types.VersionRange (VersionRange, anyVersion, earlierVersion, intersectVersionRanges, noVersion, orLaterVersion, unionVersionRanges, withinRange)
import Validation (Validation(..))

import Security.Advisories.Core.Advisory
import Security.Advisories.Filesystem
import Security.Advisories.Parse

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
      checkAffected affected = case affectedComponentIdentifier affected of
        Hackage pkg -> queryPackageName == pkg && checkWithRange queryVersionish (fromAffected affected)
        -- TODO: support GHC ecosystem query, e.g. by adding a cli flag
        _ -> False

      fromAffected :: Affected -> VersionRange
      fromAffected = foldr (unionVersionRanges . fromAffectedVersionRange) noVersion . affectedVersions

      fromAffectedVersionRange :: AffectedVersionRange -> VersionRange
      fromAffectedVersionRange avr = intersectVersionRanges
        (orLaterVersion (affectedVersionRangeIntroduced avr))
        (maybe anyVersion earlierVersion (affectedVersionRangeFixed avr))

type QueryResult = Validation [(FilePath, ParseAdvisoryError)] [Advisory]

-- | List the advisories matching a package name and a version
listVersionAffectedBy
  :: MonadIO m
  => FilePath -> Text -> Version -> m QueryResult
listVersionAffectedBy = listAffectedByHelper isVersionAffectedBy

-- | List the advisories matching a package name and a version range
listVersionRangeAffectedBy
  :: (MonadIO m)
  => FilePath -> Text -> VersionRange -> m QueryResult
listVersionRangeAffectedBy = listAffectedByHelper isVersionRangeAffectedBy

-- | Helper function for 'listVersionAffectedBy' and 'listVersionRangeAffectedBy'
listAffectedByHelper
  :: (MonadIO m)
  => (Text -> a -> Advisory -> Bool) -> FilePath -> Text -> a -> m QueryResult
listAffectedByHelper checkAffectedBy root queryPackageName queryVersionish =
  fmap (filter (checkAffectedBy queryPackageName queryVersionish)) <$>
    listAdvisories root
