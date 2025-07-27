module Security.Advisories.Queries
  ( listVersionAffectedBy
  , listVersionRangeAffectedBy
  )
where

import Control.Monad.IO.Class (MonadIO)
import Distribution.Types.Version (Version)
import Distribution.Types.VersionRange (VersionRange)
import Validation (Validation(..))

import Security.Advisories.Core.Advisory
import Security.Advisories.Filesystem
import Security.Advisories.Parse

type QueryResult = Validation [(FilePath, ParseAdvisoryError)] [Advisory]

-- | List the advisories matching a component and a version
listVersionAffectedBy
  :: MonadIO m
  => FilePath -> ComponentIdentifier -> Version -> m QueryResult
listVersionAffectedBy = listAffectedByHelper isVersionAffectedBy

-- | List the advisories matching a component and a version range
listVersionRangeAffectedBy
  :: (MonadIO m)
  => FilePath -> ComponentIdentifier -> VersionRange -> m QueryResult
listVersionRangeAffectedBy = listAffectedByHelper isVersionRangeAffectedBy

-- | Helper function for 'listVersionAffectedBy' and 'listVersionRangeAffectedBy'
listAffectedByHelper
  :: (MonadIO m)
  => (ComponentIdentifier -> a -> Advisory -> Bool) -> FilePath -> ComponentIdentifier -> a -> m QueryResult
listAffectedByHelper checkAffectedBy root queryComponent queryVersionish =
  fmap (filter (checkAffectedBy queryComponent queryVersionish)) <$>
    listAdvisories root
