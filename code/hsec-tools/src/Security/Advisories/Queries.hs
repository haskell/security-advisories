module Security.Advisories.Queries
  ( listVersionAffectedBy
  , listVersionRangeAffectedBy
  )
where

import Control.Monad.IO.Class (MonadIO)
import Data.Text (Text)
import Distribution.Types.Version (Version)
import Distribution.Types.VersionRange (VersionRange)
import Validation (Validation(..))

import Security.Advisories.Core.Advisory
import Security.Advisories.Filesystem
import Security.Advisories.Parse

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
  => (ComponentIdentifier -> a -> Advisory -> Bool) -> FilePath -> Text -> a -> m QueryResult
listAffectedByHelper checkAffectedBy root queryPackageName queryVersionish =
  fmap (filter (checkAffectedBy (Hackage queryPackageName) queryVersionish)) <$>
    listAdvisories root
