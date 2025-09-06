{-# LANGUAGE CPP #-}

{-|

Helpers for the /security-advisories/ file system.

Top-level functions that take a @FilePath@ expect the path to the
top-level directory of the /security-advisories/ repository (i.e.
it must have the @advisories/@ subdirectory).

-}
module Security.Advisories.Filesystem
  (
    dirNameAdvisories
  , dirNameReserved
  , dirNamePublished
  , isSecurityAdvisoriesRepo
  , getReservedIds
  , getAdvisoryIds
  , getAllocatedIds
  , greatestId
  , getGreatestId
  , forReserved
  , forAdvisory
  , listAdvisories
  , advisoryFromFile
  , parseComponentIdentifier
  ) where

#if MIN_VERSION_base(4,18,0)
#else
import Control.Applicative (liftA2)
#endif
import Data.Bifunctor (bimap)
import Data.Foldable (fold)
import Data.Semigroup (Max(Max, getMax))
import Data.Traversable (for)

import Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import System.FilePath ((</>), dropExtension, splitDirectories)
import System.Directory (doesDirectoryExist, listDirectory)
import Validation (Validation (..))

import Security.Advisories (Advisory, AttributeOverridePolicy (NoOverrides), OutOfBandAttributes (..), ParseAdvisoryError, parseAdvisory, ComponentIdentifier(..))
import Security.Advisories.Core.HsecId (HsecId, parseHsecId, placeholder)
import Security.Advisories.Git(firstAppearanceCommitDate, getAdvisoryGitInfo, lastModificationCommitDate)
import Control.Monad.Except (runExceptT, ExceptT (ExceptT), withExceptT)
import Security.Advisories.Parse (OOBError(GitHasNoOOB, PathHasNoComponentIdentifier))
import Security.Advisories.Core.Advisory (ghcComponentFromText)

dirNameAdvisories :: FilePath
dirNameAdvisories = "advisories"

dirNameReserved :: FilePath
dirNameReserved = "reserved"

dirNamePublished :: FilePath
dirNamePublished = "published"

-- | Check whether the directory appears to be the root of a
-- /security-advisories/ filesystem.  Only checks that the
-- @advisories@ subdirectory exists.
--
isSecurityAdvisoriesRepo :: FilePath -> IO Bool
isSecurityAdvisoriesRepo path =
  doesDirectoryExist (path </> dirNameAdvisories)


-- | Get a list of reserved HSEC IDs.  The order is unspecified.
--
getReservedIds :: FilePath -> IO [HsecId]
getReservedIds root =
  forReserved root (\_ hsid -> pure [hsid])

-- | Get a list of used IDs (does not include reserved IDs)
-- There may be duplicates and the order is unspecified.
--
getAdvisoryIds :: FilePath -> IO [HsecId]
getAdvisoryIds root =
  forAdvisory root (\_ hsid -> pure [hsid])

-- | Get all allocated IDs, including reserved IDs.
-- There may be duplicates and the order is unspecified.
--
getAllocatedIds :: FilePath -> IO [HsecId]
getAllocatedIds root =
  liftA2 (<>)
    (getAdvisoryIds root)
    (getReservedIds root)

-- | Return the greatest ID in a collection of IDs.  If the
-- collection is empty, return the 'placeholder'.
--
greatestId :: (Foldable t) => t HsecId -> HsecId
greatestId = getMax . foldr ((<>) . Max) (Max placeholder)

-- | Return the greatest ID in the database, including reserved IDs.
-- If there are IDs in the database, returns the 'placeholder'.
--
getGreatestId :: FilePath -> IO HsecId
getGreatestId = fmap greatestId . getAllocatedIds


-- | Invoke a callback for each HSEC ID in the reserved
-- directory.  The results are combined monoidally.
--
forReserved
  :: (MonadIO m, Monoid r)
  => FilePath -> (FilePath -> HsecId -> m r) -> m r
forReserved root =
  _forFilesByYear (root </> dirNameAdvisories </> dirNameReserved)

-- | Invoke a callback for each HSEC ID under each of the advisory
-- subdirectories, excluding the @reserved@ directory.  The results
-- are combined monoidally.
--
-- The same ID could appear multiple times.  In particular, the callback
-- is invoked for symbolic links as well as regular files.
--
forAdvisory
  :: (MonadIO m, Monoid r)
  => FilePath -> (FilePath -> HsecId -> m r) -> m r
forAdvisory root =
  _forFilesByYear (root </> dirNameAdvisories </> dirNamePublished)

-- | List parsed Advisories
listAdvisories
  :: (MonadIO m)
  => FilePath -> m (Validation [(FilePath, ParseAdvisoryError)] [Advisory])
listAdvisories root =
  forAdvisory root $ \advisoryPath _advisoryId ->
    bimap (\err -> [(advisoryPath, err)]) pure
    <$> advisoryFromFile advisoryPath

-- | Parse an advisory from a file system path
advisoryFromFile
  :: (MonadIO m)
  => FilePath -> m (Validation ParseAdvisoryError Advisory)
advisoryFromFile advisoryPath = do
  oob <- runExceptT $ do
   ecosystem <- parseComponentIdentifier advisoryPath
   withExceptT GitHasNoOOB $ do
    gitInfo <- ExceptT $ liftIO $ getAdvisoryGitInfo advisoryPath
    pure OutOfBandAttributes
      { oobPublished = firstAppearanceCommitDate gitInfo
      , oobModified = lastModificationCommitDate gitInfo
      , oobComponentIdentifier = ecosystem
      }
  fileContent <- liftIO $ T.readFile advisoryPath
  pure
    $ either Failure Success
    $ parseAdvisory NoOverrides oob fileContent

_forFilesByYear
  :: (MonadIO m, Monoid r)
  => FilePath  -- ^ (sub)directory name
  -> (FilePath -> HsecId -> m r)
  -> m r
_forFilesByYear root go = do
  yearsFile <- liftIO $ listDirectory root
  fmap (foldMap fold) $
    for yearsFile $ \year -> do
      let yearDir = root </> year
      isYear <- liftIO $ doesDirectoryExist yearDir
      if isYear
        then do
          files <- liftIO $ listDirectory yearDir
          for files $ \file ->
            case parseHsecId ("HSEC-" <> year <> "-" <> dropExtension file) of
              Nothing -> pure mempty
              Just hsid -> go (yearDir </> file) hsid
        else pure mempty

parseComponentIdentifier :: Monad m => FilePath -> ExceptT OOBError m (Maybe ComponentIdentifier)
parseComponentIdentifier fp = ExceptT . pure $ case drop 1 $ reverse $ splitDirectories fp of
  package : "hackage" : _ -> pure (Just $ Hackage $ T.pack package)
  component : "ghc" : _ | Just ghc <- ghcComponentFromText (T.pack component) -> pure (Just $ GHC ghc)
  _ : _ : "advisories" : _ -> Left PathHasNoComponentIdentifier
  _ -> pure Nothing
