{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}

module Security.Advisories.Sync
  ( Snapshot (..),
    defaultRepository,
    SyncStatus (..),
    sync,
    RepositoryStatus (..),
    status,
  )
where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Data.Either.Combinators (whenLeft)
import Security.Advisories.Sync.Atom
import Security.Advisories.Sync.Snapshot

data SyncStatus
  = Created
  | Updated
  | AlreadyUpToDate
  deriving stock (Eq, Show)

sync :: Snapshot -> IO (Either String SyncStatus)
sync s =
  runExceptT $ do
    let snapshotError = throwE . explainSnapshotError
    snapshotStatus <- liftIO $ snapshotRepositoryStatus s
    ensured <- liftIO $ ensureSnapshot s snapshotStatus
    ensuredStatus <- either snapshotError return ensured
    case ensuredStatus of
      SnapshotRepositoryCreated ->
        return Created
      SnapshotRepositoryExisting -> do
        repoStatus <- liftIO $ status' s snapshotStatus
        if repoStatus == DirectoryOutDated
          then do
            overwrittenStatus <- liftIO $ overwriteSnapshot s
            whenLeft overwrittenStatus snapshotError
            return Updated
          else return AlreadyUpToDate

data RepositoryStatus
  = DirectoryMissing
  | DirectoryIncoherent
  | DirectoryUpToDate
  | DirectoryOutDated
  deriving stock (Eq, Show)

status :: Snapshot -> IO RepositoryStatus
status s =
  status' s =<< snapshotRepositoryStatus s

status' :: Snapshot -> SnapshotRepositoryStatus -> IO RepositoryStatus
status' s =
  \case
    SnapshotDirectoryMissing ->
      return DirectoryMissing
    SnapshotDirectoryIncoherent ->
      return DirectoryIncoherent
    SnapshotDirectoryInitialized -> do
      snapshotInfo <- getDirectorySnapshotInfo $ snapshotRoot s
      case snapshotInfo of
        Left _ ->
          return DirectoryOutDated
        Right info -> do
          update <- latestUpdate (repositoryUrl s) (repositoryBranch s)
          return $
            if update == Right (lastModificationCommitDate info)
              then DirectoryUpToDate
              else DirectoryOutDated

defaultRepository :: Snapshot
defaultRepository =
  Snapshot
    { snapshotRoot = "security-advisories",
      repositoryUrl = "https://github.com/haskell/security-advisories",
      repositoryBranch = "generated/snapshot-export"
    }
