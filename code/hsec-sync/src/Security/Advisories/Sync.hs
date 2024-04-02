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
import Control.Monad.Trans.Except (runExceptT, withExceptT)
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
    snapshotStatus <- liftIO $ snapshotRepositoryStatus s
    ensuredStatus <- withExceptT explainSnapshotError $ ensureSnapshot s snapshotStatus
    case ensuredStatus of
      SnapshotRepositoryCreated ->
        return Created
      SnapshotRepositoryExisting -> do
        repoStatus <- liftIO $ status' s snapshotStatus
        if repoStatus == DirectoryOutDated
          then do
            withExceptT explainSnapshotError $ overwriteSnapshot s
            return Updated
          else return AlreadyUpToDate

data RepositoryStatus
  = DirectoryMissing
  | -- | Used when expected files/directories are missing or not readable
    DirectoryIncoherent
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
