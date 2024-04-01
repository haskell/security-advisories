{-# LANGUAGE DerivingStrategies #-}

module Security.Advisories.Sync
  ( Snapshot (..),
    defaultRepository,
    SyncStatus (..),
    sync,
    RepositoryStatus (..),
    status,
  )
where

import Security.Advisories.Sync.Atom
import Security.Advisories.Sync.Snapshot

data SyncStatus
  = Created
  | Updated
  | AlreadyUpToDate
  deriving stock (Eq, Show)

sync :: Snapshot -> IO (Either String SyncStatus)
sync s = do
  snapshotStatus <- snapshotRepositoryStatus s
  ensured <- ensureSnapshot s snapshotStatus
  let mkSnapshotError = Left . explainSnapshotError
  case ensured of
    Left e -> return $ mkSnapshotError e
    Right ensuredStatus ->
      case ensuredStatus of
        SnapshotRepositoryCreated ->
          return $ Right Created
        SnapshotRepositoryExisting -> do
          repoStatus <- status' s snapshotStatus
          if repoStatus == DirectoryOutDated
            then either mkSnapshotError (const $ Right Updated) <$> overwriteSnapshot s
            else return $ Right AlreadyUpToDate

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
status' s snapshotStatus = do
  case snapshotStatus of
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
      repositoryUrl = "https://snapshothub.com/haskell/security-advisories",
      repositoryBranch = "generated/snapshot-export"
    }
