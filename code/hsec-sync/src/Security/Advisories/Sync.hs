{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}

module Security.Advisories.Sync
  ( Snapshot (..),
    SnapshotUrl (..),
    defaultSnapshot,
    githubSnapshot,
    SyncStatus (..),
    sync,
    RepositoryStatus (..),
    status,
  )
where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, withExceptT)
import Security.Advisories.Sync.Snapshot
import Security.Advisories.Sync.Url

data Snapshot = Snapshot
  { snapshotRoot :: FilePath,
    snapshotUrl :: SnapshotUrl
  }

defaultSnapshot :: Snapshot
defaultSnapshot =
  githubSnapshot
    "security-advisories"
    "https://github.com/haskell/security-advisories"
    "generated/snapshot-export"

githubSnapshot :: FilePath -> String -> String -> Snapshot
githubSnapshot root repoUrl repoBranch =
  Snapshot
    { snapshotRoot = root,
      snapshotUrl = SnapshotUrl $ ensureFile (mkUrl [repoUrl, "archive/refs/heads", repoBranch]) <> ".tar.gz"
    }

data SyncStatus
  = Created
  | Updated
  | AlreadyUpToDate
  deriving stock (Eq, Show)

sync :: Snapshot -> IO (Either String SyncStatus)
sync s =
  runExceptT $ do
    snapshotStatus <- liftIO $ snapshotRepositoryStatus $ snapshotRoot s
    ensuredStatus <- withExceptT explainSnapshotError $ ensureSnapshot (snapshotRoot s) (snapshotUrl s) snapshotStatus
    case ensuredStatus of
      SnapshotRepositoryCreated ->
        return Created
      SnapshotRepositoryExisting -> do
        repoStatus <- liftIO $ status' s snapshotStatus
        if repoStatus == DirectoryOutDated
          then do
            withExceptT explainSnapshotError $ overwriteSnapshot (snapshotRoot s) (snapshotUrl s)
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
  status' s =<< snapshotRepositoryStatus (snapshotRoot s)

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
          update <- runExceptT $ latestUpdate $ snapshotUrl s
          return $
            case update of
              Right latestETag | latestETag == etag info ->
                DirectoryUpToDate
              _ ->
                DirectoryOutDated
