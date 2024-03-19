{-# LANGUAGE DerivingStrategies #-}

module Security.Advisories.Sync
  ( Repository (..),
    defaultRepository,
    SyncStatus (..),
    sync,
    RepositoryStatus (..),
    status,
  )
where

import Data.Time (zonedTimeToUTC)
import Security.Advisories.Sync.Atom
import Security.Advisories.Sync.Git

data SyncStatus
  = Created
  | Updated
  | AlreadyUpToDate
  deriving stock (Eq, Show)

sync :: Repository -> IO (Either String SyncStatus)
sync repo = do
  gitStatus <- gitRepositoryStatus repo
  ensured <- ensureGitRepositoryWithRemote repo gitStatus
  let mkGitError = Left . explainGitError
  case ensured of
    Left e -> return $ mkGitError e
    Right s ->
      case s of
        GitRepositoryCreated ->
          return $ Right Created
        GitRepositoryExisting -> do
          repoStatus <- status' repo gitStatus
          if repoStatus == DirectoryOutDated
            then either mkGitError (const $ Right Updated) <$> updateGitRepository repo
            else return $ Right AlreadyUpToDate

data RepositoryStatus
  = DirectoryMissing
  | DirectoryEmpty
  | DirectoryUpToDate
  | DirectoryOutDated
  deriving stock (Eq, Show)

status :: Repository -> IO RepositoryStatus
status repo =
  status' repo =<< gitRepositoryStatus repo

status' :: Repository -> GitRepositoryStatus -> IO RepositoryStatus
status' repo gitStatus = do
  case gitStatus of
    GitDirectoryMissing ->
      return DirectoryMissing
    GitDirectoryEmpty ->
      return DirectoryEmpty
    GitDirectoryInitialized -> do
      gitInfo <- getDirectoryGitInfo $ repositoryRoot repo
      case gitInfo of
        Left _ ->
          return DirectoryOutDated
        Right info -> do
          update <- latestUpdate (repositoryUrl repo) (repositoryBranch repo)
          return $
            if update == Right (zonedTimeToUTC $ lastModificationCommitDate info)
              then DirectoryUpToDate
              else DirectoryOutDated

defaultRepository :: Repository
defaultRepository =
  Repository
    { repositoryUrl = "https://github.com/haskell/security-advisories",
      repositoryRoot = "security-advisories",
      repositoryBranch = "main"
    }
