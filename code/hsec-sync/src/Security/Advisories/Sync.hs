{-# LANGUAGE DerivingStrategies #-}

module Security.Advisories.Sync
  ( Repository (..),
    defaultRepository,
    SyncStatus (..),
    sync,
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
  ensured <- ensureGitRepositoryWithRemote repo
  let mkGitError = Left . explainGitError
  case ensured of
    Left e -> return $ mkGitError e
    Right s ->
      case s of
        GitRepositoryCreated ->
          return $ Right Created
        GitRepositoryExisting -> do
          gitInfo <- getDirectoryGitInfo $ repositoryRoot repo
          case gitInfo of
            Left e -> return $ mkGitError e
            Right info -> do
              update <- latestUpdate (repositoryUrl repo) (repositoryBranch repo)
              if update == Right (zonedTimeToUTC $ lastModificationCommitDate info)
                then return $ Right AlreadyUpToDate
                else either mkGitError (const $ Right Updated) <$> updateGitRepository repo

defaultRepository :: Repository
defaultRepository =
  Repository
    { repositoryUrl = "https://github.com/haskell/security-advisories",
      repositoryRoot = "security-advisories",
      repositoryBranch = "main"
    }
