{-# LANGUAGE LambdaCase #-}

module Command.Reserve where

import Control.Monad (unless, when)
import Data.Maybe (fromMaybe)
import System.Exit (die)
import System.FilePath ((</>), (<.>))

import Security.Advisories.Git
  ( add
  , commit
  , explainGitError
  , getRepoRoot
  )
import Security.Advisories.Core.HsecId
  ( placeholder
  , printHsecId
  , getNextHsecId
  )
import Security.Advisories.Filesystem
  ( dirNameAdvisories
  , dirNameReserved
  , isSecurityAdvisoriesRepo
  , getGreatestId
  )

-- | How to choose IDs when creating advisories or
-- reservations.
data IdMode
  = IdModePlaceholder
  -- ^ Create a placeholder ID (e.g. HSEC-0000-0000).  Real IDs
  -- will be assigned later.
  | IdModeAuto
  -- ^ Use the next available ID.  This option is more likely to
  -- result in conflicts when submitting advisories or reservations.

data CommitFlag = Commit | DoNotCommit
  deriving (Eq)

runReserveCommand :: Maybe FilePath -> IdMode -> CommitFlag -> IO ()
runReserveCommand mPath idMode commitFlag = do
  let
    path = fromMaybe "." mPath
  repoPath <- getRepoRoot path >>= \case
    Left _ -> die "Not a git repo"
    Right a -> pure a
  isRepo <- isSecurityAdvisoriesRepo repoPath
  unless isRepo $
    die "Not a security-advisories repo"

  hsid <- case idMode of
    IdModePlaceholder -> pure placeholder
    IdModeAuto -> do
      curMax <- getGreatestId repoPath
      getNextHsecId curMax

  let
    advisoriesPath = repoPath </> dirNameAdvisories
    fileName = printHsecId hsid <.> "md"
    filePath = advisoriesPath </> dirNameReserved </> fileName
  writeFile filePath ""  -- write empty file

  when (commitFlag == Commit) $ do
    let msg = printHsecId hsid <> ": reserve id"
    add repoPath [filePath] >>= \case
      Left e -> die $ "Failed to update Git index: " <> explainGitError e
      Right _ -> pure ()
    commit repoPath msg >>= \case
      Left e -> die $ "Failed to create Git commit: " <> explainGitError e
      Right _ -> pure ()
