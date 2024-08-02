{-# LANGUAGE LambdaCase #-}

module Command.NextID where

import Control.Monad (unless)
import Data.Maybe (fromMaybe)
import System.Exit (die)

import Security.Advisories.Git (getRepoRoot)
import Security.Advisories.Core.HsecId (printHsecId, getNextHsecId)
import Security.Advisories.Filesystem (isSecurityAdvisoriesRepo, getGreatestId)

runNextIDCommand :: Maybe FilePath -> IO ()
runNextIDCommand mPath = do
  let
    path = fromMaybe "." mPath
  repoPath <- getRepoRoot path >>= \case
    Left _ -> die "Not a git repo"
    Right a -> pure a
  isRepo <- isSecurityAdvisoriesRepo repoPath
  unless isRepo $
    die "Not a security-advisories repo"

  getGreatestId repoPath >>= getNextHsecId >>= putStrLn . printHsecId
