{-# LANGUAGE LambdaCase #-}

module Util where

import Data.Maybe (fromMaybe)
import System.Exit (die)

import Security.Advisories.Filesystem (isSecurityAdvisoriesRepo)
import Security.Advisories.Git (getRepoRoot)

-- | Ensure the given path (or current directory "." if @Nothing@)
-- is an advisory Git repo.  Return the (valid) repo root, or die
-- with an error message.
--
ensureRepo :: Maybe FilePath -> IO FilePath
ensureRepo mPath =
  getRepoRoot (fromMaybe "." mPath) >>= \case
    Left _          -> die "Not a git repo"
    Right repoPath  -> isSecurityAdvisoriesRepo repoPath >>= \case
      False -> die "Not a security-advisories repo"
      True  -> pure repoPath
