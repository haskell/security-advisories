{-# LANGUAGE LambdaCase #-}

module Command.Reserve where

import Control.Monad (unless)
import Data.Maybe (fromMaybe)
import System.Exit (die)
import System.FilePath ((</>), (<.>))

import Security.Advisories.Git (getRepoRoot)
import Security.Advisories.HsecId
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

runReserveCommand :: Maybe FilePath -> IdMode -> IO ()
runReserveCommand mPath idMode = do
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
