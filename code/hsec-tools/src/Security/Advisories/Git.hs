{-|

Helpers for deriving advisory metadata from a Git repo.

-}
module Security.Advisories.Git
  ( AdvisoryGitInfo(..)
  , GitError(..)
  , getAdvisoryGitInfo
  )
  where

import Data.Time (ZonedTime)
import Data.Time.Format.ISO8601 (iso8601ParseM)
import System.Exit (ExitCode(ExitSuccess))
import System.FilePath (splitFileName)
import System.Process (readProcessWithExitCode)

data AdvisoryGitInfo = AdvisoryGitInfo
  { firstAppearanceCommitDate :: ZonedTime
  , lastModificationCommitDate :: ZonedTime
  }

data GitError
  = GitProcessError ExitCode String String -- ^ exit code, stdout and stderr
  | GitTimeParseError String -- ^ unable to parse this input as a datetime
  deriving (Show)

getAdvisoryGitInfo :: FilePath -> IO (Either GitError AdvisoryGitInfo)
getAdvisoryGitInfo path = do
  let (dir, file) = splitFileName path
  (status, stdout, stderr) <- readProcessWithExitCode
    "git"
    [ "-C", dir
    , "log"
    , "--pretty=format:%cI"  -- print committer date
    , "--find-renames"
    , file
    ]
    "" -- standard input
  let timestamps = filter (not . null) $ lines stdout
  case status of
    ExitSuccess | not (null timestamps) ->
      pure $ AdvisoryGitInfo
        <$> parseTime (last timestamps)  -- first commit is last line
        <*> parseTime (head timestamps)  -- most recent commit is first line
    _ ->
      -- `null lines` should not happen, but if it does we treat it
      -- the same as `ExitFailure`
      pure . Left $ GitProcessError status stdout stderr
  where
    parseTime s = maybe (Left $ GitTimeParseError s) Right $ iso8601ParseM s
