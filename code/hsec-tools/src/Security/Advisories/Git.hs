{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DerivingStrategies #-}

{-|

Helpers for deriving advisory metadata from a Git repo.

-}
module Security.Advisories.Git
  ( AdvisoryGitInfo(..)
  , GitError(..)
  , explainGitError
  , getAdvisoryGitInfo
  , getRepoRoot
  , add
  , commit
  )
  where

import Data.Char (isSpace)
import Data.List (dropWhileEnd)
import qualified Data.List.NonEmpty as NE
import Data.Time (UTCTime, zonedTimeToUTC)
import Data.Time.Format.ISO8601 (iso8601ParseM)
import System.Exit (ExitCode(ExitSuccess))
import System.FilePath (splitFileName)
import System.Process (readProcessWithExitCode)
import Control.Applicative ((<|>))

data AdvisoryGitInfo = AdvisoryGitInfo
  { firstAppearanceCommitDate :: UTCTime
  , lastModificationCommitDate :: UTCTime
  }

data GitError
  = GitProcessError ExitCode String String -- ^ exit code, stdout and stderr
  | GitTimeParseError String -- ^ unable to parse this input as a datetime
  deriving stock (Eq, Ord, Show)

explainGitError :: GitError -> String
explainGitError = \case
  GitProcessError status stdout stderr ->
    unlines
      [ "git exited with status " <> show status
      , ">>> standard output:"
      , stdout
      , ">>> standard error:"
      , stderr
      ]
  GitTimeParseError s ->
    "failed to parse time: " <> s

-- | Get top-level directory of the working tree.
--
getRepoRoot :: FilePath -> IO (Either GitError FilePath)
getRepoRoot path = do
  (status, stdout, stderr) <- readProcessWithExitCode
    "git"
    [ "-C", path
    , "rev-parse"
    , "--show-toplevel"
    ]
    "" -- standard input
  pure $ case status of
    ExitSuccess -> Right $ trim stdout
    _ -> Left $ GitProcessError status stdout stderr
  where
    trim = dropWhileEnd isSpace . dropWhile isSpace

-- | Add changes to index
--
add
  :: FilePath   -- ^ path to working tree
  -> [FilePath] -- ^ files to update in index
  -> IO (Either GitError ())
add path pathspecs = do
  (status, stdout, stderr) <- readProcessWithExitCode
    "git"
    ( ["-C", path, "add"] <> pathspecs )
    "" -- standard input
  pure $ case status of
    ExitSuccess -> Right ()
    _ -> Left $ GitProcessError status stdout stderr

-- | Commit changes to repo.
--
commit
  :: FilePath   -- ^ path to working tree
  -> String     -- ^ commit message
  -> IO (Either GitError ())
commit path msg = do
  (status, stdout, stderr) <- readProcessWithExitCode
    "git"
    ["-C", path, "commit", "-m", msg]
    "" -- standard input
  pure $ case status of
    ExitSuccess -> Right ()
    _ -> Left $ GitProcessError status stdout stderr

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
    ExitSuccess | Just timestamps' <- NE.nonEmpty timestamps ->
      pure $ AdvisoryGitInfo
        <$> parseTime (NE.last timestamps')  -- first commit is last line
        <*> parseTime (NE.head timestamps')  -- most recent commit is first line
    _ ->
      -- `null lines` should not happen, but if it does we treat it
      -- the same as `ExitFailure`
      pure . Left $ GitProcessError status stdout stderr
  where
    parseTime :: String -> Either GitError UTCTime
    parseTime s = maybe (Left $ GitTimeParseError s) Right $
       iso8601ParseM s
         <|> zonedTimeToUTC <$> iso8601ParseM s
