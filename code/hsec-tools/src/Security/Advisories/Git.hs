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
import System.Directory (canonicalizePath)
import System.Environment (getEnvironment)
import System.Exit (ExitCode(ExitSuccess))
import System.FilePath (searchPathSeparator, splitFileName)
import System.Process (CreateProcess (env), proc, readCreateProcessWithExitCode, readProcessWithExitCode)
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

-- | Get git-derived metadata for an advisory file.
--
-- The optional second argument is a /ceiling directory/: when given, the
-- spawned @git@ process gets @GIT_CEILING_DIRECTORIES@ set to it (prepended
-- to any existing value), so git discovery stops before reaching it. Note
-- that the ceiling directory itself is excluded from discovery, so callers
-- that want a repository located exactly at @root@ to remain visible must
-- pass the /parent/ of @root@. This prevents repositories enclosing the
-- listing root from contributing out-of-band dates when parsing a synced
-- snapshot; pass 'Nothing' to preserve repository tooling behavior.
getAdvisoryGitInfo
  :: FilePath          -- ^ path to the advisory file
  -> Maybe FilePath    -- ^ ceiling directory for git discovery
  -> IO (Either GitError AdvisoryGitInfo)
getAdvisoryGitInfo path mCeiling = do
  let (dir, file) = splitFileName path
  env' <- maybe (pure Nothing) (fmap Just . withCeiling) mCeiling
  (status, stdout, stderr) <- readCreateProcessWithExitCode
    (proc "git" (args dir file)) { env = env' }
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
    args dir file =
      [ "-C", dir
      , "log"
      , "--pretty=format:%cI"  -- print committer date
      , "--find-renames"
      , file
      ]

    -- Parent environment with GIT_CEILING_DIRECTORIES set to the given
    -- root, preserving any previously configured ceiling entries (git
    -- applies all of them). The path is canonicalized because git
    -- discovery walks physical (symlink-resolved) directories, and git
    -- ignores ceiling entries containing symlinks.
    withCeiling :: FilePath -> IO [(String, String)]
    withCeiling root = do
      root' <- canonicalizePath root
      parentEnv <- getEnvironment
      let newVal = case lookup "GIT_CEILING_DIRECTORIES" parentEnv of
            Nothing -> root'
            Just old -> root' <> [searchPathSeparator] <> old
      pure $
        ("GIT_CEILING_DIRECTORIES", newVal)
          : filter ((/= "GIT_CEILING_DIRECTORIES") . fst) parentEnv

    parseTime :: String -> Either GitError UTCTime
    parseTime s = maybe (Left $ GitTimeParseError s) Right $
       iso8601ParseM s
         <|> zonedTimeToUTC <$> iso8601ParseM s
