{-# LANGUAGE OverloadedStrings #-}

module Spec.FilesystemSpec (spec) where

import Data.Maybe (fromMaybe)
import Data.Time (UTCTime)
import Data.Time.Format.ISO8601 (iso8601ParseM)
import Security.Advisories (Advisory (advisoryModified))
import qualified Security.Advisories.Filesystem as Filesystem
import Security.Advisories.Git
  ( AdvisoryGitInfo (firstAppearanceCommitDate, lastModificationCommitDate)
  , getAdvisoryGitInfo
  )
import System.Directory (createDirectoryIfMissing)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import System.Process (CreateProcess (env), proc, readCreateProcessWithExitCode)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, testCase, (@?=))
import Validation (Validation (..))

inBandModified :: UTCTime
inBandModified = parseIso "2026-01-01T00:00:00Z"

-- | TOML frontmatter for a published advisory without in-band dates
-- (repository shape: dates come from git history).
repoShapeToml :: String
repoShapeToml = unlines
  [ "```toml"
  , "[advisory]"
  , "id = \"HSEC-9000-0001\""
  , "[[affected]]"
  , "package = \"tls-extra\""
  , "cvss = \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N\""
  , "[[affected.versions]]"
  , "introduced = \"0.1.0\""
  , "fixed = \"0.4.6.1\""
  , "```"
  , ""
  , "# Test advisory"
  ]

-- | Same shape with in-band dates (snapshot shape, generated branch).
snapShapeToml :: String
snapShapeToml = unlines
  [ "```toml"
  , "[advisory]"
  , "id = \"HSEC-9000-0002\""
  , "date = 2026-01-01T00:00:00Z"
  , "modified = 2026-01-01T00:00:00Z"
  , "[[affected]]"
  , "package = \"tls-extra\""
  , "cvss = \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N\""
  , "[[affected.versions]]"
  , "introduced = \"0.1.0\""
  , "fixed = \"0.4.6.1\""
  , "```"
  , ""
  , "# Test advisory"
  ]

parseIso :: String -> UTCTime
parseIso s =
  fromMaybe (error ("bad ISO8601 timestamp: " <> s)) (iso8601ParseM s)

-- | Run git for the fixture, failing the test loudly on a non-zero exit
-- (a silently broken fixture would make the failure assertions pass
-- vacuously). Global/system git config is neutralized so developer
-- settings (gpgsign, hooks, templates) cannot skew the fixture.
git :: FilePath -> [String] -> IO ()
git dir args = do
  (status, stdout, stderr) <-
    readCreateProcessWithExitCode
      (proc "git" ("-C" : dir : args))
        { env = Just [ ("GIT_CONFIG_GLOBAL", "/dev/null")
                     , ("GIT_CONFIG_SYSTEM", "/dev/null")
                     , ("GIT_TERMINAL_PROMPT", "0")
                     ] }
      ""
  case status of
    ExitSuccess -> pure ()
    _ -> error ("fixture git " <> show args <> " failed: " <> stdout <> stderr)

-- | Build @outer/@ containing:
--
--  * @outer/@ itself is a git repository holding a repository-shape
--    advisory (no in-band dates) under @advisories/published/2026/@;
--  * @outer/snap/@ is a snapshot (not a repository, but enclosed by the
--    repo) holding a snapshot-shape advisory with in-band dates.
--
-- Returns @(outer, repoShapeFile, snapFile)@.
makeFixture :: FilePath -> IO (FilePath, FilePath, FilePath)
makeFixture outer = do
  let repoAdvisoriesDir = outer </> "advisories" </> "published" </> "2026"
      snapAdvisoriesDir = outer </> "snap" </> "advisories" </> "published" </> "2026"
      repoShapeFile = repoAdvisoriesDir </> "HSEC-9000-0001.md"
      snapFile = snapAdvisoriesDir </> "HSEC-9000-0002.md"
  createDirectoryIfMissing True repoAdvisoriesDir
  createDirectoryIfMissing True snapAdvisoriesDir
  writeFile repoShapeFile repoShapeToml
  writeFile snapFile snapShapeToml
  git outer ["init", "-q"]
  git outer ["add", "-A"]
  git outer ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"]
  pure (outer, repoShapeFile, snapFile)

spec :: TestTree
spec = testGroup "Filesystem"
  [ testCase "getAdvisoryGitInfo without ceiling yields git dates in a repo" $
      withSystemTempDirectory "hsec-fs-repo" $ \outer -> do
        (_, repoShapeFile, _) <- makeFixture outer
        res <- getAdvisoryGitInfo repoShapeFile Nothing
        case res of
          Left err -> assertBool ("expected Right, got: " <> show err) False
          Right info ->
            assertBool "first appearance must not be after last modification" $
              firstAppearanceCommitDate info <= lastModificationCommitDate info

  , testCase "ceiling at snapshot root hides the enclosing repository" $
      withSystemTempDirectory "hsec-fs-snap" $ \outer -> do
        (_, _, snapFile) <- makeFixture outer
        res <- getAdvisoryGitInfo snapFile (Just (outer </> "snap"))
        case res of
          Left _ -> pure ()  -- expected: git finds no repository at/below the ceiling
          Right _ ->
            assertBool "expected git failure, got git info" False

  , testCase "listAdvisories on a snapshot uses in-band dates" $
      withSystemTempDirectory "hsec-fs-list" $ \outer -> do
        (root, _, _) <- makeFixture outer
        res <- Filesystem.listAdvisories (root </> "snap")
        case res of
          Failure errs ->
            assertBool ("expected Success, got failures: " <> show (map fst errs)) False
          Success [adv] ->
            advisoryModified adv @?= inBandModified
          Success advs ->
            assertBool ("expected exactly one advisory, got " <> show (length advs)) False

  , testCase "listAdvisories on the repository root uses git-derived dates" $
      withSystemTempDirectory "hsec-fs-root" $ \outer -> do
        (_, repoShapeFile, _) <- makeFixture outer
        gitInfoE <- getAdvisoryGitInfo repoShapeFile Nothing
        res <- Filesystem.listAdvisories outer
        case (gitInfoE, res) of
          (Right gitInfo, Success [adv]) ->
            advisoryModified adv @?= lastModificationCommitDate gitInfo
          (Right _, Success advs) ->
            assertBool ("expected exactly one advisory, got " <> show (length advs)) False
          (Left err, _) ->
            assertBool ("git info failed: " <> show err) False
          (_, Failure errs) ->
            assertBool ("listing failed: " <> show (map fst errs)) False
  ]
