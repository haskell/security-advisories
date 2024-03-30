{-# LANGUAGE OverloadedStrings #-}

module Spec.SyncSpec (spec) where

import Control.Monad (unless)
import Data.Bifunctor (first)
import Security.Advisories.Sync
import qualified System.Directory as D
import System.Environment (lookupEnv)
import System.Exit (ExitCode (ExitSuccess))
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import System.Process (readProcessWithExitCode)
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec =
  testGroup
    "Sync"
    [ testGroup
        "sync"
        [ testCase "Invalid root should fail" $ do
            let repo = withRepositoryAt "/dev/advisories"
            status repo >>= (@?= DirectoryMissing)
            isGitHubActionRunner <- lookupEnv "GITHUB_ACTIONS"
            unless (isGitHubActionRunner == Just "true") $ do
              -- GitHub Action runners let you write anywhere
              result <- sync repo
              first (const ("<Redacted error>" :: String)) result @?= Left "<Redacted error>"
            status repo >>= (@?= DirectoryMissing),
          testCase "Subdirectory creation should work" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              let repo = withRepositoryAt $ p </> "repo"
              status repo >>= (@?= DirectoryMissing)
              result <- sync repo
              result @?= Right Created
              status repo >>= (@?= DirectoryUpToDate),
          testCase "With existing subdirectory creation should work" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              D.createDirectory $ p </> "repo"
              let repo = withRepositoryAt $ p </> "repo"
              result <- sync repo
              result @?= Right Created,
          testCase "Sync twice should be a no-op" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              let repo = withRepositoryAt p
              status repo >>= (@?= DirectoryEmpty)
              resultCreate <- sync repo
              resultCreate @?= Right Created
              resultResync <- sync repo
              resultResync @?= Right AlreadyUpToDate,
          testCase "Sync behind should update" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              let repo = withRepositoryAt p
              resultCreate <- sync repo
              resultCreate @?= Right Created
              D.withCurrentDirectory p $ do
                (statusReset, _, _) <-
                  readProcessWithExitCode "git" ["reset", "--hard", "HEAD~50"] ""
                statusReset @?= ExitSuccess
              status repo >>= (@?= DirectoryOutDated)
              resultResync <- sync repo
              resultResync @?= Right Updated
              status repo >>= (@?= DirectoryUpToDate),
          testCase "Sync behind and changed remote should update" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              let repo = withRepositoryAt p
              resultCreate <- sync repo
              resultCreate @?= Right Created
              D.withCurrentDirectory p $ do
                (statusReset, _, _) <-
                  readProcessWithExitCode "git" ["reset", "--hard", "HEAD~50"] ""
                statusReset @?= ExitSuccess
                (statusRemote, _, _) <-
                  readProcessWithExitCode "git" ["remote", "rename", "origin", "old"] ""
                statusRemote @?= ExitSuccess
              resultResync <- sync repo
              resultResync @?= Right Updated
        ]
    ]

withRepositoryAt :: FilePath -> Repository
withRepositoryAt root =
  defaultRepository {repositoryRoot = root}
