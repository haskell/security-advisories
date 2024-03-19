{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Spec.SyncSpec (spec) where

import Data.Bifunctor (first)
import Security.Advisories.Sync
import qualified System.Directory as D
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
            result <- sync $ withRepositoryAt "/x/y/z"
            first (const ("<Redacted error>" :: String)) result @?= Left "<Redacted error>",
          testCase "Subdirectory creation should work" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              result <- sync $ withRepositoryAt $ p </> "repo"
              result @?= Right Created,
          testCase "With existing subdirectory creation should work" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              D.createDirectory $ p </> "repo"
              result <- sync $ withRepositoryAt $ p </> "repo"
              result @?= Right Created,
          testCase "Sync twice should be a no-op" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              resultCreate <- sync $ withRepositoryAt p
              resultCreate @?= Right Created
              resultResync <- sync $ withRepositoryAt p
              resultResync @?= Right AlreadyUpToDate,
          testCase "Sync behind should update" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              resultCreate <- sync $ withRepositoryAt p
              resultCreate @?= Right Created
              D.withCurrentDirectory p $ do
                (status, _, _) <-
                  readProcessWithExitCode "git" ["reset", "--hard", "HEAD~50"] ""
                status @?= ExitSuccess
              resultResync <- sync $ withRepositoryAt p
              resultResync @?= Right Updated,
          testCase "Sync behind and changed remote should update" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              resultCreate <- sync $ withRepositoryAt p
              resultCreate @?= Right Created
              D.withCurrentDirectory p $ do
                (statusReset, _, _) <-
                  readProcessWithExitCode "git" ["reset", "--hard", "HEAD~50"] ""
                statusReset @?= ExitSuccess
                (statusRemote, _, _) <-
                  readProcessWithExitCode "git" ["remote", "rename", "origin", "old"] ""
                statusRemote @?= ExitSuccess
              resultResync <- sync $ withRepositoryAt p
              resultResync @?= Right Updated
        ]
    ]

withRepositoryAt :: FilePath -> Repository
withRepositoryAt root =
  defaultRepository {repositoryRoot = root}
