{-# LANGUAGE OverloadedStrings #-}

module Spec.SyncSpec (spec) where

import Control.Monad (unless)
import Data.Bifunctor (first)
import Security.Advisories.Sync
import qualified System.Directory as D
import System.Environment (lookupEnv)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Test.Tasty
import Test.Tasty.HUnit

spec :: TestTree
spec = testGroup "Sync" []

_spec :: TestTree
_spec =
  testGroup
    "Sync"
    [ testGroup
        "sync"
        [ testCase "Invalid root should fail" $ do
            let snapshot = snapshotAt "/dev/advisories"
            status snapshot >>= (@?= DirectoryMissing)
            isGitHubActionRunner <- lookupEnv "GITHUB_ACTIONS"
            unless (isGitHubActionRunner == Just "true") $ do
              -- GitHub Action runners let you write anywhere
              result <- sync snapshot
              first (const ("<Redacted error>" :: String)) result @?= Left "<Redacted error>"
            status snapshot >>= (@?= DirectoryMissing),
          testCase "Subdirectory creation should work" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              let snapshot = snapshotAt $ p </> "snapshot"
              status snapshot >>= (@?= DirectoryMissing)
              result <- sync snapshot
              result @?= Right Created
              status snapshot >>= (@?= DirectoryUpToDate),
          testCase "With existing subdirectory creation should work" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              D.createDirectory $ p </> "snapshot"
              let snapshot = snapshotAt $ p </> "snapshot"
              result <- sync snapshot
              result @?= Right Created,
          testCase "Sync twice should be a no-op" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              let snapshot = snapshotAt p
              status snapshot >>= (@?= DirectoryIncoherent)
              resultCreate <- sync snapshot
              resultCreate @?= Right Created
              resultResync <- sync snapshot
              resultResync @?= Right AlreadyUpToDate,
          testCase "Sync behind should update" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              let snapshot = snapshotAt p
              resultCreate <- sync snapshot
              resultCreate @?= Right Created
              writeFile
                (p </> "snapshot.json")
                "{\"latestUpdate\":\"2020-03-11T12:26:51Z\",\"snapshotVersion\":\"0.1.0.0\"}"
              status snapshot >>= (@?= DirectoryOutDated)
              resultResync <- sync snapshot
              resultResync @?= Right Updated
              status snapshot >>= (@?= DirectoryUpToDate),
          testCase "Sync a broken snapshot.json" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              let snapshot = snapshotAt p
              resultCreate <- sync snapshot
              resultCreate @?= Right Created
              writeFile
                (p </> "snapshot.json")
                "{\"latestpdate\":\"2020-03-11T12:26:51Z\",\"snapshotVersion\":\"0.1.0.0\"}"
              status snapshot >>= (@?= DirectoryIncoherent)
              resultResync <- sync snapshot
              resultResync @?= Right Updated
              status snapshot >>= (@?= DirectoryUpToDate),
          testCase "Sync a deleted snapshot.json" $
            withSystemTempDirectory "hsec-sync" $ \p -> do
              let snapshot = snapshotAt p
              resultCreate <- sync snapshot
              resultCreate @?= Right Created
              D.removeFile (p </> "snapshot.json")
              status snapshot >>= (@?= DirectoryOutDated)
              resultResync <- sync snapshot
              resultResync @?= Right Updated
              status snapshot >>= (@?= DirectoryIncoherent)
        ]
    ]

snapshotAt :: FilePath -> Snapshot
snapshotAt root =
  defaultSnapshot {snapshotRoot = root}
