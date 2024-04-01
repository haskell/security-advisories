{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}

-- |
--
-- Helpers for deriving advisory metadata from a Snapshot s.
module Security.Advisories.Sync.Snapshot
  ( SnapshotDirectoryInfo (..),
    SnapshotError (..),
    explainSnapshotError,
    Snapshot (..),
    SnapshotRepositoryEnsuredStatus (..),
    ensureSnapshot,
    getDirectorySnapshotInfo,
    overwriteSnapshot,
    SnapshotRepositoryStatus (..),
    snapshotRepositoryStatus,
  )
where

import qualified Codec.Archive.Tar as Tar
import qualified Codec.Compression.GZip as GZip
import Control.Exception (IOException, try)
import Control.Lens
import Control.Monad.Extra (unlessM, whenM)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Data.Aeson (FromJSON, eitherDecodeFileStrict)
import qualified Data.ByteString.Lazy as BL
import Data.Either.Combinators (whenLeft)
import Data.Functor (($>))
import Data.Time (UTCTime)
import GHC.Generics (Generic)
import Network.HTTP.Client (HttpException (..), HttpExceptionContent (..))
import Network.Wreq
import qualified System.Directory as D
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Security.Advisories.Sync.Url

data SnapshotError
  = SnapshotDirectoryMissingE
  | SnapshotIncoherent String
  | SnapshotProcessError SnapshotProcessError

data SnapshotProcessError
  = FetchSnapshotArchive String
  | DirectorySetupSnapshotArchive IOException
  | ExtractSnapshotArchive IOException

explainSnapshotError :: SnapshotError -> String
explainSnapshotError =
  \case
    SnapshotDirectoryMissingE -> "Snapshot directory is missing"
    SnapshotIncoherent e -> "Snapshot directory is incoherent: " <> e
    SnapshotProcessError e ->
      unlines
        [ "An exception occurred during snapshot processing:"
        , case e of
            FetchSnapshotArchive x -> "Fetching failed with: " <> show x
            DirectorySetupSnapshotArchive x -> "Directory setup got an exception: " <> show x
            ExtractSnapshotArchive x -> "Extraction got an exception: " <> show x
        ]

data Snapshot = Snapshot
  { snapshotRoot :: FilePath,
    repositoryUrl :: String,
    repositoryBranch :: String
  }

snapshotArchiveUrl :: Snapshot -> String
snapshotArchiveUrl s =
  ensureFile (mkUrl [repositoryUrl s, "archive/refs/heads", repositoryBranch s]) <> ".tar.gz"

data SnapshotRepositoryStatus
  = SnapshotDirectoryMissing
  | SnapshotDirectoryInitialized
  | SnapshotDirectoryIncoherent

snapshotRepositoryStatus :: Snapshot -> IO SnapshotRepositoryStatus
snapshotRepositoryStatus s = do
  dirExists <- D.doesDirectoryExist $ snapshotRoot s
  if dirExists
    then do
      dirAdvisoriesExists <- D.doesDirectoryExist $ snapshotRoot s </> "advisories"
      fileMetadataExists <- D.doesFileExist $ snapshotRoot s </> "snapshot.json"
      return $
        if dirAdvisoriesExists && fileMetadataExists
          then SnapshotDirectoryInitialized
          else SnapshotDirectoryIncoherent
    else return SnapshotDirectoryMissing

data SnapshotRepositoryEnsuredStatus
  = SnapshotRepositoryCreated
  | SnapshotRepositoryExisting

ensureSnapshot ::
  Snapshot ->
  SnapshotRepositoryStatus ->
  IO (Either SnapshotError SnapshotRepositoryEnsuredStatus)
ensureSnapshot s =
  \case
    SnapshotDirectoryMissing ->
      ($> SnapshotRepositoryCreated)
        <$> overwriteSnapshot s
    SnapshotDirectoryIncoherent ->
      ($> SnapshotRepositoryCreated)
        <$> overwriteSnapshot s
    SnapshotDirectoryInitialized ->
      return $ Right SnapshotRepositoryExisting

overwriteSnapshot :: Snapshot -> IO (Either SnapshotError ())
overwriteSnapshot s =
  runExceptT $ do
    let root = snapshotRoot s
    ensuringPerformed <- liftIO $ try $ ensureEmptyRoot root
    whenLeft ensuringPerformed $
      throwE . SnapshotProcessError . DirectorySetupSnapshotArchive

    resultE <- liftIO $ try $ get $ snapshotArchiveUrl s
    case resultE of
      Left e ->
        throwE $
          SnapshotProcessError $
            FetchSnapshotArchive $
              case e of
                InvalidUrlException url reason ->
                  "Invalid URL " <> show url <> ": " <> show reason
                HttpExceptionRequest _ content ->
                  case content of
                    StatusCodeException response body ->
                      "Request failed with " <> show (response ^. responseStatus) <> ": " <> show body
                    _ ->
                      "Request failed: " <> show content
      Right result -> do
        performed <-
          liftIO $
            try $
              withSystemTempDirectory "security-advisories" $ \tempDir -> do
                let archivePath = tempDir <> "/snapshot-export.tar.gz"
                BL.writeFile archivePath $ result ^. responseBody
                contents <- BL.readFile archivePath
                Tar.unpack root $ Tar.read $ GZip.decompress contents
        whenLeft performed $
          throwE . SnapshotProcessError . ExtractSnapshotArchive

ensureEmptyRoot :: FilePath -> IO ()
ensureEmptyRoot root = do
  D.createDirectoryIfMissing False root

  whenM (D.doesDirectoryExist $ root </> "advisories") $
    D.removeDirectoryRecursive $
      root </> "advisories"

  whenM (D.doesFileExist $ root </> "snapshot.json") $
    D.removeFile $
      root </> "snapshot.json"

newtype SnapshotDirectoryInfo = SnapshotDirectoryInfo
  { lastModificationCommitDate :: UTCTime
  }

getDirectorySnapshotInfo :: FilePath -> IO (Either SnapshotError SnapshotDirectoryInfo)
getDirectorySnapshotInfo root =
  runExceptT $ do
    let metadataPath = root </> "snapshot.json"
    unlessM (liftIO $ D.doesFileExist metadataPath) $
      throwE SnapshotDirectoryMissingE

    metadataE <- liftIO $ eitherDecodeFileStrict metadataPath
    case metadataE of
      Left e -> throwE $ SnapshotIncoherent $ "Cannot parse " <> show metadataPath <> ": " <> e
      Right metadata -> return $ SnapshotDirectoryInfo $ latestUpdate metadata

newtype SnapshotMetadata = SnapshotMetadata
  { latestUpdate :: UTCTime
  }
  deriving stock (Generic)
  deriving anyclass (FromJSON)
