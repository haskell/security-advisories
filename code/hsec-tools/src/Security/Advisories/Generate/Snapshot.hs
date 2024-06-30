{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Security.Advisories.Generate.Snapshot
  ( createSnapshot,
  )
where

import Data.Aeson (ToJSON, encodeFile)
import Data.Default (def)
import qualified Data.Text.IO as T
import Data.Time (UTCTime)
import Data.Version (Version)
import GHC.Generics (Generic)
import Paths_hsec_tools (version)
import qualified Prettyprinter as Pretty
import qualified Prettyprinter.Render.Text as Pretty
import Security.Advisories.Core.Advisory
import Security.Advisories.Filesystem (advisoryFromFile, forAdvisory, forReserved)
import Security.Advisories.Format (fromAdvisory)
import System.Directory (copyFileWithMetadata, createDirectoryIfMissing)
import System.FilePath (takeDirectory, (</>))
import System.IO (hPrint, hPutStrLn, stderr)
import Text.Pandoc (Block (CodeBlock), Pandoc (Pandoc), nullMeta, runIOorExplode)
import Text.Pandoc.Writers (writeCommonMark)
import qualified Toml
import Validation (Validation (..))

-- * Actions

createSnapshot :: FilePath -> FilePath -> IO ()
createSnapshot src dst = do
  let toDstFilePath orig = dst </> drop (length src + 1) orig

  forReserved src $ \p _ -> do
    createDirectoryIfMissing True $ takeDirectory $ toDstFilePath p
    hPutStrLn stderr $ "Copying '" <> p <> "' to '" <> toDstFilePath p <> "'"
    copyFileWithMetadata p $ toDstFilePath p

  advisoriesLatestUpdates <-
    forAdvisory src $ \p _ -> do
      createDirectoryIfMissing True $ takeDirectory $ toDstFilePath p
      hPutStrLn stderr $ "Taking a snapshot of '" <> p <> "' to '" <> toDstFilePath p <> "'"
      advisoryFromFile p
        >>= \case
          Failure e -> do
            hPrint stderr e
            return []
          Success advisory -> do
            let pandoc =
                  Pandoc
                    nullMeta
                    ( CodeBlock
                        ("", ["toml"], [])
                        ( Pretty.renderStrict $
                            Pretty.layoutPretty Pretty.defaultLayoutOptions $
                              Toml.encode $
                                fromAdvisory advisory
                        )
                        : blocks (advisoryPandoc advisory)
                    )
                blocks (Pandoc _ xs) = xs
            rendered <- runIOorExplode $ writeCommonMark def pandoc
            T.writeFile (toDstFilePath p) rendered
            return [advisoryModified advisory]

  let metadataPath = dst </> "snapshot.json"
      metadata =
        SnapshotMetadata
          { latestUpdate = maximum advisoriesLatestUpdates,
            snapshotVersion = version
          }
  hPutStrLn stderr $ "Writing snapshot metadata to '" <> metadataPath <> "'"
  encodeFile metadataPath metadata

data SnapshotMetadata = SnapshotMetadata
  { latestUpdate :: UTCTime,
    snapshotVersion :: Version
  }
  deriving stock (Generic)
  deriving anyclass (ToJSON)
