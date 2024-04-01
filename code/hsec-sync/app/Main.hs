{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad (join)
import Options.Applicative
import Security.Advisories.Sync
import System.Exit (die)
import System.IO (hPutStrLn, stderr)

main :: IO ()
main =
  join $
    customExecParser
      (prefs showHelpOnEmpty)
      cliOpts

cliOpts :: ParserInfo (IO ())
cliOpts = info (commandsParser <**> helper) (fullDesc <> header "Haskell Advisories tools")
  where
    commandsParser :: Parser (IO ())
    commandsParser =
      hsubparser
        ( command "sync" (info commandSync (progDesc "Synchronize a local Haskell Security Advisory repository snapshot"))
            <> command "status" (info commandStatus (progDesc "Check the status of a local Haskell Security Advisory repository snapshot"))
        )

commandSync :: Parser (IO ())
commandSync = go <$> repositoryParser
  where
    go repo = do
      result <- sync repo
      case result of
        Left e ->
          die e
        Right s -> do
          putStrLn $
            "Snapshot at "
              <> show (snapshotRoot repo)
              <> " from "
              <> show (repositoryUrl repo <> "@" <> repositoryBranch repo)
          putStrLn $
            case s of
              Created -> "Snapshot just created"
              Updated -> "Snapshot updated"
              AlreadyUpToDate -> "Snapshot already up-to-date"

commandStatus :: Parser (IO ())
commandStatus = go <$> repositoryParser
  where
    go repo = do
      result <- status repo
      hPutStrLn stderr $
        case result of
          DirectoryMissing -> "Directory is missing"
          DirectoryIncoherent -> "Directory is incoherent"
          DirectoryUpToDate -> "Repository is up-to-date"
          DirectoryOutDated -> "Repository is out-dated"

repositoryParser :: Parser Snapshot
repositoryParser =
  Snapshot
    <$> strOption
      ( long "snapshot-root"
          <> short 'd'
          <> metavar "SNAPSHOT-ROOT"
          <> value (snapshotRoot defaultRepository)
      )
    <*> strOption
      ( long "repository-url"
          <> short 'r'
          <> metavar "REPOSITORY-URL"
          <> value (repositoryUrl defaultRepository)
      )
    <*> strOption
      ( long "repository-branch"
          <> short 'b'
          <> metavar "REPOSITORY-BRANCH"
          <> value (repositoryBranch defaultRepository)
      )
