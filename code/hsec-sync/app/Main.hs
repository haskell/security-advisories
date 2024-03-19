{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad (join)
import Options.Applicative
import Security.Advisories.Sync
import System.Exit (die)

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
        ( command "sync" (info commandSync (progDesc "Synchronize a local Haskell Security Advisory repository"))
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
            "Repository at "
              <> show (repositoryRoot repo)
              <> " from "
              <> show (repositoryUrl repo <> "@" <> repositoryBranch repo)
          putStrLn $
            case s of
              Created -> "Repository just created"
              Updated -> "Repository updated"
              AlreadyUpToDate -> "Repository already up-to-date"

repositoryParser :: Parser Repository
repositoryParser =
  Repository
    <$> strOption
      ( long "repository-root"
          <> short 'd'
          <> metavar "REPOSITORY-ROOT"
          <> value (repositoryRoot defaultRepository)
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
