{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad (join, void)
import qualified Data.Text.IO as T
import Options.Applicative
import Security.Advisories
import System.Exit (exitFailure, exitSuccess)
import System.IO (stderr)

main :: IO ()
main = join $ execParser cliOpts

cliOpts :: ParserInfo (IO ())
cliOpts = info (commandsParser <**> helper) (fullDesc <> header "Haskell Advisories tools")
  where
    commandsParser :: Parser (IO ())
    commandsParser =
      subparser
        ( command "check" (info (pure $ withAdvisory $ const $ T.putStrLn "no error") mempty)
            <> command "render" (info (pure $ withAdvisory $ T.putStrLn . renderAdvisoryHtml) mempty)
            <> command "help" (info (pure displayHelp) mempty)
        )
    displayHelp :: IO ()
    displayHelp = void $ handleParseResult $ execParserPure defaultPrefs cliOpts ["-h"]

withAdvisory :: (Advisory -> IO ()) -> IO ()
withAdvisory f = do
  input <- T.getContents
  case parseAdvisory input of
    Left e -> do
      T.hPutStrLn stderr $
        case e of
          MarkdownError _ explanation -> "Markdown parsing error:\n" <> explanation
          MarkdownFormatError explanation -> "Markdown structure error:\n" <> explanation
          TomlError _ explanation -> "Couldn't parse front matter as TOML:\n" <> explanation
          AdvisoryError _ explanation -> "Advisory structure error:\n" <> explanation
      exitFailure
    Right advisory -> do
      f advisory
      exitSuccess
