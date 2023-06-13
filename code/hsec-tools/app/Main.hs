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
        (  command "check" (info commandCheck mempty)
        <> command "render" (info commandRender mempty)
        <> command "help" (info (pure displayHelp) mempty)
        )
    displayHelp :: IO ()
    displayHelp = void $ handleParseResult $ execParserPure defaultPrefs cliOpts ["-h"]

commandCheck :: Parser (IO ())
commandCheck =
  withAdvisory (const $ T.putStrLn "no error")
  <$> optional (argument str (metavar "FILE"))

commandRender :: Parser (IO ())
commandRender =
  withAdvisory (T.putStrLn . renderAdvisoryHtml)
  <$> optional (argument str (metavar "FILE"))

withAdvisory :: (Advisory -> IO ()) -> Maybe FilePath -> IO ()
withAdvisory go file = do
  input <- maybe T.getContents T.readFile file
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
      go advisory
      exitSuccess
