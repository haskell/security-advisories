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
        <> command "help" (info commandHelp mempty)
        )

commandCheck :: Parser (IO ())
commandCheck =
  withAdvisory (const $ T.putStrLn "no error")
  <$> optional (argument str (metavar "FILE"))
  <**> helper

commandRender :: Parser (IO ())
commandRender =
  withAdvisory (T.putStrLn . renderAdvisoryHtml)
  <$> optional (argument str (metavar "FILE"))
  <**> helper

commandHelp :: Parser (IO ())
commandHelp =
  ( \mCmd ->
      let args = maybe id (:) mCmd ["-h"]
      in void $ handleParseResult $ execParserPure defaultPrefs cliOpts args
  )
  <$> optional (argument str (metavar "COMMAND"))

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
