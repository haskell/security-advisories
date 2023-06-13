{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad (join, void, when)
import Data.Foldable (for_)
import Data.List (isPrefixOf)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Options.Applicative
import Security.Advisories
import System.Exit (die, exitFailure, exitSuccess)
import System.IO (stderr)
import System.FilePath (takeBaseName)

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
  withAdvisory go
  <$> optional (argument str (metavar "FILE"))
  <**> helper
  where
    go mPath advisory = do
      for_ mPath $ \path -> do
        let base = takeBaseName path
        when ("HSEC-" `isPrefixOf` base && base /= T.unpack (advisoryId advisory)) $
          die $ "Filename does not match advisory ID: " <> path
      T.putStrLn "no error"

commandRender :: Parser (IO ())
commandRender =
  withAdvisory (\_ -> T.putStrLn . renderAdvisoryHtml)
  <$> optional (argument str (metavar "FILE"))
  <**> helper

commandHelp :: Parser (IO ())
commandHelp =
  ( \mCmd ->
      let args = maybe id (:) mCmd ["-h"]
      in void $ handleParseResult $ execParserPure defaultPrefs cliOpts args
  )
  <$> optional (argument str (metavar "COMMAND"))

withAdvisory :: (Maybe FilePath -> Advisory -> IO ()) -> Maybe FilePath -> IO ()
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
      go file advisory
      exitSuccess
