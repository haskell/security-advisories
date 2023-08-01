{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad (join, void, when)
import qualified Data.ByteString.Lazy as L
import Data.Foldable (for_)
import Data.Functor ((<&>))
import Data.List (isPrefixOf)
import qualified Data.Text.IO as T
import Options.Applicative
import System.Exit (die, exitFailure, exitSuccess)
import System.IO (stderr)
import System.FilePath (takeBaseName)

import qualified Data.Aeson

import Security.Advisories
import qualified Security.Advisories.Convert.OSV as OSV
import Security.Advisories.Git
import Security.Advisories.Generate.HTML

main :: IO ()
main = join $ execParser cliOpts

cliOpts :: ParserInfo (IO ())
cliOpts = info (commandsParser <**> helper) (fullDesc <> header "Haskell Advisories tools")
  where
    commandsParser :: Parser (IO ())
    commandsParser =
      subparser
        (  command "check" (info commandCheck (progDesc "Syntax check a single advisory"))
        <> command "osv" (info commandOsv (progDesc "Convert a single advisory to OSV"))
        <> command "render" (info commandRender (progDesc "Render a single advisory as HTML"))
        <> command "generate-index" (info commandGenerateIndex (progDesc "Generate an HTML index"))
        <> command "help" (info commandHelp (progDesc "Show command help"))
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
        when ("HSEC-" `isPrefixOf` base && base /= printHsecId (advisoryId advisory)) $
          die $ "Filename does not match advisory ID: " <> path
      T.putStrLn "no error"

commandOsv :: Parser (IO ())
commandOsv =
  withAdvisory go
  <$> optional (argument str (metavar "FILE"))
  <**> helper
  where
    go _ adv = do
      L.putStr (Data.Aeson.encode (OSV.convert adv))
      putChar '\n'

commandRender :: Parser (IO ())
commandRender =
  withAdvisory (\_ -> T.putStrLn . advisoryHtml)
  <$> optional (argument str (metavar "FILE"))
  <**> helper

commandGenerateIndex :: Parser (IO ())
commandGenerateIndex =
  ( \src dst -> do
      renderAdvisoriesIndex src dst
      T.putStrLn "Index generated"
  )
  <$> argument str (metavar "SOURCE-DIR")
  <*> argument str (metavar "DESTINATION-DIR")
  <**> helper

commandHelp :: Parser (IO ())
commandHelp =
  ( \mCmd ->
      let args = maybe id (:) mCmd ["-h"]
      in void $ handleParseResult $ execParserPure defaultPrefs cliOpts args
  )
  <$> optional (argument str (metavar "COMMAND"))
  <**> helper

withAdvisory :: (Maybe FilePath -> Advisory -> IO ()) -> Maybe FilePath -> IO ()
withAdvisory go file = do
  input <- maybe T.getContents T.readFile file

  oob <- ($ emptyOutOfBandAttributes) <$> case file of
    Nothing -> pure id
    Just path ->
      getAdvisoryGitInfo path <&> \case
        Left _ -> id
        Right gitInfo -> \oob -> oob
          { oobPublished = Just (firstAppearanceCommitDate gitInfo)
          , oobModified = Just (lastModificationCommitDate gitInfo)
          }

  case parseAdvisory NoOverrides oob input of
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
