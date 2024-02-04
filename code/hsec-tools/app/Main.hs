{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad (forM_, join, void, when)
import qualified Data.ByteString.Lazy as L
import Data.Maybe (fromMaybe)
import Data.Foldable (for_)
import Data.Functor ((<&>))
import Data.List (intercalate, isPrefixOf)
import Distribution.Parsec (eitherParsec)
import Distribution.Types.VersionRange (VersionRange, anyVersion)
import System.Exit (die, exitFailure, exitSuccess)
import System.IO (hPrint, hPutStrLn, stderr)
import System.FilePath (takeBaseName)
import Validation (Validation(..))

import qualified Data.Aeson
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Options.Applicative

import Security.Advisories
import qualified Security.Advisories.Convert.OSV as OSV
import Security.Advisories.Git
import Security.Advisories.Queries (listVersionRangeAffectedBy)
import Security.Advisories.Generate.HTML

import qualified Command.Reserve

main :: IO ()
main = join $
  customExecParser
    (prefs showHelpOnEmpty)
    cliOpts

cliOpts :: ParserInfo (IO ())
cliOpts = info (commandsParser <**> helper) (fullDesc <> header "Haskell Advisories tools")
  where
    commandsParser :: Parser (IO ())
    commandsParser =
      hsubparser
        (  command "check" (info commandCheck (progDesc "Syntax check a single advisory"))
        <> command "reserve" (info commandReserve (progDesc "Reserve an HSEC ID"))
        <> command "osv" (info commandOsv (progDesc "Convert a single advisory to OSV"))
        <> command "render" (info commandRender (progDesc "Render a single advisory as HTML"))
        <> command "generate-index" (info commandGenerateIndex (progDesc "Generate an HTML index"))
        <> command "query" (info commandQuery (progDesc "Run various queries against the database"))
        <> command "help" (info commandHelp (progDesc "Show command help"))
        )

-- | Create an option with a fixed set of values
multiOption :: [(String, a)] -> Mod OptionFields a -> Parser a
multiOption kvs m = option rdr (m <> metavar choices)
  where
  choices = "{" <> intercalate "|" (fmap fst kvs) <> "}"
  errMsg = "must be one of " <> choices
  rdr = eitherReader (maybe (Left errMsg) Right . flip lookup kvs)

commandReserve :: Parser (IO ())
commandReserve =
  Command.Reserve.runReserveCommand
  <$> optional (argument str (metavar "REPO"))
  <*> multiOption
        [ ("placeholder", Command.Reserve.IdModePlaceholder)
        , ("auto",        Command.Reserve.IdModeAuto)
        ]
        ( long "id-mode" <> help "How to assign IDs" )
  <*> flag
        Command.Reserve.DoNotCommit -- default value
        Command.Reserve.Commit      -- active value
        ( long "commit"
        <> help "Commit the reservation file"
        )

commandCheck :: Parser (IO ())
commandCheck =
  withAdvisory go
  <$> optional (argument str (metavar "FILE"))
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
  where
    go _ adv = do
      L.putStr (Data.Aeson.encode (OSV.convert adv))
      putChar '\n'

commandRender :: Parser (IO ())
commandRender =
  withAdvisory (\_ -> T.putStrLn . advisoryHtml)
  <$> optional (argument str (metavar "FILE"))

commandQuery :: Parser (IO ())
commandQuery =
  subparser
    ( command "is-affected" (info isAffected (progDesc "Check if a package/version range is marked vulnerable"))
    )
  where
    isAffected :: Parser (IO ())
    isAffected =
      go
        <$> argument str (metavar "PACKAGE")
        <*> optional (option versionRangeReader (metavar "VERSION-RANGE" <> short 'v' <> long "version-range"))
        <*> optional (option str (metavar "ADVISORIES-PATH" <> short 'p' <> long "advisories-path"))
      where go :: T.Text -> Maybe VersionRange -> Maybe FilePath -> IO ()
            go packageName versionRange advisoriesPath = do
              let versionRange' = fromMaybe anyVersion versionRange
              maybeAffectedAdvisories <- listVersionRangeAffectedBy (fromMaybe "." advisoriesPath) packageName versionRange'
              case maybeAffectedAdvisories of
                Validation.Failure errors -> do
                  T.hPutStrLn stderr "Cannot parse some advisories"
                  forM_ errors $
                    hPrint stderr
                  exitFailure
                Validation.Success [] -> putStrLn "Not affected"
                Validation.Success affectedAdvisories -> do
                  hPutStrLn stderr "Affected by:"
                  forM_ affectedAdvisories $ \advisory ->
                    T.hPutStrLn stderr $ "* [" <> T.pack (printHsecId $ advisoryId advisory) <> "] " <> advisorySummary advisory
                  exitFailure

commandGenerateIndex :: Parser (IO ())
commandGenerateIndex =
  ( \src dst -> do
      renderAdvisoriesIndex src dst
      T.putStrLn "Index generated"
  )
  <$> argument str (metavar "SOURCE-DIR")
  <*> argument str (metavar "DESTINATION-DIR")

commandHelp :: Parser (IO ())
commandHelp =
  ( \mCmd ->
      let args = maybe id (:) mCmd ["-h"]
      in void $ handleParseResult $ execParserPure defaultPrefs cliOpts args
  )
  <$> optional (argument str (metavar "COMMAND"))

versionRangeReader :: ReadM VersionRange
versionRangeReader = eitherReader eitherParsec

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
