module Distribution.Audit (auditMain) where

import Colourista.Pure (blue, bold, formatWith, green, red, yellow)
import Control.Exception (Exception (displayException), throwIO)
import Control.Monad (when)
import Data.Coerce (coerce)
import Data.Foldable (for_)
import Data.Functor.Identity (Identity (runIdentity))
import Data.List qualified as List
import Data.Map qualified as M
import Data.String (IsString (fromString))
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.IO qualified as T
import Distribution.Client.NixStyleOptions (NixStyleFlags, defaultNixStyleFlags)
import Distribution.Client.ProjectConfig (ProjectConfig)
import Distribution.Client.ProjectOrchestration
  ( CurrentCommand (OtherCommand)
  , ProjectBaseContext (ProjectBaseContext, cabalDirLayout, distDirLayout, localPackages, projectConfig)
  , commandLineFlagsToProjectConfig
  , establishProjectBaseContext
  )
import Distribution.Client.ProjectPlanning (rebuildInstallPlan)
import Distribution.Client.Setup (defaultGlobalFlags)
import Distribution.Types.PackageName (PackageName, unPackageName)
import Distribution.Verbosity qualified as Verbosity
import Distribution.Version (Version, versionNumbers)
import GHC.Generics (Generic)
import Options.Applicative
import Security.Advisories (Advisory (..), Keyword (..), ParseAdvisoryError, printHsecId)
import Security.Advisories.Cabal (ElaboratedPackageInfoAdvised, ElaboratedPackageInfoWith (elaboratedPackageVersion, packageAdvisories), matchAdvisoriesForPlan)
import Security.Advisories.Filesystem (listAdvisories)
import System.IO.Temp (withSystemTempDirectory)
import System.Process (callProcess)
import Validation (validation)

data AuditException
  = InvalidFilePath String
  | ListAdvisoryValidationError FilePath [ParseAdvisoryError]
  deriving stock (Eq, Show, Generic)

instance Exception AuditException where
  displayException = \case
    InvalidFilePath fp -> show fp <> " is not a valid filepath"
    ListAdvisoryValidationError dir errs ->
      unlines
        [ "Listing the advisories in directory " <> dir <> " failed with:"
        , show errs
        ]

-- | configuration that is specific to the cabal audit command
data AuditConfig = MkAuditConfig
  { advisoriesPathOrURL :: Either FilePath String
  -- ^ path or URL to the advisories
  , verbosity :: Verbosity.Verbosity
  -- ^ verbosity of cabal
  }

auditMain :: IO ()
auditMain = do
  (MkAuditConfig {advisoriesPathOrURL, verbosity}, flags) <- customExecParser (prefs showHelpOnEmpty) do
    info
      do helper <*> auditCommandParser
      do
        mconcat
          [ fullDesc
          , progDesc (formatWith [blue] "audit your cabal projects for vulnerabilities")
          , header (formatWith [bold, blue] "Welcome to cabal audit")
          ]
  let cliConfig = projectConfigFromFlags flags

  ProjectBaseContext {distDirLayout, cabalDirLayout, projectConfig, localPackages} <-
    establishProjectBaseContext
      verbosity
      cliConfig
      OtherCommand
  (_plan', plan, _, _, _) <-
    rebuildInstallPlan verbosity distDirLayout cabalDirLayout projectConfig localPackages Nothing

  when (verbosity > Verbosity.normal) do
    putStrLn (formatWith [blue] "Finished building the cabal install plan, looking for advisories...")

  advisories <- withSystemTempDirectory "hsec-cabal" \tmp -> do
    realPath <- case advisoriesPathOrURL of
      Left fp -> pure fp
      Right url -> do
        putStrLn $ formatWith [blue] $ "trying to clone " <> url
        callProcess "git" ["clone", url, tmp]
        pure tmp
    listAdvisories realPath
      >>= validation (throwIO . ListAdvisoryValidationError realPath) pure

  humanReadableHandler (M.toList (matchAdvisoriesForPlan plan advisories))

{-# INLINE prettyVersion #-}
prettyVersion :: IsString s => Version -> s
prettyVersion = fromString . List.intercalate "." . map show . versionNumbers

prettyAdvisory :: Advisory -> Maybe Version -> Text
prettyAdvisory Advisory {advisoryId, advisoryPublished, advisoryKeywords, advisorySummary} mfv =
  T.unlines do
    let hsecId = T.pack (printHsecId advisoryId)
    map
      ("  " <>)
      [ formatWith [bold, blue] hsecId <> " \"" <> advisorySummary <> "\""
      , "published: " <> formatWith [bold] (ps advisoryPublished)
      , "https://haskell.github.io/security-advisories/advisory/" <> hsecId
      , fixAvailable
      , formatWith [blue] $ T.intercalate ", " (coerce advisoryKeywords)
      ]
 where
  ps = T.pack . show
  fixAvailable = case mfv of
    Nothing -> formatWith [bold, red] "No fix version available"
    Just fv -> formatWith [bold, green] "Fix available since version " <> formatWith [yellow] (prettyVersion fv)

-- | this is handler is used when displaying to the user
humanReadableHandler :: [(PackageName, ElaboratedPackageInfoAdvised)] -> IO ()
humanReadableHandler = \case
  [] -> putStrLn (formatWith [green, bold] "No advisories found.")
  avs -> do
    putStrLn (formatWith [bold, red] "\n\nFound advisories:\n")
    for_ avs \(pn, i) -> do
      let verString = formatWith [yellow] $ prettyVersion $ elaboratedPackageVersion i
          pkgName = formatWith [yellow] $ show $ unPackageName pn
      putStrLn ("dependency " <> pkgName <> " at version " <> verString <> " is vulnerable for:")
      for_ (runIdentity (packageAdvisories i)) (T.putStrLn . uncurry prettyAdvisory)

-- print $ matchAdvisoriesForPlan plan' advisories
-- TODO(mangoiv): find out what's the correct plan

projectConfigFromFlags :: NixStyleFlags a -> ProjectConfig
projectConfigFromFlags flags = commandLineFlagsToProjectConfig defaultGlobalFlags flags mempty

auditCommandParser :: Parser (AuditConfig, NixStyleFlags ())
auditCommandParser =
  (,)
    <$> do
      MkAuditConfig
        <$> do
          Left
            <$> strOption do
              mconcat
                [ long "file-path"
                , short 'p'
                , metavar "FILE_PATH"
                , help "the path the the repository containing an advisories directory"
                ]
              <|> Right
            <$> strOption do
              mconcat
                [ long "repository"
                , short 'r'
                , metavar "REPOSITORY"
                , help "the url to the repository containing an advisories directory"
                , value "https://github.com/haskell/security-advisories"
                ]
        <*> flip option (long "verbosity" <> value Verbosity.normal <> showDefaultWith (const "normal")) do
          eitherReader \case
            "silent" -> Right Verbosity.silent
            "normal" -> Right Verbosity.normal
            "verbose" -> Right Verbosity.verbose
            "deafening" -> Right Verbosity.deafening
            _ -> Left "verbosity has to be one of \"silent\", \"normal\", \"verbose\" or \"deafening\""
    <*> pure (defaultNixStyleFlags ())
