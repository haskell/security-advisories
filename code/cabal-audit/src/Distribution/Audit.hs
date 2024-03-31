-- | provides the @cabal-audit@ plugin which works as follows:
--
-- 1. parse command line arguments to pass on to cabal to build
--    an install plan and parse the advisories database
-- 2. lookup all dependencies in the elaborated plan within the
--    database
-- 3. summarise the found vulnerabilities as a humand readable or
--    otherwise formatted output
module Distribution.Audit (auditMain, buildAdvisories, AuditConfig (..), AuditException (..), Output (..)) where

import Colourista.Pure (blue, bold, formatWith, green, red, yellow)
import Control.Exception (Exception (displayException), SomeException (SomeException), catch, throwIO)
import Control.Monad (when)
import Data.Aeson (KeyValue ((.=)), Value, object)
import Data.Aeson qualified as Aeson
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
import Security.Advisories.Cabal (ElaboratedPackageInfoAdvised, ElaboratedPackageInfoWith (MkElaboratedPackageInfoWith, elaboratedPackageVersion, packageAdvisories), matchAdvisoriesForPlan)
import Security.Advisories.Convert.OSV qualified as OSV
import Security.Advisories.Filesystem (listAdvisories)
import System.Exit (exitFailure)
import System.IO.Temp (withSystemTempDirectory)
import System.Process (callProcess)
import Validation (validation)
import System.IO (stderr, hPutStrLn)

data AuditException
  = -- | parsing the advisory database failed
    ListAdvisoryValidationError {originalFilePath :: FilePath, parseError :: [ParseAdvisoryError]}
  | -- | to rethrow exceptions thrown by cabal during plan elaboration
    CabalException {reason :: String, cabalException :: SomeException}
  deriving stock (Show, Generic)

instance Exception AuditException where
  displayException = \case
    ListAdvisoryValidationError dir errs ->
      mconcat
        [ "Listing the advisories in directory "
        , dir
        , " failed with: \n"
        , show errs
        ]
    CabalException ctx (SomeException ex) ->
      "cabal failed while "
        <> ctx
        <> ":\n"
        <> displayException ex

-- | the type of output that is chosen for the command
data Output
  = -- | write humand readable to stdout
    HumanReadable
  | -- | write as Osv format to the specified file
    Osv {osvPath :: FilePath}

-- | configuration that is specific to the cabal audit command
data AuditConfig = MkAuditConfig
  { advisoriesPathOrURL :: Either FilePath String
  -- ^ path or URL to the advisories
  , verbosity :: Verbosity.Verbosity
  -- ^ verbosity of cabal
  , outputType :: Output
  }

-- | the main action to invoke
auditMain :: IO ()
auditMain =
  do
    (auditConfig, nixStyleFlags) <- customExecParser (prefs showHelpOnEmpty) do
      info (helper <*> auditCommandParser) do
        mconcat
          [ fullDesc
          , progDesc (formatWith [blue] "audit your cabal projects for vulnerabilities")
          , header (formatWith [bold, blue] "Welcome to cabal audit")
          ]

    buildAdvisories auditConfig nixStyleFlags
      >>= handleBuiltAdvisories (outputType auditConfig)
    `catch` \(SomeException ex) -> do
      hPutStrLn stderr $
        unlines
          [ formatWith [red, bold] "cabal-audit failed:"
          , formatWith [red] $ displayException ex
          ]
      exitFailure

buildAdvisories :: AuditConfig -> NixStyleFlags () -> IO (M.Map PackageName ElaboratedPackageInfoAdvised)
buildAdvisories MkAuditConfig {advisoriesPathOrURL, verbosity} flags = do
  let cliConfig = projectConfigFromFlags flags

  ProjectBaseContext {distDirLayout, cabalDirLayout, projectConfig, localPackages} <-
    establishProjectBaseContext
      verbosity
      cliConfig
      OtherCommand
      `catch` \ex -> throwIO $ CabalException {reason = "trying to establish project base context", cabalException = ex}
  -- the two plans are
  -- 1. the "improved plan" with packages replaced by in-store packages
  -- 2. the "original" elaborated plan
  --
  -- as far as I can tell, for our use case these should be indistinguishable
  (_improvedPlan, plan, _, _, _) <-
    rebuildInstallPlan verbosity distDirLayout cabalDirLayout projectConfig localPackages Nothing
      `catch` \ex -> throwIO $ CabalException {reason = "elaborating the install-plan", cabalException = ex}

  when (verbosity > Verbosity.normal) do
    hPutStrLn stderr (formatWith [blue] "Finished building the cabal install plan, looking for advisories...")

  advisories <- do
    let k realPath =
          listAdvisories realPath
            >>= validation (throwIO . ListAdvisoryValidationError realPath) pure
    case advisoriesPathOrURL of
      Left fp -> k fp
      Right url -> withSystemTempDirectory "cabal-audit" \tmp -> do
        hPutStrLn stderr $ formatWith [blue] $ "trying to clone " <> url
        callProcess "git" ["clone","--depth", "1",url, tmp]
        k tmp

  pure $ matchAdvisoriesForPlan plan advisories

-- | provides the built advisories in some consumable form, e.g. as human readable form
--
-- FUTUREWORK(mangoiv): provide output as JSON
handleBuiltAdvisories :: Output -> M.Map PackageName ElaboratedPackageInfoAdvised -> IO ()
handleBuiltAdvisories = \case
  HumanReadable -> humanReadableHandler . M.toList
  Osv fp -> osvHandler fp

osvHandler :: FilePath -> M.Map PackageName ElaboratedPackageInfoAdvised -> IO ()
osvHandler fp =
  Aeson.encodeFile @Value fp . object . M.foldMapWithKey
    \pn MkElaboratedPackageInfoWith {elaboratedPackageVersion, packageAdvisories} ->
      [ fromString (unPackageName pn)
          .= object
            [ "version" .= prettyVersion @Text elaboratedPackageVersion
            , "advisories" .= map (OSV.convert . fst) (runIdentity packageAdvisories)
            ]
      ]

-- | pretty-prints a `Version`
--
-- >>> import Distribution.Version
-- >>> prettyVersion $ mkVersion [0, 1, 0, 0]
-- "0.1.0.0"
prettyVersion :: IsString s => Version -> s
prettyVersion = fromString . List.intercalate "." . map show . versionNumbers
{-# INLINE prettyVersion #-}

prettyAdvisory :: Advisory -> Maybe Version -> Text
prettyAdvisory Advisory {advisoryId, advisoryPublished, advisoryKeywords, advisorySummary} mfv =
  T.unlines do
    let hsecId = T.pack (printHsecId advisoryId)
    map
      ("  " <>)
      [ formatWith [bold, blue] hsecId <> " \"" <> advisorySummary <> "\""
      , "published: " <> formatWith [bold] (T.pack $ show advisoryPublished)
      , "https://haskell.github.io/security-advisories/advisory/" <> hsecId
      , fixAvailable
      , formatWith [blue] $ T.intercalate ", " (coerce advisoryKeywords)
      ]
 where
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
                , metavar "FILEPATH"
                , help "the path to the repository containing an advisories directory"
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
        <*> do
          Osv
            <$> strOption do
              mconcat
                [ long "osv"
                , short 'o'
                , metavar "FILEPATH"
                , help "whether to print to a file of osv, mapping package name and version to an osv"
                ]
              <|> pure HumanReadable
    -- FUTUREWORK(mangoiv): this will accept cabal flags as an additional argument with something like
    -- --cabal-flags "--some-cabal-flag" and print a helper that just forwards the cabal help text
    <*> pure (defaultNixStyleFlags ())
