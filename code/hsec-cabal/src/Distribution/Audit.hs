module Distribution.Audit (auditMain) where

import Control.Exception (Exception (displayException), throwIO)
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
import Distribution.Verbosity qualified as Verbosity
import GHC.Generics (Generic)
import Options.Applicative
import Security.Advisories (ParseAdvisoryError)
import Security.Advisories.Cabal (matchAdvisoriesForPlan)
import Security.Advisories.Filesystem (listAdvisories)
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
  { advisoriesPath :: FilePath
  -- ^ path to the advisories
  , verbosity :: Verbosity.Verbosity
  -- ^ verbosity of cabal
  }

auditMain :: IO ()
auditMain = do
  (MkAuditConfig {advisoriesPath, verbosity}, flags) <- customExecParser (prefs showHelpOnEmpty) do
    info
      do helper <*> auditCommandParser
      do
        mconcat
          [ fullDesc
          , progDesc "audit your cabal projects for vulnerabilities"
          , header "Welcome to cabal audit"
          ]
  let cliConfig = projectConfigFromFlags flags

  ProjectBaseContext {distDirLayout, cabalDirLayout, projectConfig, localPackages} <-
    establishProjectBaseContext
      verbosity
      cliConfig
      OtherCommand
  (_plan', plan, _, _, _) <-
    rebuildInstallPlan verbosity distDirLayout cabalDirLayout projectConfig localPackages Nothing
  advisories <-
    listAdvisories advisoriesPath
      >>= validation (throwIO . ListAdvisoryValidationError advisoriesPath) pure
  print $ matchAdvisoriesForPlan plan advisories

-- print $ matchAdvisoriesForPlan plan' advisories
-- TODO(mangoiv): find out what's the correct plan

projectConfigFromFlags :: NixStyleFlags a -> ProjectConfig
projectConfigFromFlags flags = commandLineFlagsToProjectConfig defaultGlobalFlags flags mempty

auditCommandParser :: Parser (AuditConfig, NixStyleFlags ())
auditCommandParser =
  (,)
    <$> do
      MkAuditConfig
        <$> strArgument (metavar "<path to advisories>")
        <*> flip option (long "verbosity" <> value Verbosity.normal <> showDefaultWith (const "normal")) do
          eitherReader \case
            "silent" -> Right Verbosity.silent
            "normal" -> Right Verbosity.normal
            "verbose" -> Right Verbosity.verbose
            "deafening" -> Right Verbosity.deafening
            _ -> Left "verbosity has to be one of \"silent\", \"normal\", \"verbose\" or \"deafening\""
    <*> pure (defaultNixStyleFlags ())
