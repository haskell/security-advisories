module Distribution.Audit (auditMain) where

import Data.Foldable (traverse_)
import qualified Distribution.Client.InstallPlan as Plan
import Distribution.Client.NixStyleOptions
  ( NixStyleFlags (configFlags)
  , defaultNixStyleFlags
  , nixStyleOptions
  )
import Distribution.Client.ProjectConfig (ProjectConfig)
import Distribution.Client.ProjectOrchestration
  ( CurrentCommand (OtherCommand)
  , ProjectBaseContext
    ( ProjectBaseContext
    , cabalDirLayout
    , distDirLayout
    , localPackages
    , projectConfig
    )
  , commandLineFlagsToProjectConfig
  , establishProjectBaseContext
  )
import Distribution.Client.ProjectPlanning (rebuildInstallPlan)
import Distribution.Client.Setup (ConfigFlags (configVerbosity), defaultGlobalFlags)
import Distribution.Simple.Command
  ( CommandParse (CommandErrors, CommandHelp, CommandList, CommandReadyToGo)
  , CommandUI (..)
  , commandParseArgs
  )
import Distribution.Simple.Flag (fromFlagOrDefault)
import qualified Distribution.Verbosity as Verbosity
import System.Environment (getArgs)

auditMain :: IO ()
auditMain =
  handleArgs auditCommandUI \flags -> do
    let verbosity = verbosityFromFlags flags
        cliConfig = projectConfigFromFlags flags
    ProjectBaseContext {distDirLayout, cabalDirLayout, projectConfig, localPackages} <-
      establishProjectBaseContext
        verbosity
        cliConfig
        OtherCommand
    (_, plan, _, _, _) <-
      rebuildInstallPlan verbosity distDirLayout cabalDirLayout projectConfig localPackages Nothing
    print `traverse_` Plan.toList plan

projectConfigFromFlags :: NixStyleFlags a -> ProjectConfig
projectConfigFromFlags flags = commandLineFlagsToProjectConfig defaultGlobalFlags flags mempty

verbosityFromFlags :: NixStyleFlags a -> Verbosity.Verbosity
verbosityFromFlags = fromFlagOrDefault Verbosity.normal . configVerbosity . configFlags

auditCommandUI :: CommandUI (NixStyleFlags ())
auditCommandUI =
  CommandUI
    { commandName = "cabal-audit"
    , commandSynopsis = "Audits your cabal project"
    , commandUsage = ("Usage: " ++)
    , commandDescription = Nothing
    , commandNotes = Nothing
    , commandDefaultFlags = defaultNixStyleFlags ()
    , commandOptions = nixStyleOptions (const [])
    }

-- | handle cabal global command args
handleArgs
  :: CommandUI flags
  -> (flags -> IO ())
  -> IO ()
handleArgs ui k = do
  args <- getArgs
  case commandParseArgs ui True args of
    CommandHelp help -> putStrLn $ help "cabal-audit"
    CommandList opts -> putStrLn $ "commandList: " <> show opts
    CommandErrors errs -> putStrLn $ "commandErrors: " <> show errs
    CommandReadyToGo (flags, _commandParse) -> k $ flags $ commandDefaultFlags ui
