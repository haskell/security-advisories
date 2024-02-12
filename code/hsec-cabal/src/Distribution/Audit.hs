module Distribution.Audit (auditMain) where

import Data.Foldable (traverse_)
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
  , mkCommandUI
  )
import Distribution.Simple.Flag (fromFlagOrDefault)
import qualified Distribution.Verbosity as Verbosity
import System.Environment (getArgs)
import qualified System.FilePath as FP
import Control.Exception (throwIO, Exception (displayException))
import Security.Advisories.Filesystem (listAdvisories)
import Validation (validation)
import Security.Advisories (ParseAdvisoryError)
import GHC.Generics (Generic)
import Security.Advisories.Cabal (matchAdvisoriesForPlan)

data AuditException 
  = MissingArgs  
  | TooManyArgs
  | InvalidFilePath String
  | ListAdvisoryValidationError FilePath [ParseAdvisoryError]
  deriving stock (Eq, Show, Generic)

instance Exception AuditException where
 displayException = \case 
   MissingArgs -> "You didn't specify where to take the audit results from"
   TooManyArgs -> "Expected only one argument"
   InvalidFilePath fp -> show fp <> " is not a valid filepath"
   ListAdvisoryValidationError dir errs -> unlines 
     [ "Listing the advisories in directory " <> dir <> " failed with:"
     , show errs
     ]

auditMain :: IO ()
auditMain =
  handleArgs auditCommandUI \args flags -> do
    let verbosity = verbosityFromFlags flags
        cliConfig = projectConfigFromFlags flags
    ProjectBaseContext {distDirLayout, cabalDirLayout, projectConfig, localPackages} <-
      establishProjectBaseContext
        verbosity
        cliConfig
        OtherCommand
    (plan', plan, _, _, _) <-
      rebuildInstallPlan verbosity distDirLayout cabalDirLayout projectConfig localPackages Nothing

    fp <- case args of 
      [] -> throwIO MissingArgs
      [fp] -> if FP.isValid fp then pure fp else throwIO (InvalidFilePath fp) 
      (_x : _y : _zs) -> throwIO TooManyArgs
    advisories <- listAdvisories fp 
      >>= validation (throwIO . ListAdvisoryValidationError fp) pure

    print $ matchAdvisoriesForPlan plan advisories
    print $ matchAdvisoriesForPlan plan' advisories
    -- TODO(mangoiv): find out what's the correct plan

projectConfigFromFlags :: NixStyleFlags a -> ProjectConfig
projectConfigFromFlags flags = commandLineFlagsToProjectConfig defaultGlobalFlags flags mempty

verbosityFromFlags :: NixStyleFlags a -> Verbosity.Verbosity
verbosityFromFlags = fromFlagOrDefault Verbosity.normal . configVerbosity . configFlags

auditCommandUI :: CommandUI (NixStyleFlags ())
auditCommandUI =
  mkCommandUI
    "audit"
    "Audits your cabal project"
    ["<hsec-advisory-directory>"]
    do defaultNixStyleFlags ()
    do nixStyleOptions (const [])

-- | handle cabal global command args
handleArgs
  :: CommandUI flags
  -> ([String] -> flags -> IO ())
  -> IO ()
handleArgs ui k = do
  args <- getArgs
  case commandParseArgs ui False args of
    CommandHelp help -> putStrLn $ help "cabal"
    CommandList opts -> putStrLn `traverse_` opts
    CommandErrors errs -> putStrLn `traverse_` errs
    CommandReadyToGo (flags, commandParse) -> k commandParse $ flags $ commandDefaultFlags ui
