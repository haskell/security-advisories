module Command.NextID where

import Security.Advisories.Core.HsecId (printHsecId, getNextHsecId)
import Security.Advisories.Filesystem (getGreatestId)

import Util (ensureRepo)

runNextIDCommand :: Maybe FilePath -> IO ()
runNextIDCommand mPath =
  ensureRepo mPath >>= getGreatestId >>= getNextHsecId >>= putStrLn . printHsecId
