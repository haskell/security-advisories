module Security.Advisories.Generate.TH ( 
  readFileTH,
  readDirFilesTH,
  fileLocation,
  ) where

import Control.Monad.IO.Class (liftIO)
import Data.ByteString.Char8 as BS8
import Data.FileEmbed (embedDir, makeRelativeToLocationPredicate)
import Language.Haskell.TH (Exp (LitE), Lit (StringL), Q)

-- | Read file at compile-time.
readFileTH :: FilePath -> Q Exp
readFileTH p = fileLocation p $ \p' -> LitE . StringL . BS8.unpack <$> liftIO (BS8.readFile p')

-- | Read files in (sub-)directory at compile-time.
-- Gives a [(FilePath, ByteString)]
readDirFilesTH :: FilePath -> Q Exp
readDirFilesTH p = fileLocation p embedDir

fileLocation :: FilePath -> (FilePath -> Q Exp) -> Q Exp
fileLocation fp act = makeRelativeToLocationPredicate (== "hsec-tools.cabal") fp >>= act
