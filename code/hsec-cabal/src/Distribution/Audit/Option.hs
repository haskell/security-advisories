-- TODO(mangoiv): implement a proper parser as well as proper options to
-- - use constraints from a cabal file
-- - use a cabal.freeze file
-- - solve and then use cabal.freeze obtained
module Distribution.Audit.Option
  ( CabalAuditOptions (..)
  , cabalAuditParser
  )
where

import GHC.Generics (Generic)
import Options.Applicative (Parser)

data CabalAuditOptions = MkCabalAuditOptions {}
  deriving stock (Eq, Ord, Show, Generic)

cabalAuditParser :: Parser CabalAuditOptions
cabalAuditParser = pure MkCabalAuditOptions
