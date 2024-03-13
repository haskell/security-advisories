{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Security.CWE (CWEID, unCWEID, mkCWEID, cweNames, cweIds) where

import Security.CWE.Data
import Data.Text (Text)
import Data.Coerce
import Data.Map.Strict as Map
import Data.Bits

-- | A CWE identifier.
newtype CWEID = CWEID Word
  deriving newtype (Eq, Ord, Show)

-- | Access the underlying data.
unCWEID :: CWEID -> Word
unCWEID (CWEID cwe) = cwe

mkCWEID :: (Integral a, Bits a) => a -> Maybe CWEID
mkCWEID num = CWEID <$> toIntegralSized num

-- | A map to lookup CWE names.
cweNames :: Map CWEID Text
cweNames = Map.fromList (coerce cweData)

-- | A map to lookup CWEID.
cweIds :: Map Text CWEID
cweIds = Map.fromList $ (\(k, v) -> (v, k)) <$> coerce cweData
