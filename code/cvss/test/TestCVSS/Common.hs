{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module TestCVSS.Common
  ( -- * CVSS 3.1/3.0 types
    Base31 (..),
    base31Vector,
    base30Vector,
    cvss31Vector,

    -- * CVSS 2.0 types
    Base20 (..),
    base20Vector,
    Temporal20 (..),
    temporal20Vector,
    Env20 (..),
    env20Vector,
    full20Vector,
    allNDEnv,

    -- * CVSS 3.x types
    Temporal3x (..),
    temporal3xVector,
    Env3x (..),
    env3xVector,
    full30Vector,
    full31TemporalVector,
    full31EnvVector,
    allXEnv3x,

    -- * CVSS 4.0 types
    Base40 (..),
    base40Vector,
    Env40 (..),
    env40Vector,
    full40Vector,
    allXEnv,

    -- * Helpers
    metric,
    metric20,
    notDefinedTemporalEnv,

    -- * Test helpers
    scoreTestCase,
    officialTestCaseV3X,
  )
where

import Data.Text (Text)
import qualified Data.Text as Text
import OfficialExamples (OfficialExample (..))
import qualified Security.CVSS as CVSS
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

metric :: Text -> Char -> Text
metric name value = name <> ":" <> Text.singleton value

metric20 :: Text -> Text -> Text
metric20 name value = name <> ":" <> value

cvss31Vector :: [Text] -> Text
cvss31Vector metrics = Text.intercalate "/" ("CVSS:3.1" : metrics)

notDefinedTemporalEnv :: Text
notDefinedTemporalEnv =
  "/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"

-- | Create a single testCase from a (vector, score, rating) triple.
scoreTestCase :: (Text, Float, CVSS.Rating) -> TestTree
scoreTestCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Left e -> assertFailure (show e)
      Right cvss -> do
        CVSS.cvssScore cvss @?= (rating, score)
        CVSS.cvssVectorString cvss @?= cvssString
        CVSS.cvssVectorStringOrdered cvss @?= cvssString

-- ------------------------------------------------------------------
-- CVSS 3.1 / 3.0 base
-- ------------------------------------------------------------------

data Base31 = Base31
  { bAV :: Char,
    bAC :: Char,
    bPR :: Char,
    bUI :: Char,
    bS :: Char,
    bC :: Char,
    bI :: Char,
    bA :: Char
  }
  deriving (Eq, Show)

instance Arbitrary Base31 where
  arbitrary =
    Base31
      <$> elements ['N', 'A', 'L', 'P']
      <*> elements ['L', 'H']
      <*> elements ['N', 'L', 'H']
      <*> elements ['N', 'R']
      <*> elements ['U', 'C']
      <*> elements ['H', 'L', 'N']
      <*> elements ['H', 'L', 'N']
      <*> elements ['H', 'L', 'N']

base31Vector :: Base31 -> Text
base31Vector b =
  cvss31Vector
    [ metric "AV" (bAV b),
      metric "AC" (bAC b),
      metric "PR" (bPR b),
      metric "UI" (bUI b),
      metric "S" (bS b),
      metric "C" (bC b),
      metric "I" (bI b),
      metric "A" (bA b)
    ]

base30Vector :: Base31 -> Text
base30Vector b =
  Text.intercalate
    "/"
    [ "CVSS:3.0",
      metric "AV" (bAV b),
      metric "AC" (bAC b),
      metric "PR" (bPR b),
      metric "UI" (bUI b),
      metric "S" (bS b),
      metric "C" (bC b),
      metric "I" (bI b),
      metric "A" (bA b)
    ]

-- ------------------------------------------------------------------
-- CVSS 2.0 types
-- ------------------------------------------------------------------

data Base20 = Base20
  { b20AV :: Text,
    b20AC :: Text,
    b20Au :: Text,
    b20C :: Text,
    b20I :: Text,
    b20A :: Text
  }
  deriving (Eq, Show)

instance Arbitrary Base20 where
  arbitrary =
    Base20
      <$> elements ["L", "A", "N"]
      <*> elements ["H", "M", "L"]
      <*> elements ["M", "S", "N"]
      <*> elements ["N", "P", "C"]
      <*> elements ["N", "P", "C"]
      <*> elements ["N", "P", "C"]

data Temporal20 = Temporal20
  { t20E :: Text,
    t20RL :: Text,
    t20RC :: Text
  }
  deriving (Eq, Show)

instance Arbitrary Temporal20 where
  arbitrary =
    Temporal20
      <$> elements ["ND", "U", "POC", "F", "H"]
      <*> elements ["ND", "OF", "TF", "W", "U"]
      <*> elements ["ND", "UC", "UR", "C"]

data Env20 = Env20
  { e20CR :: Text,
    e20IR :: Text,
    e20AR :: Text,
    e20CDP :: Text,
    e20TD :: Text
  }
  deriving (Eq, Show)

instance Arbitrary Env20 where
  arbitrary =
    Env20
      <$> elements ["ND", "L", "M", "H"]
      <*> elements ["ND", "L", "M", "H"]
      <*> elements ["ND", "L", "M", "H"]
      <*> elements ["ND", "N", "L", "LM", "MH", "H"]
      <*> elements ["ND", "N", "L", "M", "H"]

base20Vector :: Base20 -> Text
base20Vector b =
  Text.intercalate
    "/"
    [ metric20 "AV" (b20AV b),
      metric20 "AC" (b20AC b),
      metric20 "Au" (b20Au b),
      metric20 "C" (b20C b),
      metric20 "I" (b20I b),
      metric20 "A" (b20A b)
    ]

temporal20Vector :: Temporal20 -> Text
temporal20Vector t =
  Text.intercalate
    "/"
    [ metric20 "E" (t20E t),
      metric20 "RL" (t20RL t),
      metric20 "RC" (t20RC t)
    ]

env20Vector :: Env20 -> Text
env20Vector e =
  Text.intercalate
    "/"
    [ metric20 "CR" (e20CR e),
      metric20 "IR" (e20IR e),
      metric20 "AR" (e20AR e),
      metric20 "CDP" (e20CDP e),
      metric20 "TD" (e20TD e)
    ]

full20Vector :: Base20 -> Temporal20 -> Env20 -> Text
full20Vector b t e =
  base20Vector b <> "/" <> temporal20Vector t <> "/" <> env20Vector e

allNDEnv :: Env20
allNDEnv =
  Env20
    { e20CR = "ND",
      e20IR = "ND",
      e20AR = "ND",
      e20CDP = "ND",
      e20TD = "H"
    }

-- ------------------------------------------------------------------
-- CVSS 3.x temporal / environmental
-- ------------------------------------------------------------------

data Temporal3x = Temporal3x
  { t3xE :: Char,
    t3xRL :: Char,
    t3xRC :: Char
  }
  deriving (Eq, Show)

instance Arbitrary Temporal3x where
  arbitrary =
    Temporal3x
      <$> elements ['X', 'H', 'F', 'P', 'U']
      <*> elements ['X', 'U', 'W', 'T', 'O']
      <*> elements ['X', 'C', 'R', 'U']

data Env3x = Env3x
  { e3xCR :: Char,
    e3xIR :: Char,
    e3xAR :: Char,
    e3xMAV :: Char,
    e3xMAC :: Char,
    e3xMPR :: Char,
    e3xMUI :: Char,
    e3xMS :: Char,
    e3xMC :: Char,
    e3xMI :: Char,
    e3xMA :: Char
  }
  deriving (Eq, Show)

instance Arbitrary Env3x where
  arbitrary =
    Env3x
      <$> elements ['X', 'H', 'M', 'L']
      <*> elements ['X', 'H', 'M', 'L']
      <*> elements ['X', 'H', 'M', 'L']
      <*> elements ['X', 'N', 'A', 'L', 'P']
      <*> elements ['X', 'L', 'H']
      <*> elements ['X', 'N', 'L', 'H']
      <*> elements ['X', 'N', 'R']
      <*> elements ['X', 'U', 'C']
      <*> elements ['X', 'H', 'L', 'N']
      <*> elements ['X', 'H', 'L', 'N']
      <*> elements ['X', 'H', 'L', 'N']

temporal3xVector :: Temporal3x -> Text
temporal3xVector t =
  Text.intercalate
    "/"
    [ metric "E" (t3xE t),
      metric "RL" (t3xRL t),
      metric "RC" (t3xRC t)
    ]

env3xVector :: Env3x -> Text
env3xVector e =
  Text.intercalate
    "/"
    [ metric "CR" (e3xCR e),
      metric "IR" (e3xIR e),
      metric "AR" (e3xAR e),
      metric "MAV" (e3xMAV e),
      metric "MAC" (e3xMAC e),
      metric "MPR" (e3xMPR e),
      metric "MUI" (e3xMUI e),
      metric "MS" (e3xMS e),
      metric "MC" (e3xMC e),
      metric "MI" (e3xMI e),
      metric "MA" (e3xMA e)
    ]

full30Vector :: Base31 -> Temporal3x -> Env3x -> Text
full30Vector b t e =
  base30Vector b <> "/" <> temporal3xVector t <> "/" <> env3xVector e

full31TemporalVector :: Base31 -> Temporal3x -> Text
full31TemporalVector b t =
  base31Vector b <> "/" <> temporal3xVector t

full31EnvVector :: Base31 -> Temporal3x -> Env3x -> Text
full31EnvVector b t e =
  base31Vector b <> "/" <> temporal3xVector t <> "/" <> env3xVector e

allXEnv3x :: Env3x
allXEnv3x =
  Env3x
    { e3xCR = 'X',
      e3xIR = 'X',
      e3xAR = 'X',
      e3xMAV = 'X',
      e3xMAC = 'X',
      e3xMPR = 'X',
      e3xMUI = 'X',
      e3xMS = 'X',
      e3xMC = 'X',
      e3xMI = 'X',
      e3xMA = 'X'
    }

-- ------------------------------------------------------------------
-- CVSS 4.0 types
-- ------------------------------------------------------------------

data Base40 = Base40
  { b40AV :: Char,
    b40AC :: Char,
    b40AT :: Char,
    b40PR :: Char,
    b40UI :: Char,
    b40VC :: Char,
    b40VI :: Char,
    b40VA :: Char,
    b40SC :: Char,
    b40SI :: Char,
    b40SA :: Char
  }
  deriving (Eq, Show)

instance Arbitrary Base40 where
  arbitrary =
    Base40
      <$> elements ['N', 'A', 'L', 'P']
      <*> elements ['L', 'H']
      <*> elements ['N', 'P']
      <*> elements ['N', 'L', 'H']
      <*> elements ['N', 'A', 'P']
      <*> elements ['H', 'L', 'N']
      <*> elements ['H', 'L', 'N']
      <*> elements ['H', 'L', 'N']
      <*> elements ['H', 'L', 'N']
      <*> elements ['H', 'L', 'N']
      <*> elements ['H', 'L', 'N']

data Env40 = Env40
  { e40CR :: Char,
    e40IR :: Char,
    e40AR :: Char,
    e40MAV :: Char,
    e40MAC :: Char,
    e40MAT :: Char,
    e40MPR :: Char,
    e40MUI :: Char,
    e40MVC :: Char,
    e40MVI :: Char,
    e40MVA :: Char,
    e40MSC :: Char,
    e40MSI :: Char,
    e40MSA :: Char
  }
  deriving (Eq, Show)

instance Arbitrary Env40 where
  arbitrary =
    Env40
      <$> elements ['X', 'L', 'M', 'H']
      <*> elements ['X', 'L', 'M', 'H']
      <*> elements ['X', 'L', 'M', 'H']
      <*> elements ['X', 'N', 'A', 'L', 'P']
      <*> elements ['X', 'L', 'H']
      <*> elements ['X', 'N', 'P']
      <*> elements ['X', 'N', 'L', 'H']
      <*> elements ['X', 'N', 'P', 'A']
      <*> elements ['X', 'H', 'L', 'N']
      <*> elements ['X', 'H', 'L', 'N']
      <*> elements ['X', 'H', 'L', 'N']
      <*> elements ['X', 'H', 'L', 'N']
      <*> elements ['X', 'S', 'H', 'L', 'N']
      <*> elements ['X', 'S', 'H', 'L', 'N']

cvss40Vector :: [Text] -> Text
cvss40Vector metrics = Text.intercalate "/" ("CVSS:4.0" : metrics)

base40Vector :: Base40 -> Text
base40Vector b =
  cvss40Vector
    [ metric "AV" (b40AV b),
      metric "AC" (b40AC b),
      metric "AT" (b40AT b),
      metric "PR" (b40PR b),
      metric "UI" (b40UI b),
      metric "VC" (b40VC b),
      metric "VI" (b40VI b),
      metric "VA" (b40VA b),
      metric "SC" (b40SC b),
      metric "SI" (b40SI b),
      metric "SA" (b40SA b)
    ]

env40Vector :: Env40 -> Text
env40Vector e =
  Text.intercalate
    "/"
    [ metric "CR" (e40CR e),
      metric "IR" (e40IR e),
      metric "AR" (e40AR e),
      metric "MAV" (e40MAV e),
      metric "MAC" (e40MAC e),
      metric "MAT" (e40MAT e),
      metric "MPR" (e40MPR e),
      metric "MUI" (e40MUI e),
      metric "MVC" (e40MVC e),
      metric "MVI" (e40MVI e),
      metric "MVA" (e40MVA e),
      metric "MSC" (e40MSC e),
      metric "MSI" (e40MSI e),
      metric "MSA" (e40MSA e)
    ]

full40Vector :: Base40 -> Env40 -> Text
full40Vector b e = base40Vector b <> "/" <> env40Vector e

allXEnv :: Env40
allXEnv =
  Env40
    { e40CR = 'X',
      e40IR = 'X',
      e40AR = 'X',
      e40MAV = 'X',
      e40MAC = 'X',
      e40MAT = 'X',
      e40MPR = 'X',
      e40MUI = 'X',
      e40MVC = 'X',
      e40MVI = 'X',
      e40MVA = 'X',
      e40MSC = 'X',
      e40MSI = 'X',
      e40MSA = 'X'
    }

-- ------------------------------------------------------------------
-- Shared official-test helper (used by V30 and V31)
-- ------------------------------------------------------------------

officialTestCaseV3X :: OfficialExample -> TestTree
officialTestCaseV3X ex =
  testCase (Text.unpack $ oeVector ex) $
    case CVSS.parseCVSS (oeVector ex) of
      Left e -> assertFailure (show e)
      Right cvss -> do
        let (rating, score) = CVSS.cvssScore cvss
        score @?= oeBaseScore ex
        rating @?= oeBaseRating ex
