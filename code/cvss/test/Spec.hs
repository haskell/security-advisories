{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import Data.Text (Text)
import qualified Data.Text as Text
import OfficialExamples (OfficialExample (..), cvss20OfficialExamples, cvss30OfficialExamples, cvss31OfficialExamples, cvss40OfficialExamples)
import qualified Security.CVSS as CVSS
import qualified Security.CVSS.V40 as V40
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

main :: IO ()
main =
  defaultMain $
    testGroup
      "Security.CVSS"
      [ testCase "score examples" testExamples,
        testCase "temporal score examples" testTemporalScore,
        testCase "environmental score examples" testEnvironmentalScore,
        testCase
          "CVSS 3.1 X temporal/env metrics do not change score"
          testNotDefinedOptionalNoScoreChange,
        testProperty "CVSS 3.1 parser preserves original vector string" prop_cvss31RoundTrip,
        testCase "CVSS v3.0 temporal score examples" testCVSS30TemporalScore,
        testCase "CVSS v3.0 ND temporal metrics do not change score" testCVSS30NotDefinedNoScoreChange,
        testCase "CVSS v3.0 environmental score examples" testCVSS30EnvironmentalScore,
        testCase "CVSS v3.0 ND environmental metrics do not change score" testCVSS30EnvironmentalNotDefinedNoScoreChange,
        testCase "CVSS v2.0 rating boundary tests" testCVSS20RatingBoundaries,
        testCase "CVSS v2.0 temporal score examples" testCVSS20TemporalScore,
        testCase "CVSS v2.0 ND temporal metrics do not change score" testCVSS20NotDefinedNoScoreChange,
        testCase "CVSS v2.0 environmental score examples" testCVSS20EnvironmentalScore,
        testCase "CVSS v2.0 ND environmental metrics do not change score" testCVSS20EnvironmentalNotDefinedNoScoreChange,
        testCase "CVSS v4.0 parsing tests" testCVSS40Parsing,
        testGroup "CVSS v4.0 base score examples" $ cvss40ScoringCase <$> cvss40ScoringExamples,
        testGroup "CVSS v4.0 expanded base score tests" $ cvss40ScoringCase <$> cvss40ExpandedExamples,
        testGroup "CVSS v4.0 direct baseScore tests" $ cvss40BaseScoreCase <$> cvss40BaseScoreExamples,
        testGroup "CVSS v4.0 threat score examples" $ cvss40BaseScoreCase <$> cvss40ThreatExamples,
        testCase "CVSS v4.0 threat score examples" testCVSS40ThreatScore,
        testCase "CVSS v4.0 environmental score examples" testCVSS40EnvironmentalScore,
        testCase "CVSS v4.0 parsing with optional metrics" testCVSS40ParsingWithOptional,
        testCase "CVSS v4.0 X metrics do not change score" testCVSS40XMetricsNoScoreChange,
        testProperty "CVSS v4.0 parser preserves original vector string" prop_cvss40RoundTrip,
        testProperty "CVSS v4.0 environmental parser preserves original vector string" prop_cvss40EnvRoundTrip,
        testProperty "CVSS v4.0 all-X environmental metrics do not change score" prop_cvss40EnvXNoScoreChange,
        testProperty "CVSS v4.0 environmental score is in [0, 10]" prop_cvss40EnvScoreBounds,
        testProperty "CVSS v4.0 environmental rating is consistent with score" prop_cvss40EnvRatingConsistency,
        testGroup
          "QuickCheck Properties - CVSS v2.0"
          [ testProperty "temporal ≤ base" prop_v20_temporalLEBase,
            testProperty "ND temporal doesn't change score" prop_v20_ndTemporalNoChange,
            testProperty "ND env doesn't change score" prop_v20_ndEnvNoChange,
            testProperty "temporal score in [0, 10]" prop_v20_temporalScoreBounds,
            testProperty "env score in [0, 10]" prop_v20_envScoreBounds,
            testProperty "TD:N results in score 0" prop_v20_tdNoneZero,
            testProperty "env ≤ temporal when CR/IR/AR=ND and CDP=ND" prop_v20_envLETemporal,
            testProperty "full vector roundtrip" prop_v20_fullRoundTrip
          ],
        testGroup
          "QuickCheck Properties - CVSS v3.0"
          [ testProperty "temporal ≤ base" prop_v30_temporalLEBase,
            testProperty "ND temporal doesn't change score" prop_v30_ndTemporalNoChange,
            testProperty "ND env doesn't change score" prop_v30_ndEnvNoChange,
            testProperty "temporal score in [0, 10]" prop_v30_temporalScoreBounds,
            testProperty "env score in [0, 10]" prop_v30_envScoreBounds,
            testProperty "env rating consistent with score" prop_v30_envRatingConsistency,
            testProperty "full vector roundtrip" prop_v30_fullRoundTrip
          ],
        testGroup
          "QuickCheck Properties - CVSS v3.1"
          [ testProperty "temporal ≤ base" prop_v31_temporalLEBase,
            testProperty "ND temporal doesn't change score" prop_v31_ndTemporalNoChange,
            testProperty "ND env doesn't change score" prop_v31_ndEnvNoChange,
            testProperty "temporal score in [0, 10]" prop_v31_temporalScoreBounds,
            testProperty "env score in [0, 10]" prop_v31_envScoreBounds,
            testProperty "env rating consistent with score" prop_v31_envRatingConsistency,
            testProperty "temporal vector roundtrip" prop_v31_temporalRoundTrip
          ],
        testCase "CVSS v4.0 rating boundary tests" testCVSS40RatingBoundaries,
        testGroup
          "Official FIRST cross-validation"
          [ testGroup "CVSS v2.0" $ officialTestCaseV20 <$> cvss20OfficialExamples,
            testGroup "CVSS v3.0" $ officialTestCaseV3X <$> cvss30OfficialExamples,
            testGroup "CVSS v3.1" $ officialTestCaseV3X <$> cvss31OfficialExamples,
            testGroup "CVSS v4.0" $ officialTestCaseV40 <$> cvss40OfficialExamples
          ]
      ]

testExamples :: Assertion
testExamples =
  forM_ examples $ \(cvssString, score, rating) -> do
    case CVSS.parseCVSS cvssString of
      Left e -> assertFailure (show e)
      Right cvss -> do
        CVSS.cvssScore cvss @?= (rating, score)
        CVSS.cvssVectorString cvss @?= cvssString
        CVSS.cvssVectorStringOrdered cvss @?= cvssString

examples :: [(Text, Float, CVSS.Rating)]
examples =
  [ ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8, CVSS.Medium),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, CVSS.Medium),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, CVSS.Low),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, CVSS.High),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, CVSS.Medium),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, CVSS.Medium),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, CVSS.Low),
    ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.0, CVSS.Medium),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, CVSS.Critical),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2, CVSS.Medium),
    ("AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8, CVSS.High),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10, CVSS.High),
    ("AV:L/AC:H/Au:N/C:C/I:C/A:C", 6.2, CVSS.Medium),
    ("AV:N/AC:M/Au:N/C:P/I:N/A:N", 4.3, CVSS.Medium),
    ( "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
      9.8,
      CVSS.Critical
    ),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.7, CVSS.High),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.7, CVSS.High)
  ]

testTemporalScore :: Assertion
testTemporalScore =
  forM_ temporalScoreExamples $ \(cvssString, score, rating) -> do
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS31, CVSS.cvssMetrics = cm} -> do
        CVSS.cvss31TemporalScore cm @?= (rating, score)
      other -> assertFailure (show other)

temporalScoreExamples :: [(Text, Float, CVSS.Rating)]
temporalScoreExamples =
  [ ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.0, CVSS.High),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/E:F/RL:O/RC:R", 6.7, CVSS.Medium),
    ( "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
      9.8,
      CVSS.Critical
    ),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.7, CVSS.High)
  ]

testEnvironmentalScore :: Assertion
testEnvironmentalScore =
  forM_ environmentalScoreExamples $ \(cvssString, score, rating) -> do
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS31, CVSS.cvssMetrics = cm} -> do
        CVSS.cvss31EnvironmentalScore cm @?= (rating, score)
      other -> assertFailure (show other)

environmentalScoreExamples :: [(Text, Float, CVSS.Rating)]
environmentalScoreExamples =
  [ -- https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/E:F/RL:X/RC:X/CR:L/IR:M/AR:H/MAV:N/MAC:L/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:N&version=3.1
    ( "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/E:F/CR:L/IR:M/AR:H/MAV:N/MAC:L/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:N",
      6.5,
      CVSS.Medium
    ),
    ( "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
      9.8,
      CVSS.Critical
    ),
    -- Tests Modified Scope + MPR changed-scope override.
    -- MPR:H should use 0.50 when MS:C, not 0.27.
    ( "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:L/MA:N",
      5.5,
      CVSS.Medium
    )
  ]

testNotDefinedOptionalNoScoreChange :: Assertion
testNotDefinedOptionalNoScoreChange = do
  let baseVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      fullVector = baseVector <> notDefinedTemporalEnv
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right baseCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore baseCvss
    _ -> assertFailure ("base parse failed: " <> show fullVector)

-- CVSS.cvssVectorString <$> CVSS.parseCVSS input == Right input
prop_cvss31RoundTrip :: Base31 -> Property
prop_cvss31RoundTrip b =
  let input = base31Vector b <> notDefinedTemporalEnv
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left e -> counterexample ("parse failed: " <> show e <> "\n" <> Text.unpack input) False

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

metric :: Text -> Char -> Text
metric name value = name <> ":" <> Text.singleton value

cvss31Vector :: [Text] -> Text
cvss31Vector metrics = Text.intercalate "/" ("CVSS:3.1" : metrics)

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

metric20 :: Text -> Text -> Text
metric20 name value = name <> ":" <> value

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

notDefinedTemporalEnv :: Text
notDefinedTemporalEnv =
  "/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"

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

full20Vector :: Base20 -> Temporal20 -> Env20 -> Text
full20Vector b t e =
  base20Vector b <> "/" <> temporal20Vector t <> "/" <> env20Vector e

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

allNDEnv :: Env20
allNDEnv =
  Env20
    { e20CR = "ND",
      e20IR = "ND",
      e20AR = "ND",
      e20CDP = "ND",
      e20TD = "H"
    }

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

prop_v20_temporalLEBase :: Base20 -> Temporal20 -> Property
prop_v20_temporalLEBase b t =
  let baseInput = base20Vector b
      temporalInput = baseInput <> "/" <> temporal20Vector t
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS temporalInput) of
        (Right baseCvss, Right temporalCvss) ->
          let (_, baseScore) = CVSS.cvssScore baseCvss
              (_, temporalScore) = CVSS.cvss20TemporalScore (CVSS.cvssMetrics temporalCvss)
           in property $ temporalScore <= baseScore
        _ -> counterexample "parse failed" False

prop_v30_temporalLEBase :: Base31 -> Temporal3x -> Property
prop_v30_temporalLEBase b t =
  let baseInput = base30Vector b
      temporalInput = baseInput <> "/" <> temporal3xVector t
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS temporalInput) of
        (Right baseCvss, Right temporalCvss) ->
          let (_, baseScore) = CVSS.cvssScore baseCvss
              (_, temporalScore) = CVSS.cvss30TemporalScore (CVSS.cvssMetrics temporalCvss)
           in property $ temporalScore <= baseScore
        _ -> counterexample "parse failed" False

prop_v31_temporalLEBase :: Base31 -> Temporal3x -> Property
prop_v31_temporalLEBase b t =
  let baseInput = base31Vector b
      temporalInput = baseInput <> "/" <> temporal3xVector t
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS temporalInput) of
        (Right baseCvss, Right temporalCvss) ->
          let (_, baseScore) = CVSS.cvssScore baseCvss
              (_, temporalScore) = CVSS.cvss31TemporalScore (CVSS.cvssMetrics temporalCvss)
           in property $ temporalScore <= baseScore
        _ -> counterexample "parse failed" False

prop_v20_ndTemporalNoChange :: Base20 -> Property
prop_v20_ndTemporalNoChange b =
  let baseInput = base20Vector b
      ndTemporal = "/E:ND/RL:ND/RC:ND"
      temporalInput = baseInput <> ndTemporal
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS temporalInput) of
        (Right baseCvss, Right temporalCvss) ->
          CVSS.cvssScore baseCvss === CVSS.cvss20TemporalScore (CVSS.cvssMetrics temporalCvss)
        _ -> counterexample "parse failed" False

prop_v30_ndTemporalNoChange :: Base31 -> Property
prop_v30_ndTemporalNoChange b =
  let baseInput = base30Vector b
      ndTemporal = "/E:X/RL:X/RC:X"
      temporalInput = baseInput <> ndTemporal
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS temporalInput) of
        (Right baseCvss, Right temporalCvss) ->
          CVSS.cvssScore baseCvss === CVSS.cvss30TemporalScore (CVSS.cvssMetrics temporalCvss)
        _ -> counterexample "parse failed" False

prop_v31_ndTemporalNoChange :: Base31 -> Property
prop_v31_ndTemporalNoChange b =
  let baseInput = base31Vector b
      ndTemporal = "/E:X/RL:X/RC:X"
      temporalInput = baseInput <> ndTemporal
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS temporalInput) of
        (Right baseCvss, Right temporalCvss) ->
          CVSS.cvssScore baseCvss === CVSS.cvss31TemporalScore (CVSS.cvssMetrics temporalCvss)
        _ -> counterexample "parse failed" False

prop_v20_ndEnvNoChange :: Base20 -> Temporal20 -> Property
prop_v20_ndEnvNoChange b t =
  let temporalInput = base20Vector b <> "/" <> temporal20Vector t
      ndEnv = "/CR:ND/IR:ND/AR:ND/CDP:ND/TD:ND"
      envInput = temporalInput <> ndEnv
   in case (CVSS.parseCVSS temporalInput, CVSS.parseCVSS envInput) of
        (Right temporalCvss, Right envCvss) ->
          CVSS.cvss20TemporalScore (CVSS.cvssMetrics temporalCvss) === CVSS.cvss20EnvironmentalScore (CVSS.cvssMetrics envCvss)
        _ -> counterexample "parse failed" False

prop_v30_ndEnvNoChange :: Base31 -> Temporal3x -> Property
prop_v30_ndEnvNoChange b t =
  let temporalInput = base30Vector b <> "/" <> temporal3xVector t
      ndEnv = "/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
      envInput = temporalInput <> ndEnv
   in case (CVSS.parseCVSS temporalInput, CVSS.parseCVSS envInput) of
        (Right temporalCvss, Right envCvss) ->
          CVSS.cvss30TemporalScore (CVSS.cvssMetrics temporalCvss) === CVSS.cvss30EnvironmentalScore (CVSS.cvssMetrics envCvss)
        _ -> counterexample "parse failed" False

prop_v31_ndEnvNoChange :: Base31 -> Temporal3x -> Property
prop_v31_ndEnvNoChange b t =
  let temporalInput = base31Vector b <> "/" <> temporal3xVector t
      ndEnv = "/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
      envInput = temporalInput <> ndEnv
   in case (CVSS.parseCVSS temporalInput, CVSS.parseCVSS envInput) of
        (Right temporalCvss, Right envCvss) ->
          CVSS.cvss31TemporalScore (CVSS.cvssMetrics temporalCvss) === CVSS.cvss31EnvironmentalScore (CVSS.cvssMetrics envCvss)
        _ -> counterexample "parse failed" False

prop_v20_temporalScoreBounds :: Base20 -> Temporal20 -> Property
prop_v20_temporalScoreBounds b t =
  let temporalInput = base20Vector b <> "/" <> temporal20Vector t
   in case CVSS.parseCVSS temporalInput of
        Right cvss ->
          let (_, score) = CVSS.cvss20TemporalScore (CVSS.cvssMetrics cvss)
           in score >= 0.0 .&&. score <= 10.0
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v30_temporalScoreBounds :: Base31 -> Temporal3x -> Property
prop_v30_temporalScoreBounds b t =
  let temporalInput = base30Vector b <> "/" <> temporal3xVector t
   in case CVSS.parseCVSS temporalInput of
        Right cvss ->
          let (_, score) = CVSS.cvss30TemporalScore (CVSS.cvssMetrics cvss)
           in score >= 0.0 .&&. score <= 10.0
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v31_temporalScoreBounds :: Base31 -> Temporal3x -> Property
prop_v31_temporalScoreBounds b t =
  let temporalInput = base31Vector b <> "/" <> temporal3xVector t
   in case CVSS.parseCVSS temporalInput of
        Right cvss ->
          let (_, score) = CVSS.cvss31TemporalScore (CVSS.cvssMetrics cvss)
           in score >= 0.0 .&&. score <= 10.0
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v20_envScoreBounds :: Base20 -> Temporal20 -> Env20 -> Property
prop_v20_envScoreBounds b t e =
  let envInput = full20Vector b t e
   in case CVSS.parseCVSS envInput of
        Right cvss ->
          let (_, score) = CVSS.cvss20EnvironmentalScore (CVSS.cvssMetrics cvss)
           in score >= 0.0 .&&. score <= 10.0
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v30_envScoreBounds :: Base31 -> Temporal3x -> Env3x -> Property
prop_v30_envScoreBounds b t e =
  let envInput = full30Vector b t e
   in case CVSS.parseCVSS envInput of
        Right cvss ->
          let (_, score) = CVSS.cvss30EnvironmentalScore (CVSS.cvssMetrics cvss)
           in score >= 0.0 .&&. score <= 10.0
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v31_envScoreBounds :: Base31 -> Temporal3x -> Env3x -> Property
prop_v31_envScoreBounds b t e =
  let envInput = full31EnvVector b t e
   in case CVSS.parseCVSS envInput of
        Right cvss ->
          let (_, score) = CVSS.cvss31EnvironmentalScore (CVSS.cvssMetrics cvss)
           in score >= 0.0 .&&. score <= 10.0
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v20_tdNoneZero :: Base20 -> Temporal20 -> Property
prop_v20_tdNoneZero b t =
  let envInput = base20Vector b <> "/" <> temporal20Vector t <> "/CR:ND/IR:ND/AR:ND/CDP:ND/TD:N"
   in case CVSS.parseCVSS envInput of
        Right cvss ->
          let (_, score) = CVSS.cvss20EnvironmentalScore (CVSS.cvssMetrics cvss)
           in score === 0.0
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v20_envLETemporal :: Base20 -> Temporal20 -> Property
prop_v20_envLETemporal b t =
  let envInput = base20Vector b <> "/" <> temporal20Vector t <> "/CR:ND/IR:ND/AR:ND/CDP:ND/TD:ND"
   in case CVSS.parseCVSS envInput of
        Right envCvss ->
          let (_, envScore) = CVSS.cvss20EnvironmentalScore (CVSS.cvssMetrics envCvss)
              (_, temporalScore) = CVSS.cvss20TemporalScore (CVSS.cvssMetrics envCvss)
           in property $ envScore <= temporalScore
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v20_fullRoundTrip :: Base20 -> Temporal20 -> Env20 -> Property
prop_v20_fullRoundTrip b t e =
  let input = full20Vector b t e
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v30_fullRoundTrip :: Base31 -> Temporal3x -> Env3x -> Property
prop_v30_fullRoundTrip b t e =
  let input = full30Vector b t e
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v31_temporalRoundTrip :: Base31 -> Temporal3x -> Property
prop_v31_temporalRoundTrip b t =
  let input = full31TemporalVector b t
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v31_envRatingConsistency :: Base31 -> Temporal3x -> Env3x -> Property
prop_v31_envRatingConsistency b t e =
  let envInput = full31EnvVector b t e
   in case CVSS.parseCVSS envInput of
        Right cvss ->
          let (rating, score) = CVSS.cvss31EnvironmentalScore (CVSS.cvssMetrics cvss)
           in rating === CVSS.toRating score
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v30_envRatingConsistency :: Base31 -> Temporal3x -> Env3x -> Property
prop_v30_envRatingConsistency b t e =
  let envInput = full30Vector b t e
   in case CVSS.parseCVSS envInput of
        Right cvss ->
          let (rating, score) = CVSS.cvss30EnvironmentalScore (CVSS.cvssMetrics cvss)
           in rating === CVSS.toRating score
        Left err -> counterexample ("parse failed: " <> show err) False

testCVSS20RatingBoundaries :: Assertion
testCVSS20RatingBoundaries =
  forM_ cvss20BoundaryTests $ \(score, expectedRating) -> do
    CVSS.toRating20 score @?= expectedRating

cvss20BoundaryTests :: [(Float, CVSS.Rating)]
cvss20BoundaryTests =
  [ (0, CVSS.None), -- Score 0 maps to None
    (0.1, CVSS.Low), -- Low: 0.0-3.9
    (3.9, CVSS.Low), -- Upper bound of Low
    (4.0, CVSS.Medium), -- Medium: 4.0-6.9
    (6.9, CVSS.Medium), -- Upper bound of Medium
    (7.0, CVSS.High), -- High: 7.0-10.0
    (9.0, CVSS.High), -- Scores that would be Critical in v3.1 are High in v2
    (10, CVSS.High) -- Maximum score
  ]

testCVSS20TemporalScore :: Assertion
testCVSS20TemporalScore =
  forM_ cvss20TemporalExamples $ \(cvssString, score, rating) -> do
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS20, CVSS.cvssMetrics = cm} -> do
        CVSS.cvss20TemporalScore cm @?= (rating, score)
      other -> assertFailure (show other)

cvss20TemporalExamples :: [(Text, Float, CVSS.Rating)]
cvss20TemporalExamples =
  [ -- High severity base with ND temporal (should give same score as base)
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND", 10.0, CVSS.High),
    ("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:ND/RL:ND/RC:ND", 7.8, CVSS.High)
  ]

testCVSS20NotDefinedNoScoreChange :: Assertion
testCVSS20NotDefinedNoScoreChange = do
  let baseVector = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
      fullVector = baseVector <> "/E:ND/RL:ND/RC:ND"
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right baseCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore baseCvss
    _ -> assertFailure ("base or full vector parse failed")

testCVSS20EnvironmentalScore :: Assertion
testCVSS20EnvironmentalScore =
  forM_ cvss20EnvironmentalExamples $ \(cvssString, score, rating) -> do
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS20, CVSS.cvssMetrics = cm} -> do
        CVSS.cvss20EnvironmentalScore cm @?= (rating, score)
      other -> assertFailure (show other)

cvss20EnvironmentalExamples :: [(Text, Float, CVSS.Rating)]
cvss20EnvironmentalExamples =
  [ -- Base: AV:N/AC:L/Au:N/C:C/I:C/A:C = 10.0, all env metrics ND = 10.0
    ( "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND",
      10.0,
      CVSS.High
    ),
    -- High security requirements increase the adjusted impact
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:ND/TD:H/CR:H/IR:H/AR:H",
      7.8,
      CVSS.High
    ),
    -- Low security requirements decrease the adjusted impact
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:L/TD:H/CR:L/IR:L/AR:L",
      5.3,
      CVSS.Medium
    ),
    -- High CDP amplifies the score
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:F/RL:OF/RC:UC/CDP:H/TD:H/CR:M/IR:M/AR:M",
      7.4,
      CVSS.High
    ),
    -- TD:N (none) results in score 0
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:H/TD:N/CR:M/IR:M/AR:M",
      0,
      CVSS.None
    ),
    -- TD:L (low) reduces the score
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:H/TD:L/CR:M/IR:M/AR:M",
      2.0,
      CVSS.Low
    )
  ]

testCVSS20EnvironmentalNotDefinedNoScoreChange :: Assertion
testCVSS20EnvironmentalNotDefinedNoScoreChange = do
  let baseVector = "AV:N/AC:L/Au:N/C:P/I:P/A:N"
      fullVector = baseVector <> "/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND"
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right baseCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore baseCvss
    _ -> assertFailure ("base or full vector parse failed")

testCVSS30TemporalScore :: Assertion
testCVSS30TemporalScore =
  forM_ cvss30TemporalExamples $ \(cvssString, score, rating) -> do
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS30, CVSS.cvssMetrics = cm} -> do
        CVSS.cvss30TemporalScore cm @?= (rating, score)
      other -> assertFailure (show other)

cvss30TemporalExamples :: [(Text, Float, CVSS.Rating)]
cvss30TemporalExamples =
  [ ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.7, CVSS.High),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:F/RL:O/RC:R", 5.4, CVSS.Medium),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X", 9.8, CVSS.Critical)
  ]

testCVSS30NotDefinedNoScoreChange :: Assertion
testCVSS30NotDefinedNoScoreChange = do
  let baseVector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      fullVector = baseVector <> "/E:X/RL:X/RC:X"
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right baseCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore baseCvss
    _ -> assertFailure ("base or full vector parse failed")

testCVSS30EnvironmentalScore :: Assertion
testCVSS30EnvironmentalScore =
  forM_ cvss30EnvironmentalExamples $ \(cvssString, score, rating) -> do
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS30, CVSS.cvssMetrics = cm} -> do
        CVSS.cvss30EnvironmentalScore cm @?= (rating, score)
      other -> assertFailure (show other)

cvss30EnvironmentalExamples :: [(Text, Float, CVSS.Rating)]
cvss30EnvironmentalExamples =
  [ -- High security requirements increase the environmental score
    ( "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/E:F/CR:L/IR:M/AR:H/MAV:N/MAC:L/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:N",
      6.5,
      CVSS.Medium
    ),
    -- Tests Modified Scope + MPR changed-scope override
    ( "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:L/MA:N",
      5.5,
      CVSS.Medium
    )
  ]

testCVSS30EnvironmentalNotDefinedNoScoreChange :: Assertion
testCVSS30EnvironmentalNotDefinedNoScoreChange = do
  let temporalVector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R"
      fullVector = temporalVector <> "/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
  case (CVSS.parseCVSS temporalVector, CVSS.parseCVSS fullVector) of
    (Right temporalCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore temporalCvss
    _ -> assertFailure ("temporal or full vector parse failed")

testCVSS40Parsing :: Assertion
testCVSS40Parsing = do
  forM_ cvss40ValidVectors $ \(cvssString, expectedMetricsCount) ->
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = metrics} -> do
        length metrics @?= expectedMetricsCount
        CVSS.cvssVectorString (CVSS.CVSS CVSS.CVSS40 metrics) @?= cvssString
      other -> assertFailure $ "Failed to parse valid CVSS 4.0: " <> show other <> " for " <> show cvssString
  forM_ cvss40InvalidVectors $ \cvssString ->
    case CVSS.parseCVSS cvssString of
      Left _ -> pure ()
      Right _ -> assertFailure $ "Should have failed to parse: " <> show cvssString
  case CVSS.parseCVSS "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N" of
    Left _ -> pure ()
    Right _ -> assertFailure "CVSS 4.0 should require CVSS:4.0/ prefix (no legacy format)"

cvss40ValidVectors :: [(Text, Int)]
cvss40ValidVectors =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 11),
    ("CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N/E:X", 12),
    ("CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 11)
  ]

cvss40InvalidVectors :: [Text]
cvss40InvalidVectors =
  [ "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:INVALID",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/AV:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:S/SA:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:S"
  ]

cvss40ScoringCase :: (Text, Float, CVSS.Rating) -> TestTree
cvss40ScoringCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $ do
    case CVSS.parseCVSS cvssString of
      Left e -> assertFailure (show e)
      Right cvss -> do
        CVSS.cvssScore cvss @?= (rating, score)
        CVSS.cvssVectorString cvss @?= cvssString

cvss40ScoringExamples :: [(Text, Float, CVSS.Rating)]
cvss40ScoringExamples =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N", 9.5, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.3, CVSS.Critical),
    ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.7, CVSS.Critical),
    ("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 2.4, CVSS.Low),
    -- Additional verified examples from the lookup table
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.7, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.7, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.7, CVSS.Critical),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.7, CVSS.Critical),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.6, CVSS.Critical),
    ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.8, CVSS.Critical),
    ("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.7, CVSS.Critical),
    -- EQ3 tests (VC/VI/VA combinations)
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N", 9.3, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N", 8.8, CVSS.High),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N", 8.8, CVSS.High),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N", 8.4, CVSS.High),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N", 8.4, CVSS.High),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 6.9, CVSS.Medium),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 6.9, CVSS.Medium)
  ]

cvss40ExpandedExamples :: [(Text, Float, CVSS.Rating)]
cvss40ExpandedExamples =
  []

cvss40BaseScoreExamples :: [(Text, Float, CVSS.Rating)]
cvss40BaseScoreExamples =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.3, CVSS.Critical),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.7, CVSS.Critical),
    ("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 2.4, CVSS.Low)
  ]

cvss40EnvironmentalExamples :: [(Text, Float, CVSS.Rating)]
cvss40EnvironmentalExamples =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:S/MSA:X", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:H/IR:H/AR:H/MAV:L", 9.7, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:L/IR:L/AR:L", 9.6, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MVC:L", 9.6, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:S/MSA:X", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:S", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:S/MSA:S", 10.0, CVSS.Critical)
  ]

cvss40ThreatExamples :: [(Text, Float, CVSS.Rating)]
cvss40ThreatExamples =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:A", 9.3, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P", 8.9, CVSS.High),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U", 8.1, CVSS.High)
  ]

cvss40BaseScoreCase :: (Text, Float, CVSS.Rating) -> TestTree
cvss40BaseScoreCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $ do
    case CVSS.parseCVSS cvssString of
      Left e -> assertFailure (show e)
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = cm} -> do
        V40.cvss40BaseScore cm @?= (rating, score)
      other -> assertFailure $ "Not a CVSS 4.0 vector: " <> show other

testCVSS40EnvironmentalScore :: Assertion
testCVSS40EnvironmentalScore =
  forM_ cvss40EnvironmentalExamples $ \(cvssString, score, rating) -> do
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = cm} -> do
        CVSS.cvss40EnvironmentalScore cm @?= (rating, score)
      other -> assertFailure (show other)

testCVSS40ThreatScore :: Assertion
testCVSS40ThreatScore =
  forM_ cvss40ThreatExamples $ \(cvssString, score, rating) -> do
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = cm} -> do
        V40.cvss40ThreatScore cm @?= (rating, score)
      other -> assertFailure (show other)

testCVSS40ParsingWithOptional :: Assertion
testCVSS40ParsingWithOptional = do
  let vectors =
        [ -- Supplemental metrics
          ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:N", 12),
          ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:N/AU:N", 13),
          -- Threat metric
          ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X", 12),
          ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 12),
          ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", 12),
          ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 12),
          -- Environmental metrics (only supported ones)
          ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:H", 14),
          -- All optional metrics
          ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:N/AU:N/E:X/CR:X/IR:X/AR:X", 17)
        ]
  forM_ vectors $ \(cvssString, expectedCount) ->
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = cm} -> do
        length cm @?= expectedCount
        CVSS.cvssVectorString (CVSS.CVSS CVSS.CVSS40 cm) @?= cvssString
      other -> assertFailure $ "Failed to parse: " <> show other <> " for " <> show cvssString

testCVSS40XMetricsNoScoreChange :: Assertion
testCVSS40XMetricsNoScoreChange = do
  let baseVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      xMetrics = "/E:X/S:N/AU:N/CR:X/IR:X/AR:X"
      fullVector = baseVector <> xMetrics
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right CVSS.CVSS {CVSS.cvssMetrics = baseMetrics}, Right CVSS.CVSS {CVSS.cvssMetrics = fullMetrics}) -> do
      V40.cvss40BaseScore baseMetrics @?= V40.cvss40BaseScore fullMetrics
    _ -> assertFailure $ "Failed to parse base or full vector"

prop_cvss40RoundTrip :: Base40 -> Property
prop_cvss40RoundTrip b =
  let input = base40Vector b
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left e -> counterexample ("parse failed: " <> show e <> "\n" <> Text.unpack input) False

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

prop_cvss40EnvRoundTrip :: Base40 -> Env40 -> Property
prop_cvss40EnvRoundTrip b e =
  let input = full40Vector b e
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left err -> counterexample ("parse failed: " <> show err <> "\n" <> Text.unpack input) False

prop_cvss40EnvXNoScoreChange :: Base40 -> Property
prop_cvss40EnvXNoScoreChange b =
  let baseInput = base40Vector b
      fullInput = full40Vector b allXEnv
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS fullInput) of
        (Right baseCvss, Right fullCvss) ->
          let (_, baseScore) = CVSS.cvssScore baseCvss
              (_, fullScore) = CVSS.cvssScore fullCvss
           in fullScore === baseScore
        _ -> counterexample "parse failed for base or full vector" False

prop_cvss40EnvScoreBounds :: Base40 -> Env40 -> Property
prop_cvss40EnvScoreBounds b e =
  let input = full40Vector b e
   in case CVSS.parseCVSS input of
        Right cvss ->
          let (_, score) = CVSS.cvssScore cvss
           in score >= 0.0 .&&. score <= 10.0
        Left err -> counterexample ("parse failed: " <> show err <> "\n" <> Text.unpack input) False

prop_cvss40EnvRatingConsistency :: Base40 -> Env40 -> Property
prop_cvss40EnvRatingConsistency b e =
  let input = full40Vector b e
   in case CVSS.parseCVSS input of
        Right CVSS.CVSS {CVSS.cvssMetrics = cm} ->
          let (rating, score) = CVSS.cvss40EnvironmentalScore cm
           in rating === CVSS.toRating score
        Left err -> counterexample ("parse failed: " <> show err <> "\n" <> Text.unpack input) False

testCVSS40RatingBoundaries :: Assertion
testCVSS40RatingBoundaries =
  forM_ cvss40BoundaryTests $ \(score, expectedRating) -> do
    CVSS.toRating score @?= expectedRating

cvss40BoundaryTests :: [(Float, CVSS.Rating)]
cvss40BoundaryTests =
  [ (0, CVSS.None),
    (0.1, CVSS.Low),
    (3.9, CVSS.Low),
    (4.0, CVSS.Medium),
    (6.9, CVSS.Medium),
    (7.0, CVSS.High),
    (8.9, CVSS.High),
    (9.0, CVSS.Critical),
    (10, CVSS.Critical)
  ]

officialTestCaseV20 :: OfficialExample -> TestTree
officialTestCaseV20 ex =
  testCase (Text.unpack $ oeVector ex) $ do
    case CVSS.parseCVSS (oeVector ex) of
      Left e -> assertFailure (show e)
      Right cvss -> do
        let (rating, score) = CVSS.cvssScore cvss
        score @?= oeBaseScore ex
        rating @?= oeBaseRating ex
        case oeTemporalScore ex of
          Just (expectedScore, expectedRating) ->
            case cvss of
              CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS20, CVSS.cvssMetrics = cm} -> CVSS.cvss20TemporalScore cm @?= (expectedRating, expectedScore)
              _ -> assertFailure "Not a CVSS v2.0 vector"
          Nothing -> pure ()
        case oeEnvironmentalScore ex of
          Just (expectedScore, expectedRating) ->
            case cvss of
              CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS20, CVSS.cvssMetrics = cm} -> CVSS.cvss20EnvironmentalScore cm @?= (expectedRating, expectedScore)
              _ -> assertFailure "Not a CVSS v2.0 vector"
          Nothing -> pure ()

officialTestCaseV3X :: OfficialExample -> TestTree
officialTestCaseV3X ex =
  testCase (Text.unpack $ oeVector ex) $ do
    case CVSS.parseCVSS (oeVector ex) of
      Left e -> assertFailure (show e)
      Right cvss -> do
        let (rating, score) = CVSS.cvssScore cvss
        score @?= oeBaseScore ex
        rating @?= oeBaseRating ex

officialTestCaseV40 :: OfficialExample -> TestTree
officialTestCaseV40 ex =
  testCase (Text.unpack $ oeVector ex) $ do
    case CVSS.parseCVSS (oeVector ex) of
      Left e -> assertFailure (show e)
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = cm} -> do
        V40.cvss40BaseScore cm @?= (oeBaseRating ex, oeBaseScore ex)
        case oeThreatScore ex of
          Just (expectedScore, expectedRating) -> V40.cvss40ThreatScore cm @?= (expectedRating, expectedScore)
          Nothing -> pure ()
        case oeEnvironmentalScore ex of
          Just (expectedScore, expectedRating) -> CVSS.cvss40EnvironmentalScore cm @?= (expectedRating, expectedScore)
          Nothing -> pure ()
      other -> assertFailure $ "Not a CVSS 4.0 vector: " <> show other
