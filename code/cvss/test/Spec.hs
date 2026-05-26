{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import Data.Text (Text)
import qualified Data.Text as Text
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
        testCase "CVSS v4.0 rating boundary tests" testCVSS40RatingBoundaries
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

notDefinedTemporalEnv :: Text
notDefinedTemporalEnv =
  "/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"

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
      7.7,
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
