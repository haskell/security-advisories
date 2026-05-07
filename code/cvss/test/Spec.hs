{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Security.CVSS as CVSS
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
        testCase "CVSS v2.0 rating boundary tests" testCVSS20RatingBoundaries,
        testCase "CVSS v2.0 temporal score examples" testCVSS20TemporalScore,
        testCase "CVSS v2.0 ND temporal metrics do not change score" testCVSS20NotDefinedNoScoreChange,
        testCase "CVSS v2.0 environmental score examples" testCVSS20EnvironmentalScore,
        testCase "CVSS v2.0 ND environmental metrics do not change score" testCVSS20EnvironmentalNotDefinedNoScoreChange
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
