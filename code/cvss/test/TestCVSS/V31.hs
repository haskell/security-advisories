{-# LANGUAGE OverloadedStrings #-}

module TestCVSS.V31
  ( v31Tests,
  )
where

import Data.Text (Text)
import qualified Data.Text as Text
import OfficialExamples (cvss31OfficialExamples)
import qualified Security.CVSS as CVSS
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import TestCVSS.Common

v31Tests :: TestTree
v31Tests =
  testGroup
    "CVSS v3.1"
    [ testGroup "score examples" $ scoreTestCase <$> v31ScoreExamples,
      testGroup "temporal score examples" $ temporalCase <$> v31TemporalExamples,
      testGroup "environmental score examples" $ envCase <$> v31EnvironmentalExamples,
      testCase "X temporal/env metrics do not change score" testNotDefinedOptionalNoScoreChange,
      testProperty "parser preserves original vector string" prop_cvss31RoundTrip,
      testGroup
        "QuickCheck Properties"
        [ testProperty "temporal <= base" prop_v31_temporalLEBase,
          testProperty "ND temporal doesn't change score" prop_v31_ndTemporalNoChange,
          testProperty "ND env doesn't change score" prop_v31_ndEnvNoChange,
          testProperty "temporal score in [0, 10]" prop_v31_temporalScoreBounds,
          testProperty "env score in [0, 10]" prop_v31_envScoreBounds,
          testProperty "env rating consistent with score" prop_v31_envRatingConsistency,
          testProperty "temporal vector roundtrip" prop_v31_temporalRoundTrip
        ],
      testGroup "Official FIRST cross-validation" $ officialTestCaseV3X <$> cvss31OfficialExamples
    ]

-- ------------------------------------------------------------------
-- Example data
-- ------------------------------------------------------------------

v31ScoreExamples :: [(Text, Float, CVSS.Rating)]
v31ScoreExamples =
  [ ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8, CVSS.Medium),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, CVSS.Medium),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, CVSS.Low),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, CVSS.High),
    ( "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
      9.8,
      CVSS.Critical
    ),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.7, CVSS.High)
  ]

v31TemporalExamples :: [(Text, Float, CVSS.Rating)]
v31TemporalExamples =
  [ ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.0, CVSS.High),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/E:F/RL:O/RC:R", 6.7, CVSS.Medium),
    ( "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
      9.8,
      CVSS.Critical
    ),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.7, CVSS.High)
  ]

v31EnvironmentalExamples :: [(Text, Float, CVSS.Rating)]
v31EnvironmentalExamples =
  [ ( "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/E:F/CR:L/IR:M/AR:H/MAV:N/MAC:L/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:N",
      6.5,
      CVSS.Medium
    ),
    ( "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X",
      9.8,
      CVSS.Critical
    ),
    ( "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:L/MA:N",
      5.5,
      CVSS.Medium
    )
  ]

-- ------------------------------------------------------------------
-- Individual test-case builders
-- ------------------------------------------------------------------

temporalCase :: (Text, Float, CVSS.Rating) -> TestTree
temporalCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS31, CVSS.cvssMetrics = cm} ->
        CVSS.cvss31TemporalScore cm @?= (rating, score)
      other -> assertFailure (show other)

envCase :: (Text, Float, CVSS.Rating) -> TestTree
envCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS31, CVSS.cvssMetrics = cm} ->
        CVSS.cvss31EnvironmentalScore cm @?= (rating, score)
      other -> assertFailure (show other)

-- ------------------------------------------------------------------
-- Single-assertion tests
-- ------------------------------------------------------------------

testNotDefinedOptionalNoScoreChange :: Assertion
testNotDefinedOptionalNoScoreChange = do
  let baseVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      fullVector = baseVector <> notDefinedTemporalEnv
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right baseCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore baseCvss
    _ -> assertFailure ("base parse failed: " <> show fullVector)

-- ------------------------------------------------------------------
-- QuickCheck properties
-- ------------------------------------------------------------------

prop_cvss31RoundTrip :: Base31 -> Property
prop_cvss31RoundTrip b =
  let input = base31Vector b <> notDefinedTemporalEnv
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left e -> counterexample ("parse failed: " <> show e <> "\n" <> Text.unpack input) False

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

prop_v31_ndTemporalNoChange :: Base31 -> Property
prop_v31_ndTemporalNoChange b =
  let baseInput = base31Vector b
      ndTemporal = "/E:X/RL:X/RC:X"
      temporalInput = baseInput <> ndTemporal
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS temporalInput) of
        (Right baseCvss, Right temporalCvss) ->
          CVSS.cvssScore baseCvss === CVSS.cvss31TemporalScore (CVSS.cvssMetrics temporalCvss)
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

prop_v31_temporalScoreBounds :: Base31 -> Temporal3x -> Property
prop_v31_temporalScoreBounds b t =
  let temporalInput = base31Vector b <> "/" <> temporal3xVector t
   in case CVSS.parseCVSS temporalInput of
        Right cvss ->
          let (_, score) = CVSS.cvss31TemporalScore (CVSS.cvssMetrics cvss)
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

prop_v31_envRatingConsistency :: Base31 -> Temporal3x -> Env3x -> Property
prop_v31_envRatingConsistency b t e =
  let envInput = full31EnvVector b t e
   in case CVSS.parseCVSS envInput of
        Right cvss ->
          let (rating, score) = CVSS.cvss31EnvironmentalScore (CVSS.cvssMetrics cvss)
           in rating === CVSS.toRating score
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v31_temporalRoundTrip :: Base31 -> Temporal3x -> Property
prop_v31_temporalRoundTrip b t =
  let input = full31TemporalVector b t
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left err -> counterexample ("parse failed: " <> show err) False
