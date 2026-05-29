{-# LANGUAGE OverloadedStrings #-}

module TestCVSS.V30
  ( v30Tests,
  )
where

import Data.Text (Text)
import qualified Data.Text as Text
import OfficialExamples (cvss30OfficialExamples)
import qualified Security.CVSS as CVSS
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import TestCVSS.Common

v30Tests :: TestTree
v30Tests =
  testGroup
    "CVSS v3.0"
    [ testGroup "score examples" $ scoreTestCase <$> v30ScoreExamples,
      testGroup "temporal score examples" $ temporalCase <$> cvss30TemporalExamples,
      testCase "ND temporal metrics do not change score" testCVSS30NotDefinedNoScoreChange,
      testGroup "environmental score examples" $ envCase <$> cvss30EnvironmentalExamples,
      testCase "ND environmental metrics do not change score" testCVSS30EnvironmentalNotDefinedNoScoreChange,
      testGroup
        "QuickCheck Properties"
        [ testProperty "temporal <= base" prop_v30_temporalLEBase,
          testProperty "ND temporal doesn't change score" prop_v30_ndTemporalNoChange,
          testProperty "ND env doesn't change score" prop_v30_ndEnvNoChange,
          testProperty "temporal score in [0, 10]" prop_v30_temporalScoreBounds,
          testProperty "env score in [0, 10]" prop_v30_envScoreBounds,
          testProperty "env rating consistent with score" prop_v30_envRatingConsistency,
          testProperty "full vector roundtrip" prop_v30_fullRoundTrip
        ],
      testGroup "Official FIRST cross-validation" $ officialTestCaseV3X <$> cvss30OfficialExamples
    ]

-- ------------------------------------------------------------------
-- Example data
-- ------------------------------------------------------------------

v30ScoreExamples :: [(Text, Float, CVSS.Rating)]
v30ScoreExamples =
  [ ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, CVSS.Medium),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, CVSS.Medium),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, CVSS.Low),
    ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.0, CVSS.Medium),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, CVSS.Critical),
    ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2, CVSS.Medium),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.7, CVSS.High)
  ]

cvss30TemporalExamples :: [(Text, Float, CVSS.Rating)]
cvss30TemporalExamples =
  [ ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R", 8.7, CVSS.High),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:F/RL:O/RC:R", 5.4, CVSS.Medium),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X", 9.8, CVSS.Critical)
  ]

cvss30EnvironmentalExamples :: [(Text, Float, CVSS.Rating)]
cvss30EnvironmentalExamples =
  [ ( "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/E:F/CR:L/IR:M/AR:H/MAV:N/MAC:L/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:N",
      6.5,
      CVSS.Medium
    ),
    ( "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:L/MA:N",
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
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS30, CVSS.cvssMetrics = cm} ->
        CVSS.cvss30TemporalScore cm @?= (rating, score)
      other -> assertFailure (show other)

envCase :: (Text, Float, CVSS.Rating) -> TestTree
envCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS30, CVSS.cvssMetrics = cm} ->
        CVSS.cvss30EnvironmentalScore cm @?= (rating, score)
      other -> assertFailure (show other)

-- ------------------------------------------------------------------
-- Single-assertion tests
-- ------------------------------------------------------------------

testCVSS30NotDefinedNoScoreChange :: Assertion
testCVSS30NotDefinedNoScoreChange = do
  let baseVector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      fullVector = baseVector <> "/E:X/RL:X/RC:X"
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right baseCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore baseCvss
    _ -> assertFailure "base or full vector parse failed"

testCVSS30EnvironmentalNotDefinedNoScoreChange :: Assertion
testCVSS30EnvironmentalNotDefinedNoScoreChange = do
  let temporalVector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R"
      fullVector = temporalVector <> "/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
  case (CVSS.parseCVSS temporalVector, CVSS.parseCVSS fullVector) of
    (Right temporalCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore temporalCvss
    _ -> assertFailure "temporal or full vector parse failed"

-- ------------------------------------------------------------------
-- QuickCheck properties
-- ------------------------------------------------------------------

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

prop_v30_ndTemporalNoChange :: Base31 -> Property
prop_v30_ndTemporalNoChange b =
  let baseInput = base30Vector b
      ndTemporal = "/E:X/RL:X/RC:X"
      temporalInput = baseInput <> ndTemporal
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS temporalInput) of
        (Right baseCvss, Right temporalCvss) ->
          CVSS.cvssScore baseCvss === CVSS.cvss30TemporalScore (CVSS.cvssMetrics temporalCvss)
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

prop_v30_temporalScoreBounds :: Base31 -> Temporal3x -> Property
prop_v30_temporalScoreBounds b t =
  let temporalInput = base30Vector b <> "/" <> temporal3xVector t
   in case CVSS.parseCVSS temporalInput of
        Right cvss ->
          let (_, score) = CVSS.cvss30TemporalScore (CVSS.cvssMetrics cvss)
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

prop_v30_envRatingConsistency :: Base31 -> Temporal3x -> Env3x -> Property
prop_v30_envRatingConsistency b t e =
  let envInput = full30Vector b t e
   in case CVSS.parseCVSS envInput of
        Right cvss ->
          let (rating, score) = CVSS.cvss30EnvironmentalScore (CVSS.cvssMetrics cvss)
           in rating === CVSS.toRating score
        Left err -> counterexample ("parse failed: " <> show err) False

prop_v30_fullRoundTrip :: Base31 -> Temporal3x -> Env3x -> Property
prop_v30_fullRoundTrip b t e =
  let input = full30Vector b t e
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left err -> counterexample ("parse failed: " <> show err) False
