{-# LANGUAGE OverloadedStrings #-}

module TestCVSS.V20
  ( v20Tests,
  )
where

import Data.Text (Text)
import qualified Data.Text as Text
import OfficialExamples (OfficialExample (..), cvss20OfficialExamples)
import qualified Security.CVSS as CVSS
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import TestCVSS.Common

v20Tests :: TestTree
v20Tests =
  testGroup
    "CVSS v2.0"
    [ testGroup "score examples" $ scoreTestCase <$> v20ScoreExamples,
      testGroup "rating boundary tests" $ boundaryCase <$> cvss20BoundaryTests,
      testGroup "temporal score examples" $ temporalCase <$> cvss20TemporalExamples,
      testCase "ND temporal metrics do not change score" testCVSS20NotDefinedNoScoreChange,
      testGroup "environmental score examples" $ envCase <$> cvss20EnvironmentalExamples,
      testCase "ND environmental metrics do not change score" testCVSS20EnvironmentalNotDefinedNoScoreChange,
      testGroup
        "QuickCheck Properties"
        [ testProperty "temporal <= base" prop_v20_temporalLEBase,
          testProperty "ND temporal doesn't change score" prop_v20_ndTemporalNoChange,
          testProperty "ND env doesn't change score" prop_v20_ndEnvNoChange,
          testProperty "temporal score in [0, 10]" prop_v20_temporalScoreBounds,
          testProperty "env score in [0, 10]" prop_v20_envScoreBounds,
          testProperty "TD:N results in score 0" prop_v20_tdNoneZero,
          testProperty "env <= temporal when CR/IR/AR=ND and CDP=ND" prop_v20_envLETemporal,
          testProperty "full vector roundtrip" prop_v20_fullRoundTrip
        ],
      testGroup "Official FIRST cross-validation" $ officialTestCaseV20 <$> cvss20OfficialExamples
    ]

-- ------------------------------------------------------------------
-- Example data
-- ------------------------------------------------------------------

v20ScoreExamples :: [(Text, Float, CVSS.Rating)]
v20ScoreExamples =
  [ ("AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8, CVSS.High),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10, CVSS.High),
    ("AV:L/AC:H/Au:N/C:C/I:C/A:C", 6.2, CVSS.Medium),
    ("AV:N/AC:M/Au:N/C:P/I:N/A:N", 4.3, CVSS.Medium)
  ]

cvss20BoundaryTests :: [(Float, CVSS.Rating)]
cvss20BoundaryTests =
  [ (0, CVSS.None),
    (0.1, CVSS.Low),
    (3.9, CVSS.Low),
    (4.0, CVSS.Medium),
    (6.9, CVSS.Medium),
    (7.0, CVSS.High),
    (9.0, CVSS.High),
    (10, CVSS.High)
  ]

cvss20TemporalExamples :: [(Text, Float, CVSS.Rating)]
cvss20TemporalExamples =
  [ ("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND", 10.0, CVSS.High),
    ("AV:N/AC:L/Au:N/C:N/I:N/A:C/E:ND/RL:ND/RC:ND", 7.8, CVSS.High)
  ]

cvss20EnvironmentalExamples :: [(Text, Float, CVSS.Rating)]
cvss20EnvironmentalExamples =
  [ ( "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND",
      10.0,
      CVSS.High
    ),
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:ND/TD:H/CR:H/IR:H/AR:H",
      7.8,
      CVSS.High
    ),
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:L/TD:H/CR:L/IR:L/AR:L",
      5.3,
      CVSS.Medium
    ),
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:F/RL:OF/RC:UC/CDP:H/TD:H/CR:M/IR:M/AR:M",
      7.4,
      CVSS.High
    ),
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:H/TD:N/CR:M/IR:M/AR:M",
      0,
      CVSS.None
    ),
    ( "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:ND/RC:ND/CDP:H/TD:L/CR:M/IR:M/AR:M",
      2.0,
      CVSS.Low
    )
  ]

-- ------------------------------------------------------------------
-- Individual test-case builders
-- ------------------------------------------------------------------

boundaryCase :: (Float, CVSS.Rating) -> TestTree
boundaryCase (score, expectedRating) =
  testCase ("boundary: " <> showFFloat score) $
    CVSS.toRating20 score @?= expectedRating

temporalCase :: (Text, Float, CVSS.Rating) -> TestTree
temporalCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS20, CVSS.cvssMetrics = cm} ->
        CVSS.cvss20TemporalScore cm @?= (rating, score)
      other -> assertFailure (show other)

envCase :: (Text, Float, CVSS.Rating) -> TestTree
envCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS20, CVSS.cvssMetrics = cm} ->
        CVSS.cvss20EnvironmentalScore cm @?= (rating, score)
      other -> assertFailure (show other)

showFFloat :: Float -> String
showFFloat = show

-- ------------------------------------------------------------------
-- Single-assertion tests
-- ------------------------------------------------------------------

testCVSS20NotDefinedNoScoreChange :: Assertion
testCVSS20NotDefinedNoScoreChange = do
  let baseVector = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
      fullVector = baseVector <> "/E:ND/RL:ND/RC:ND"
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right baseCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore baseCvss
    _ -> assertFailure "base or full vector parse failed"

testCVSS20EnvironmentalNotDefinedNoScoreChange :: Assertion
testCVSS20EnvironmentalNotDefinedNoScoreChange = do
  let baseVector = "AV:N/AC:L/Au:N/C:P/I:P/A:N"
      fullVector = baseVector <> "/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND"
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right baseCvss, Right fullCvss) ->
      CVSS.cvssScore fullCvss @?= CVSS.cvssScore baseCvss
    _ -> assertFailure "base or full vector parse failed"

-- ------------------------------------------------------------------
-- QuickCheck properties
-- ------------------------------------------------------------------

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

prop_v20_ndTemporalNoChange :: Base20 -> Property
prop_v20_ndTemporalNoChange b =
  let baseInput = base20Vector b
      ndTemporal = "/E:ND/RL:ND/RC:ND"
      temporalInput = baseInput <> ndTemporal
   in case (CVSS.parseCVSS baseInput, CVSS.parseCVSS temporalInput) of
        (Right baseCvss, Right temporalCvss) ->
          CVSS.cvssScore baseCvss === CVSS.cvss20TemporalScore (CVSS.cvssMetrics temporalCvss)
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

prop_v20_temporalScoreBounds :: Base20 -> Temporal20 -> Property
prop_v20_temporalScoreBounds b t =
  let temporalInput = base20Vector b <> "/" <> temporal20Vector t
   in case CVSS.parseCVSS temporalInput of
        Right cvss ->
          let (_, score) = CVSS.cvss20TemporalScore (CVSS.cvssMetrics cvss)
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

-- ------------------------------------------------------------------
-- Official FIRST cross-validation
-- ------------------------------------------------------------------

officialTestCaseV20 :: OfficialExample -> TestTree
officialTestCaseV20 ex =
  testCase (Text.unpack $ oeVector ex) $
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
