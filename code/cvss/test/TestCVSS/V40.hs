{-# LANGUAGE OverloadedStrings #-}

module TestCVSS.V40
  ( v40Tests,
  )
where

import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as Text
import OfficialExamples (OfficialExample (..), cvss40OfficialExamples)
import qualified Security.CVSS as CVSS
import qualified Security.CVSS.V40 as V40
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import TestCVSS.Common

v40Tests :: TestTree
v40Tests =
  testGroup
    "CVSS v4.0"
    [ testGroup "valid parsing" $ validParseCase <$> cvss40ValidVectors,
      testGroup "invalid parsing" $ invalidParseCase <$> cvss40InvalidVectors,
      testCase "should require CVSS:4.0/ prefix" testCVSS40LegacyRejected,
      testGroup "base score examples" $ cvss40ScoringCase <$> cvss40ScoringExamples,
      testGroup "expanded base score tests" $ cvss40ScoringCase <$> cvss40ExpandedExamples,
      testGroup "direct baseScore tests" $ cvss40BaseScoreCase <$> cvss40BaseScoreExamples,
      testGroup "threat score examples" $ threatCase <$> cvss40ThreatExamples,
      testGroup "environmental score examples" $ envCase <$> cvss40EnvironmentalExamples,
      testGroup "parsing with optional metrics" $ optionalParseCase <$> cvss40OptionalVectors,
      testCase "X metrics do not change score" testCVSS40XMetricsNoScoreChange,
      testGroup "rating boundary tests" $ boundaryCase <$> cvss40BoundaryTests,
      testGroup
        "QuickCheck Properties"
        [ testProperty "parser preserves original vector string" prop_cvss40RoundTrip,
          testProperty "environmental parser preserves original vector string" prop_cvss40EnvRoundTrip,
          testProperty "all-X environmental metrics do not change score" prop_cvss40EnvXNoScoreChange,
          testProperty "environmental score is in [0, 10]" prop_cvss40EnvScoreBounds,
          testProperty "environmental rating is consistent with score" prop_cvss40EnvRatingConsistency
        ],
      testGroup "Supplemental Metrics" testSupplementalMetrics,
      testGroup "CVSS Nomenclature" testNomenclature,
      testGroup "Official FIRST cross-validation" $ officialTestCaseV40 <$> cvss40OfficialExamples
    ]

-- ------------------------------------------------------------------
-- Example data
-- ------------------------------------------------------------------

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

cvss40ScoringExamples :: [(Text, Float, CVSS.Rating)]
cvss40ScoringExamples =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N", 9.9, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.3, CVSS.Critical),
    ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.6, CVSS.High),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.4, CVSS.High),
    ("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 2.4, CVSS.Low)
  ]

cvss40ExpandedExamples :: [(Text, Float, CVSS.Rating)]
cvss40ExpandedExamples =
  []

cvss40BaseScoreExamples :: [(Text, Float, CVSS.Rating)]
cvss40BaseScoreExamples =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.3, CVSS.Critical),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.4, CVSS.High),
    ("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 2.4, CVSS.Low),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 7.6, CVSS.High)
  ]

cvss40ThreatExamples :: [(Text, Float, CVSS.Rating)]
cvss40ThreatExamples =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:A", 9.3, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P", 8.8, CVSS.High),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U", 8.0, CVSS.High)
  ]

cvss40EnvironmentalExamples :: [(Text, Float, CVSS.Rating)]
cvss40EnvironmentalExamples =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:S/MSA:X", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:H/IR:H/AR:H/MAV:L", 9.4, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:L/IR:L/AR:L", 9.6, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MVC:L", 9.3, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:S/MSA:X", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:S", 10.0, CVSS.Critical),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:S/MSA:S", 10.0, CVSS.Critical)
  ]

cvss40OptionalVectors :: [(Text, Int)]
cvss40OptionalVectors =
  [ ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:N", 12),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:N/AU:N", 13),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X", 12),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 12),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", 12),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 12),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/IR:H/AR:H", 14),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:N/AU:N/E:X/CR:X/IR:X/AR:X", 17)
  ]

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

-- ------------------------------------------------------------------
-- Individual test-case builders
-- ------------------------------------------------------------------

validParseCase :: (Text, Int) -> TestTree
validParseCase (cvssString, expectedMetricsCount) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = metrics} -> do
        length metrics @?= expectedMetricsCount
        CVSS.cvssVectorString (CVSS.CVSS CVSS.CVSS40 metrics) @?= cvssString
      other -> assertFailure $ "Failed to parse valid CVSS 4.0: " <> show other <> " for " <> show cvssString

invalidParseCase :: Text -> TestTree
invalidParseCase cvssString =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Left _ -> pure ()
      Right _ -> assertFailure $ "Should have failed to parse: " <> show cvssString

cvss40ScoringCase :: (Text, Float, CVSS.Rating) -> TestTree
cvss40ScoringCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Left e -> assertFailure (show e)
      Right cvss -> do
        CVSS.cvssScore cvss @?= (rating, score)
        CVSS.cvssVectorString cvss @?= cvssString

cvss40BaseScoreCase :: (Text, Float, CVSS.Rating) -> TestTree
cvss40BaseScoreCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Left e -> assertFailure (show e)
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = cm} ->
        V40.cvss40BaseScore cm @?= (rating, score)
      other -> assertFailure $ "Not a CVSS 4.0 vector: " <> show other

threatCase :: (Text, Float, CVSS.Rating) -> TestTree
threatCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = cm} ->
        V40.cvss40ThreatScore cm @?= (rating, score)
      other -> assertFailure (show other)

envCase :: (Text, Float, CVSS.Rating) -> TestTree
envCase (cvssString, score, rating) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = cm} ->
        CVSS.cvss40EnvironmentalScore cm @?= (rating, score)
      other -> assertFailure (show other)

optionalParseCase :: (Text, Int) -> TestTree
optionalParseCase (cvssString, expectedCount) =
  testCase (Text.unpack cvssString) $
    case CVSS.parseCVSS cvssString of
      Right CVSS.CVSS {CVSS.cvssVersion = CVSS.CVSS40, CVSS.cvssMetrics = cm} -> do
        length cm @?= expectedCount
        CVSS.cvssVectorString (CVSS.CVSS CVSS.CVSS40 cm) @?= cvssString
      other -> assertFailure $ "Failed to parse: " <> show other <> " for " <> show cvssString

boundaryCase :: (Float, CVSS.Rating) -> TestTree
boundaryCase (score, expectedRating) =
  testCase ("boundary: " <> show score) $
    CVSS.toRating score @?= expectedRating

-- ------------------------------------------------------------------
-- Single-assertion tests
-- ------------------------------------------------------------------

testCVSS40LegacyRejected :: Assertion
testCVSS40LegacyRejected =
  case CVSS.parseCVSS "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N" of
    Left _ -> pure ()
    Right _ -> assertFailure "CVSS 4.0 should require CVSS:4.0/ prefix (no legacy format)"

testCVSS40XMetricsNoScoreChange :: Assertion
testCVSS40XMetricsNoScoreChange = do
  let baseVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      xMetrics = "/E:X/S:N/AU:N/CR:X/IR:X/AR:X"
      fullVector = baseVector <> xMetrics
  case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
    (Right CVSS.CVSS {CVSS.cvssMetrics = baseMetrics}, Right CVSS.CVSS {CVSS.cvssMetrics = fullMetrics}) ->
      V40.cvss40BaseScore baseMetrics @?= V40.cvss40BaseScore fullMetrics
    _ -> assertFailure "Failed to parse base or full vector"

-- ------------------------------------------------------------------
-- QuickCheck properties
-- ------------------------------------------------------------------

prop_cvss40RoundTrip :: Base40 -> Property
prop_cvss40RoundTrip b =
  let input = base40Vector b
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left e -> counterexample ("parse failed: " <> show e <> "\n" <> Text.unpack input) False

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

-- ------------------------------------------------------------------
-- Supplemental Metrics
-- ------------------------------------------------------------------

testSupplementalMetrics :: [TestTree]
testSupplementalMetrics =
  [ testCase "No supplemental metrics" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      case CVSS.parseCVSS vec of
        Right cvss -> do
          V40.hasSupplementalMetrics (CVSS.cvssMetrics cvss) @?= False
          CVSS.cvssSupplementalInfo cvss @?= Nothing
        Left e -> assertFailure $ show e,
    testCase "Single supplemental metric" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P"
      case CVSS.parseCVSS vec of
        Right cvss -> do
          V40.hasSupplementalMetrics (CVSS.cvssMetrics cvss) @?= True
          let info = CVSS.cvssSupplementalInfo cvss
          isJust info @?= True
          maybeInfo <- maybe (pure "") pure info
          Text.isInfixOf "Safety" maybeInfo @?= True
          Text.isInfixOf "Present" maybeInfo @?= True
        Left e -> assertFailure $ show e,
    testCase "All supplemental metrics" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/R:A/V:D/RE:H/U:C"
      case CVSS.parseCVSS vec of
        Right cvss -> do
          V40.hasSupplementalMetrics (CVSS.cvssMetrics cvss) @?= True
          let info = CVSS.cvssSupplementalInfo cvss
          maybeInfo <- maybe (pure "") pure info
          Text.isInfixOf "Safety" maybeInfo @?= True
          Text.isInfixOf "Automatable" maybeInfo @?= True
          Text.isInfixOf "Recovery" maybeInfo @?= True
          Text.isInfixOf "Value Density" maybeInfo @?= True
          Text.isInfixOf "Vulnerability Response Effort" maybeInfo @?= True
          Text.isInfixOf "Provider Urgency" maybeInfo @?= True
        Left e -> assertFailure $ show e,
    testCase "Supplemental does not affect score" $ do
      let baseVec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
          withSupplemental = baseVec <> "/S:P/AU:Y/R:A/V:D/RE:H/U:C"
      case (CVSS.parseCVSS baseVec, CVSS.parseCVSS withSupplemental) of
        (Right baseCvss, Right suppCvss) -> do
          let (_, baseScore) = V40.cvss40BaseScore (CVSS.cvssMetrics baseCvss)
              (_, suppScore) = V40.cvss40BaseScore (CVSS.cvssMetrics suppCvss)
          suppScore @?= baseScore
        _ -> assertFailure "Parse failed",
    testCase "getSupplementalValue returns correct value" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/R:A/V:D/RE:H/U:C"
      case CVSS.parseCVSS vec of
        Right cvss -> do
          V40.getSupplementalValue (CVSS.cvssMetrics cvss) "S" @?= Just "P"
          V40.getSupplementalValue (CVSS.cvssMetrics cvss) "AU" @?= Just "Y"
          V40.getSupplementalValue (CVSS.cvssMetrics cvss) "NOTEXIST" @?= Nothing
        Left e -> assertFailure $ show e,
    testCase "parseSupplementalValue returns correct descriptions" $ do
      V40.parseSupplementalValue "S" "P" @?= Just "Present"
      V40.parseSupplementalValue "S" "N" @?= Just "Negligible"
      V40.parseSupplementalValue "AU" "Y" @?= Just "Yes"
      V40.parseSupplementalValue "AU" "N" @?= Just "No"
      V40.parseSupplementalValue "R" "A" @?= Just "Automatic"
      V40.parseSupplementalValue "R" "U" @?= Just "User"
      V40.parseSupplementalValue "R" "I" @?= Just "Irreversible"
      V40.parseSupplementalValue "V" "D" @?= Just "Diffuse"
      V40.parseSupplementalValue "V" "C" @?= Just "Concentrated"
      V40.parseSupplementalValue "RE" "L" @?= Just "Low"
      V40.parseSupplementalValue "RE" "M" @?= Just "Moderate"
      V40.parseSupplementalValue "RE" "H" @?= Just "High"
      V40.parseSupplementalValue "U" "C" @?= Just "Clear"
      V40.parseSupplementalValue "U" "A" @?= Just "Amber"
      V40.parseSupplementalValue "U" "G" @?= Just "Green",
    testCase "cvssSupplementalInfo returns Nothing for non-CVSS40" $ do
      let vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      case CVSS.parseCVSS vec of
        Right cvss -> CVSS.cvssSupplementalInfo cvss @?= Nothing
        Left e -> assertFailure $ show e
  ]

-- ------------------------------------------------------------------
-- CVSS Nomenclature
-- ------------------------------------------------------------------

testNomenclature :: [TestTree]
testNomenclature =
  [ testCase "Base only is CVSS-B" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      case CVSS.parseCVSS vec of
        Right cvss -> CVSS.determineNomenclature cvss @?= CVSS.CVSS_B
        Left e -> assertFailure $ show e,
    testCase "Base + Threat (E:A) is CVSS-BT" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
      case CVSS.parseCVSS vec of
        Right cvss -> CVSS.determineNomenclature cvss @?= CVSS.CVSS_BT
        Left e -> assertFailure $ show e,
    testCase "Base + Threat (E:X) is CVSS-BT" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X"
      case CVSS.parseCVSS vec of
        Right cvss -> CVSS.determineNomenclature cvss @?= CVSS.CVSS_BT
        Left e -> assertFailure $ show e,
    testCase "Base + Environmental (CR:H) is CVSS-BE" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H"
      case CVSS.parseCVSS vec of
        Right cvss -> CVSS.determineNomenclature cvss @?= CVSS.CVSS_BE
        Left e -> assertFailure $ show e,
    testCase "Base + Threat + Environmental is CVSS-BTE" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H"
      case CVSS.parseCVSS vec of
        Right cvss -> CVSS.determineNomenclature cvss @?= CVSS.CVSS_BTE
        Left e -> assertFailure $ show e,
    testCase "All X metrics is CVSS-BTE" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X"
      case CVSS.parseCVSS vec of
        Right cvss -> CVSS.determineNomenclature cvss @?= CVSS.CVSS_BTE
        Left e -> assertFailure $ show e,
    testCase "CVSS 3.1 is always CVSS-B" $ do
      let vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C/CR:H/IR:H/AR:H"
      case CVSS.parseCVSS vec of
        Right cvss -> CVSS.determineNomenclature cvss @?= CVSS.CVSS_B
        Left e -> assertFailure $ show e,
    testCase "showCVSSWithNomenclature format" $ do
      let vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      case CVSS.parseCVSS vec of
        Right cvss ->
          CVSS.showCVSSWithNomenclature cvss @?= "CVSS-B:Critical/9.3"
        Left e -> assertFailure $ show e
  ]

-- ------------------------------------------------------------------
-- Official FIRST cross-validation
-- ------------------------------------------------------------------

officialTestCaseV40 :: OfficialExample -> TestTree
officialTestCaseV40 ex =
  testCase (Text.unpack $ oeVector ex) $
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
