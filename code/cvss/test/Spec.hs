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
      [ testCase "examples" testExamples,
        testProperty "CVSS 3.1 X temporal/environmental metrics do not change base score" prop_cvss31NotDefinedOptionalMetricsDoNotChangeScore,
        testProperty "CVSS 3.1 parser preserves original vector string" prop_cvss31RoundTripsParseToString
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
    [ ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8, CVSS.Medium)
    , ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, CVSS.Medium)
    , ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, CVSS.Low)
    , ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, CVSS.High)
    , ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, CVSS.Medium)
    , ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, CVSS.Medium)
    , ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, CVSS.Low)
    , ("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.0, CVSS.Medium)
    , ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, CVSS.Critical)
    , ("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2, CVSS.Medium)
    , ("AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8, CVSS.High)
    , ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10, CVSS.Critical)
    , ("AV:L/AC:H/Au:N/C:C/I:C/A:C", 6.2, CVSS.Medium)
    , ("AV:N/AC:M/Au:N/C:P/I:N/A:N", 4.3, CVSS.Medium)
    , ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
      , 9.8, CVSS.Critical)
    ,  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:R", 9.8, CVSS.Critical)
    ]

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
base31Vector b = Text.pack
    [ 'C', 'V', 'S', 'S', ':', '3', '.', '1'
    , '/', 'A', 'V', ':', bAV b
    , '/', 'A', 'C', ':', bAC b
    , '/', 'P', 'R', ':', bPR b
    , '/', 'U', 'I', ':', bUI b
    , '/', 'S', ':', bS b
    , '/', 'C', ':', bC b
    , '/', 'I', ':', bI b
    , '/', 'A', ':', bA b
    ]

notDefinedTemporalEnv :: Text
notDefinedTemporalEnv =
  "/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"

prop_cvss31NotDefinedOptionalMetricsDoNotChangeScore :: Base31 -> Property
prop_cvss31NotDefinedOptionalMetricsDoNotChangeScore b =
  ioProperty $ do
    let baseVector = base31Vector b
        fullVector = baseVector <> notDefinedTemporalEnv
    case (CVSS.parseCVSS baseVector, CVSS.parseCVSS fullVector) of
      (Right baseCvss, Right fullCvss) ->
        pure $
          counterexample ("baseVector = " <> Text.unpack baseVector) $
            counterexample ("fullVector = " <> Text.unpack fullVector) $
              CVSS.cvssScore fullCvss === CVSS.cvssScore baseCvss
      _ -> pure $ counterexample ("base parse failed: " <> show fullVector) False

-- CVSS.cvssVectorString <$> CVSS.parseCVSS input == Right input
prop_cvss31RoundTripsParseToString :: Base31 -> Property
prop_cvss31RoundTripsParseToString b =
  let input = base31Vector b <> notDefinedTemporalEnv
   in case CVSS.parseCVSS input of
        Right cvss -> CVSS.cvssVectorString cvss === input
        Left e -> counterexample ("parse failed: " <> show e <> "\n" <> Text.unpack input) False
