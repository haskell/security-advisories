{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import Data.Text (Text, unpack)
import qualified Security.CVSS as CVSS
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain $
    testCase "Security.CVSS" $ do
        forM_ examples $ \(cvssString, score, rating) -> do
            case CVSS.parseCVSS cvssString of
                Left e -> assertFailure (unpack e)
                Right cvss -> CVSS.cvssScore cvss @?= (rating, score)

examples :: [(Text, Float, CVSS.Rating)]
examples =
    [ ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8, CVSS.Medium)
    , ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, CVSS.Medium)
    , ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, CVSS.Low)
    ]
