module Main where

import Test.Tasty
import qualified TestCVSS.V20 as V20
import qualified TestCVSS.V30 as V30
import qualified TestCVSS.V31 as V31
import qualified TestCVSS.V40 as V40

main :: IO ()
main =
  defaultMain $
    testGroup
      "Security.CVSS"
      [ V20.v20Tests,
        V30.v30Tests,
        V31.v31Tests,
        V40.v40Tests
      ]
