module Main where

import Test.Tasty
import qualified Spec.QueriesSpec as QueriesSpec

main :: IO ()
main =
  defaultMain $
    testGroup
      "Tests"
      [QueriesSpec.spec]
