module Main where

import Spec qualified (spec)
import Test.Hspec (hspec)

main :: IO ()
main = hspec Spec.spec
