{-# LANGUAGE OverloadedStrings #-}

module Main where

import Test.Tasty

main :: IO ()
main =
    defaultMain $
      testGroup "Tests"
        []
