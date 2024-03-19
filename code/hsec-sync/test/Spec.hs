{-# LANGUAGE OverloadedStrings #-}

module Main where

import Test.Tasty

import qualified Spec.SyncSpec as SyncSpec

main :: IO ()
main = do
    defaultMain $
      testGroup "Tests"
        [ SyncSpec.spec
        ]
