#!/usr/bin/env cabal
{- cabal:
build-depends: base, csv
-}
-- | Use this script to update the CWE.Raw module:
-- Go to https://cwe.mitre.org/data/downloads.html
-- Download and extract the 'Software Development' and 'CWE Simplified Mapping' CSV.zip files
-- Run the following command: ./RenderCsvData.hs | fourmolu --stdin-input-file ./src/CWE/Raw.hs > src/CWE/Raw.hs
module Main where

import Data.List
import Data.Maybe
import Text.CSV
import Text.Read

main :: IO ()
main = do
    dbs <- traverse readCSV ["699.csv", "1003.csv"]
    putStrLn $ unlines $ renderSource $ concat dbs

readCSV :: FilePath -> IO CSV
readCSV fp = do
    txt <- readFile fp
    case Text.CSV.parseCSV "stdin" txt of
        Left e -> error ("bad csv: " <> show e)
        Right records -> pure (drop 1 records)

renderSource :: [Record] -> [String]
renderSource xs =
    [ "{-# LANGUAGE OverloadedStrings #-}"
    , "module CWE.Data where"
    , "import Data.Text"
    , "cweData :: [(Word, Text)]"
    , "cweData = ["
    ]
        <> map renderEntry (zip [0 ..] (sortOn byNum xs))
        <> ["  ]"]
  where
    byNum (num : _) = fromMaybe (42 :: Int) (readMaybe num)
    renderEntry (pos, (num : desc : _)) = "  " <> sep <> " (" <> num <> ", \"" <> name <> "\")"
      where
        sep = if pos == 0 then " " else ","
        -- Remove extra info in parenthesis
        name = dropWhileEnd (== ' ') $ takeWhile (/= '(') desc
    renderEntry _ = ""
