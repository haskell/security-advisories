#!/usr/bin/env cabal
{- cabal:
build-depends: base, xml
-}
{-# LANGUAGE NamedFieldPuns, PatternSynonyms #-}
-- | Use this script to update the Security.CWE.Data module:
-- Download and extract https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
-- Run the following command: cat cwec_v4.12.xml | ./RenderCsvData.hs | fourmolu --stdin-input-file ./src/Security/CWE/Data.hs > src/Security/CWE/Data.hs
module Main where

import Data.List
import Data.Maybe
import Text.Read

import qualified Text.XML.Light as XML

main :: IO ()
main = do
    db <- readXML <$> getContents
    putStrLn $ unlines $ renderSource $ db

data Weakness = Weakness
    { wid :: Word
    , wname :: String
    }

pattern XElement name content <- XML.Element (XML.QName name _ _) _ content _

readXML :: String -> [Weakness]
readXML str = case XML.parseXMLDoc str of
    Just (XElement "Weakness_Catalog" (_ : (XML.Elem (XElement "Weaknesses" xs)) : _)) ->
        mapMaybe toWeakness xs
    n -> error $ "Couldn't match: " <> take 512 (show n)
  where
    toWeakness (XML.Elem (XML.Element (XML.QName "Weakness" _ _) attrs _ _)) = Just (Weakness{wid, wname})
      where
        wid = fromMaybe (error "invalid num") $ readMaybe =<< XML.lookupAttrBy ((==) "ID" . XML.qName) attrs
        wname = fromMaybe (error "missing name") $ XML.lookupAttrBy ((==) "Name" . XML.qName) attrs
    toWeakness e = Nothing

renderSource :: [Weakness] -> [String]
renderSource xs =
    [ "{-# LANGUAGE OverloadedStrings #-}"
    , "module Security.CWE.Data where"
    , "import Data.Text"
    , "cweData :: [(Word, Text)]"
    , "cweData = ["
    ]
        <> map renderEntry (zip [0 ..] (sortOn wid xs))
        <> ["  ]"]
  where
    renderEntry (pos, weakness) = "  " <> sep <> " (" <> show (wid weakness) <> ", \"" <> name <> "\")"
      where
        sep = if pos == 0 then " " else ","
        -- Remove extra info in parenthesis
        name = dropWhileEnd (== ' ') $ takeWhile (/= '(') $ escape $ wname weakness
        escape ('\\':rest) = '\\' : '\\' : escape rest
        escape (x:rest) = x : escape rest
        escape [] = []
    renderEntry _ = ""
