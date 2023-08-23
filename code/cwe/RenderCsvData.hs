#!/usr/bin/env cabal
{- cabal:
build-depends: base, xml
-}
{-# LANGUAGE NamedFieldPuns #-}
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

readXML :: String -> [Weakness]
readXML str = case XML.parseXMLDoc str of
    Just
        ( XML.Element
                (XML.QName "Weakness_Catalog" _ _)
                _
                ( _
                        : ( XML.Elem
                                ((XML.Element (XML.QName "Weaknesses" _ _) _ xs _))
                            )
                        : _
                    )
                _
            ) -> mapMaybe toWeakness xs
    n -> error (show n)
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
