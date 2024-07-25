{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Aeson.Encode.Pretty (encodePretty)
import Data.List (isSuffixOf)
import qualified Data.Text.IO as T
import qualified Data.Text.Lazy as LText
import qualified Data.Text.Lazy.Encoding as LText
import Data.Time (UTCTime(UTCTime))
import Data.Time.Calendar.OrdinalDate (fromOrdinalDate)
import qualified Security.Advisories.Convert.OSV as OSV
import Security.Advisories.Parse
import qualified Spec.FormatSpec as FormatSpec
import qualified Spec.QueriesSpec as QueriesSpec
import System.Directory (listDirectory)
import Test.Tasty (defaultMain, testGroup, TestTree)
import Test.Tasty.Golden (goldenVsString)
import Text.Pretty.Simple (pShowNoColor)

main :: IO ()
main = do
    goldenFiles <- listGoldenFiles
    defaultMain $
        testGroup
            "Tests"
            [ goldenTestsSpec goldenFiles
            , QueriesSpec.spec
            , FormatSpec.spec
            ]

listGoldenFiles :: IO [FilePath]
listGoldenFiles = map (mappend dpath) . filter (not . isSuffixOf ".golden") <$> listDirectory dpath
  where
    dpath = "test/golden/"

goldenTestsSpec :: [FilePath] -> TestTree
goldenTestsSpec goldenFiles = testGroup "Golden test" $ map doGoldenTest goldenFiles

doGoldenTest :: FilePath -> TestTree
doGoldenTest fp = goldenVsString fp (fp <> ".golden") (LText.encodeUtf8 <$> doCheck)
  where
    doCheck :: IO LText.Text
    doCheck = do
        input <- T.readFile fp
        let fakeDate = UTCTime (fromOrdinalDate 1970 0) 0
            attr = OutOfBandAttributes                    
              { oobPublished = fakeDate
              , oobModified = fakeDate
              }
            res = parseAdvisory NoOverrides (Right attr) input
            osvExport = case res of
                Right adv ->
                    let osv = OSV.convert adv
                     in LText.unlines
                            [ pShowNoColor osv
                            , LText.decodeUtf8 (encodePretty osv)
                            ]
                Left _ -> ""
        pure (LText.unlines [pShowNoColor res, osvExport])
