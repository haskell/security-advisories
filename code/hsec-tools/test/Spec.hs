{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.List (isSuffixOf)
import qualified Data.Text.IO as T
import qualified Data.Text.Lazy as LText
import qualified Data.Text.Lazy.Encoding as LText
import Data.Time.Calendar.OrdinalDate (fromOrdinalDate)
import Data.Time.LocalTime
import System.Directory (listDirectory)
import Test.Tasty
import Test.Tasty.Golden (goldenVsString)
import Text.Pretty.Simple (pShowNoColor)

import Security.Advisories.Parse

main :: IO ()
main = do
    goldenFiles <- listGoldenFiles
    defaultMain (testGroup "Tests" (tests goldenFiles))

listGoldenFiles :: IO [FilePath]
listGoldenFiles = map (mappend dpath) . filter (not . isSuffixOf ".golden") <$> listDirectory dpath
  where
    dpath = "test/golden/"

tests :: [FilePath] -> [TestTree]
tests goldenFiles =
    [ testGroup "Golden test" $ map doGoldenTest goldenFiles
    ]

doGoldenTest :: FilePath -> TestTree
doGoldenTest fp = goldenVsString fp (fp <> ".golden") (flip mappend "\n" . LText.encodeUtf8 <$> doCheck)
  where
    doCheck :: IO LText.Text
    doCheck = do
        input <- T.readFile fp
        let fakeDate = ZonedTime (LocalTime (fromOrdinalDate 1970 0) midnight) utc
            attr =
                emptyOutOfBandAttributes
                    { oobPublished = Just fakeDate
                    , oobModified = Just fakeDate
                    }
            res = parseAdvisory NoOverrides attr input
        pure . pShowNoColor $ res
