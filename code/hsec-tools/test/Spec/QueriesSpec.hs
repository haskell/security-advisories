{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Spec.QueriesSpec (spec) where

import Data.Bifunctor (first)
import Data.Either (fromRight)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Distribution.Parsec (eitherParsec)
import Distribution.Types.Version (version0, alterVersion)
import Distribution.Types.VersionRange (VersionRange, VersionRangeF(..), anyVersion, projectVersionRange)
import Test.Tasty
import Test.Tasty.HUnit

import Security.CVSS (parseCVSS)
import Security.Advisories.Core.Advisory
import Security.Advisories.Core.HsecId
import Security.Advisories.Queries

spec :: TestTree
spec =
  testGroup "Queries" [
    testGroup "isAffectedBy" $
      flip concatMap cases $ map $ \(actual, query, expected) ->
        let title x y =
              if expected
                then show x <> " is vulnerable to " <> show y
                else show x <> " is not vulnerable to " <> show y
            versionRange x =
              either (\e -> error $ "Cannot parse version range " <> show x <> " : " <> show e) id $
                parseVersionRange $
                  if x == ""
                    then Nothing
                    else Just x
         in testCase (title actual query) $
              let query' = versionRange query
                  affectedVersion' = versionRange actual
              in isVersionRangeAffectedBy packageName query' (mkAdvisory affectedVersion')
                    @?= expected
  ]

cases :: [[(Text, Text, Bool)]]
cases =
  [
    reversible ("", "", True)
  , reversible ("", "==1", True)
  , reversible ("==1.1", "<=2", True)
  , reversible ("==1.1", ">1", True)
  , reversible ("==1", "==1", True)
  , reversible ("==2||==1", "==1", True)
  , reversible ("==1.1", "<=2&&>1", True)
  , reversible ("^>=1", ">1&&<1.2", True)
  , reversible (">=1", "==2", True)
  , reversible (">=1", "==1", True)
  , reversible ("==2", ">=2", True)
  , reversible ("==2", ">1", True)
  , reversible (">5", ">=2", True)
  , reversible (">5", ">2", True)
  , reversible ("==5", ">=2", True)
  , reversible ("==5", ">2", True)
  , reversible (">=5", ">2", True)
  , reversible ("<=5", ">2", True)
  , reversible ("<=5", "<=2", True)
  , reversible ("<5", ">=2", True)
  , reversible (">=2", "==5", True)
  , reversible (">2", "==5", True)
  , reversible (">5", ">=5", True)
  , reversible ("^>=1.1", ">1", True)
  , reversible ("^>=1.1", "<2", True)
  , reversible ("^>=1.1", "<=1.2", True)
  , reversible ("^>=1.1", ">1.1", True)
  , reversible ("^>=1.1", ">=1.1.5", True)
  , reversible ("^>=1.1", ">=1", True)
  , reversible ("==1.1", "<1", False)
  , reversible ("==2.1", "<=2", False)
  , reversible ("==1", ">1.1", False)
  , reversible ("==2", "==1", False)
  , reversible ("==2||==1", ">3", False)
  , notReversible ("<=2&&>1", "==3", True)
  , reversible (">=2", "==1.1", False)
  , reversible (">=1.1", "==1", False)
  , reversible ("==2", ">=2.1", False)
  , notReversible (">1", "==1", False)
  , reversible ("<2", ">=2", False)
  , reversible ("==2", ">=5", False)
  , reversible ("==2", ">5", False)
  , reversible ("<=2", ">5", False)
  , reversible ("<=2", ">5", False)
  , reversible ("<2", ">=5", False)
  , reversible (">=2", "==1.1", False)
  , reversible ("<2", "==5", False)
  , reversible ("<5", ">=5", False)
  , reversible ("^>=1.1", "<1", False)
  , reversible ("^>=1.1", "<1.1", False)
  , reversible ("^>=1.1", ">=1.2", False)
  , reversible ("^>=1.1", "<=1", False)
  , reversible ("^>=1.1", ">2", False)
  , reversible ("^>=1", ">=2", False)
  ]
  where reversible (query, affectedVersion, expected) = [(query, affectedVersion, expected), (query, affectedVersion, expected)]
        notReversible (query, affectedVersion, expected) = [(query, affectedVersion, expected), (affectedVersion, query, not expected)]

mkAdvisory :: VersionRange -> Advisory
mkAdvisory versionRange =
   Advisory
     { advisoryId = fromMaybe (error "Cannot mkHsecId") $ mkHsecId 2023 42
     , advisoryModified = read "2023-01-01T00:00:00"
     , advisoryPublished = read "2023-01-01T00:00:00"
     , advisoryCAPECs = []
     , advisoryCWEs = []
     , advisoryKeywords = []
     , advisoryAliases = [ "CVE-2022-XXXX" ]
     , advisoryRelated = [ "CVE-2022-YYYY" , "CVE-2022-ZZZZ" ]
     , advisoryAffected =
         [ Affected
             { affectedPackage = packageName
             , affectedCVSS = cvss
             , affectedVersions = mkAffectedVersions versionRange
             , affectedArchitectures = Nothing
             , affectedOS = Nothing
             , affectedDeclarations = []
             }
         ]
     , advisoryReferences = []
     , advisoryPandoc = mempty
     , advisoryHtml = ""
     , advisorySummary = ""
     , advisoryDetails = ""
     }
  where
    cvss = fromRight (error "Cannot parseCVSS") (parseCVSS "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

mkAffectedVersions :: VersionRange -> [AffectedVersionRange]
mkAffectedVersions vr =
  let
    fixed from to =
      AffectedVersionRange
        { affectedVersionRangeIntroduced = from
        , affectedVersionRangeFixed = Just to
        }
    onlyFixed to =
      AffectedVersionRange
        { affectedVersionRangeIntroduced = version0
        , affectedVersionRangeFixed = Just to
        }
    vulnerable from =
      AffectedVersionRange
        { affectedVersionRangeIntroduced = from
        , affectedVersionRangeFixed = Nothing
        }
    nextMinor =
      \case
        [] -> [1]
        [x] -> [x, 1]
        [x, y] -> [x, y, 1]
        [x, y, z] -> [x, y, z, 1]
        [w, x, y, z] -> [w, x, y, z + 1]
        xs -> xs ++ [1]
    previousMinor =
      \case
        [] -> [0]
        [x] -> [x - 1 , 99]
        [x, y] -> [x, y - 1, 99]
        [x, y, z] -> [x, y, z - 1, 99]
        [w, x, y, z] -> [w, x, y, z - 1]
        _ -> error "TODO"
    mkMajorBoundVersion =
      \case
        [] -> [0]
        [x] -> [x, 1]
        (x:y:_) -> [x, y + 1]
  in
  case projectVersionRange vr of
    ThisVersionF x -> [fixed x $ alterVersion (<> [0,0,1]) x]
    LaterVersionF x -> [vulnerable $ alterVersion nextMinor x]
    OrLaterVersionF x -> [vulnerable x]
    EarlierVersionF x -> [onlyFixed $ alterVersion previousMinor x]
    OrEarlierVersionF x -> [onlyFixed x]
    MajorBoundVersionF x -> [fixed x $ alterVersion mkMajorBoundVersion x]
    UnionVersionRangesF x y -> mkAffectedVersions x <> mkAffectedVersions y
    IntersectVersionRangesF x y ->
      [ low { affectedVersionRangeFixed = affectedVersionRangeFixed high }
      | low <- mkAffectedVersions x
      , high <- mkAffectedVersions y
      ]

packageName :: Text
packageName = "package-name"

-- | Parse 'VersionRange' as given to the CLI
parseVersionRange :: Maybe Text -> Either Text VersionRange
parseVersionRange  = maybe (return anyVersion) (first T.pack . eitherParsec . T.unpack)
