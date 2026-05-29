{-# LANGUAGE OverloadedStrings #-}

module Security.Advisories.Core.OsvId
  ( OsvId,
    parseOsvId,
    printOsvId,
    osvIdPrefix,
  )
where

import qualified Data.List as L
import Data.Maybe (listToMaybe)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T

newtype OsvId = OsvId Text
  deriving (Eq, Ord, Show)

knownPrefixes :: Set.Set Text
knownPrefixes =
  Set.fromList
    [ "ASB-A",
      "PUB-A",
      "ALSA",
      "ALBA",
      "ALEA",
      "ALPINE",
      "BELL",
      "BIT",
      "CGA",
      "CleanStart",
      "CURL",
      "CVE",
      "DEBIAN",
      "DHI",
      "DRUPAL",
      "DSA",
      "DLA",
      "DTSA",
      "ECHO",
      "EEF",
      "ELA",
      "GHSA",
      "GO",
      "GSD",
      "HSEC",
      "JLSEC",
      "KUBE",
      "LBSEC",
      "LSN",
      "MGASA",
      "MAL",
      "MINI",
      "OESA",
      "OSEC",
      "OSV",
      "PHSA",
      "PSF",
      "PYSEC",
      "RHSA",
      "RHBA",
      "RHEA",
      "RLSA",
      "RXSA",
      "RSEC",
      "ROOT",
      "RUSTSEC",
      "SUSE-SU",
      "SUSE-RU",
      "SUSE-FU",
      "SUSE-OU",
      "openSUSE-SU",
      "UBUNTU",
      "USN",
      "V8"
    ]

sortedPrefixes :: [Text]
sortedPrefixes = L.reverse . L.sortOn T.length $ Set.toList knownPrefixes

parseOsvId :: Text -> Maybe OsvId
parseOsvId t = do
  prefix <- findPrefix t
  let rest = T.drop (T.length prefix + 1) t
  guard (not (T.null rest))
  pure (OsvId t)
  where
    findPrefix txt =
      listToMaybe $
        filter (\p -> T.isPrefixOf (p <> "-") txt) sortedPrefixes

    guard True = Just ()
    guard False = Nothing

printOsvId :: OsvId -> Text
printOsvId (OsvId t) = t

osvIdPrefix :: OsvId -> Text
osvIdPrefix (OsvId t) = case findPrefix t of
  Just p -> p
  Nothing -> T.takeWhile (/= '-') t
  where
    findPrefix txt =
      listToMaybe $
        filter (\p -> T.isPrefixOf (p <> "-") txt) sortedPrefixes
