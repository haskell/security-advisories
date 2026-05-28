{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Security.CVSS.Types
  ( CVSS (..),
    CVSSVersion (..),
    CVSSNomenclature (..),
    Rating (..),
    CVSSError (..),
    Metric (..),
    MetricShortName (..),
    MetricValueChar (..),
    showCVSSError,
    toRating,
    toRating20,
  )
where

import Data.String (IsString)
import Data.Text (Text)
import Data.Text qualified as Text

newtype MetricShortName = MetricShortName Text
  deriving newtype (Eq, IsString, Ord, Show)

newtype MetricValueChar = MetricValueChar Text
  deriving newtype (Eq, IsString, Ord, Show)

data Metric = Metric
  { mName :: MetricShortName,
    mChar :: MetricValueChar
  }
  deriving (Eq, Show)

data CVSSVersion
  = CVSS40
  | CVSS31
  | CVSS30
  | CVSS20
  deriving (Eq, Show)

data CVSSNomenclature
  = CVSS_B
  | CVSS_BT
  | CVSS_BE
  | CVSS_BTE
  deriving stock (Eq, Show)

data CVSS = CVSS
  { cvssVersion :: CVSSVersion,
    cvssMetrics :: [Metric]
  }
  deriving stock (Eq)

data Rating = None | Low | Medium | High | Critical
  deriving (Enum, Eq, Ord, Show)

data CVSSError
  = UnknownVersion
  | EmptyComponent
  | MissingValue Text
  | DuplicateMetric Text
  | MissingRequiredMetric Text
  | UnknownMetric Text
  | UnknownValue Text Text

instance Show CVSSError where
  show = Text.unpack . showCVSSError

showCVSSError :: CVSSError -> Text
showCVSSError e = case e of
  UnknownVersion -> "Unknown CVSS version"
  EmptyComponent -> "Empty component"
  MissingValue name -> "Missing value for \"" <> name <> "\""
  DuplicateMetric name -> "Duplicate metric for \"" <> name <> "\""
  MissingRequiredMetric name -> "Missing required metric \"" <> name <> "\""
  UnknownMetric name -> "Unknown metric \"" <> name <> "\""
  UnknownValue name value -> "Unknown value '" <> value <> "' for \"" <> name <> "\""

toRating :: Float -> Rating
toRating score
  | score <= 0 = None
  | score < 4 = Low
  | score < 7 = Medium
  | score < 9 = High
  | otherwise = Critical

toRating20 :: Float -> Rating
toRating20 score
  | score <= 0 = None
  | score < 4 = Low
  | score < 7 = Medium
  | otherwise = High
