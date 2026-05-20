{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module Security.CVSS.Internal
  ( CVSSDB (..),
    MetricGroup (..),
    MetricInfo (..),
    MetricValue (..),
    allMetrics,
    cvssDB,
    lookupMetricInfo,
    lookupMetricValueChar,
    lookupMetricValue,
    getMetricValue,
    getMetricValueOr,
    doCVSSInfo,
    roundup,
    validateUnique,
    validateKnown,
    validateRequired,
    hasTemporalMetrics,
    hasEnvironmentalMetrics,
    getModifiedMetricValue,
  )
where

import Data.Coerce (coerce)
import Data.Foldable (traverse_)
import Data.List (find, group, sort)
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import Data.Text qualified as Text
import GHC.Float (powerFloat)

import Security.CVSS.Types

pattern C :: Text -> MetricValueChar
pattern C c = MetricValueChar c

{-# COMPLETE C #-}

-- Constants used in place of Unchanged/Changed pattern synonyms
unchanged :: Float
unchanged = 6.42

changed :: Float
changed = 7.52

newtype CVSSDB = CVSSDB [MetricGroup]

data MetricGroup = MetricGroup
  { mgName :: Text,
    mgMetrics :: [MetricInfo]
  }

data MetricInfo = MetricInfo
  { miName :: Text,
    miShortName :: MetricShortName,
    miRequired :: Bool,
    miValues :: [MetricValue]
  }

data MetricValue = MetricValue
  { mvName :: Text,
    mvChar :: MetricValueChar,
    mvNum :: Float,
    mvNumChangedScope :: Maybe Float,
    mvDesc :: Text
  }

cvssDB :: CVSSVersion -> CVSSDB
cvssDB v = case v of
  CVSS40 -> error "cvss40 DB defined in Security.CVSS.V40"
  CVSS31 -> error "cvss31 DB defined in Security.CVSS.V31"
  CVSS30 -> error "cvss30 DB defined in Security.CVSS.V30"
  CVSS20 -> error "cvss20 DB defined in Security.CVSS.V20"

allMetrics :: CVSSDB -> [MetricInfo]
allMetrics (CVSSDB db) = concatMap mgMetrics db

lookupMetricInfo :: CVSSDB -> Text -> Maybe MetricInfo
lookupMetricInfo db name =
  find (\mi -> miName mi == name) (allMetrics db)

lookupMetricValueChar :: CVSSDB -> [Metric] -> Text -> Maybe MetricValueChar
lookupMetricValueChar db metrics name = do
  mi <- lookupMetricInfo db name
  Metric _ valueChar <- find (\metric -> miShortName mi == mName metric) metrics
  pure valueChar

lookupMetricValue :: CVSSDB -> [Metric] -> Float -> Text -> Maybe Float
lookupMetricValue db metrics scope name = do
  mi <- lookupMetricInfo db name
  valueChar <- lookupMetricValueChar db metrics name
  mv <- find (\mv -> mvChar mv == valueChar) (miValues mi)
  pure $ case mvNumChangedScope mv of
    Just value | scope /= unchanged -> value
    _ -> mvNum mv

getMetricValue :: CVSSDB -> [Metric] -> Float -> Text -> Float
getMetricValue db metrics scope name = case lookupMetricValue db metrics scope name of
  Nothing -> error $ "The impossible have happened, unknown metric: " <> Text.unpack name
  Just value -> value

getMetricValueOr :: CVSSDB -> [Metric] -> Float -> Float -> Text -> Float
getMetricValueOr db metrics defaultValue scope name = case lookupMetricValue db metrics scope name of
  Nothing -> defaultValue
  Just value -> value

doCVSSInfo :: CVSSDB -> [Metric] -> [Text]
doCVSSInfo (CVSSDB db) = map showMetricInfo
  where
    showMetricInfo metric = case mapMaybe (getInfo metric) db of
      [(mg, mi, mv)] ->
        mconcat [mgName mg, " ", miName mi, ": ", mvName mv, " (", mvDesc mv, ")"]
      _ -> error $ "The impossible have happened for " <> show metric
    getInfo metric mg = do
      mi <- find (\mi -> miShortName mi == mName metric) (mgMetrics mg)
      mv <- find (\mv -> mvChar mv == mChar metric) (miValues mi)
      pure (mg, mi, mv)

roundup :: Float -> Float
roundup input
  | int_input `mod` 10000 == 0 = fromIntegral int_input / 100000
  | otherwise = (fromIntegral (floor_int (fromIntegral int_input / 10000)) + 1) / 10
  where
    floor_int :: Float -> Int
    floor_int = floor
    int_input :: Int
    int_input = round (input * 100000)

validateUnique :: [Metric] -> Either CVSSError ()
validateUnique = traverse_ checkDouble . group . sort . map mName
  where
    checkDouble [] = error "The impossible have happened"
    checkDouble [_] = pure ()
    checkDouble (MetricShortName n : _) = Left (DuplicateMetric n)

validateKnown :: CVSSDB -> [Metric] -> Either CVSSError ()
validateKnown db = traverse_ checkKnown
  where
    checkKnown (Metric name char) = do
      mi <- case find (\mi -> miShortName mi == name) (allMetrics db) of
        Nothing -> Left (UnknownMetric (coerce name))
        Just m -> pure m
      case find (\mv -> mvChar mv == char) (miValues mi) of
        Nothing -> Left (UnknownValue (coerce name) (coerce char))
        Just _ -> pure ()

validateRequired :: CVSSDB -> [Metric] -> Either CVSSError ()
validateRequired db metrics = traverse_ checkRequired (allMetrics db)
  where
    checkRequired mi
      | miRequired mi,
        Nothing <- find (\metric -> miShortName mi == mName metric) metrics =
          Left (MissingRequiredMetric (miName mi))
      | otherwise = pure ()

hasTemporalMetrics :: [Metric] -> Bool
hasTemporalMetrics =
  any (\metric -> mName metric `elem` ["E", "RL", "RC"])

hasEnvironmentalMetrics :: [Metric] -> Bool
hasEnvironmentalMetrics =
  any
    ( \metric ->
        mName metric
          `elem` ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]
    )

getModifiedMetricValue :: CVSSDB -> [Metric] -> Text -> Text -> Float -> Float
getModifiedMetricValue db ms modifiedName baseName scope =
  case lookupMetricValueChar db ms modifiedName of
    Just (C "X") -> getMetricValue db ms scope baseName
    Just _ -> getMetricValue db ms scope modifiedName
    Nothing -> getMetricValue db ms scope baseName