{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Security.CVSS
-- Description : Main entry point for CVSS v2.0, v3.0, v3.1, and v4.0 scoring
--
-- Provides a unified interface for parsing, validating, and scoring
-- Common Vulnerability Scoring System (CVSS) vector strings across
-- all supported versions:
--
-- * __CVSS v2.0__ — https:\/\/www.first.org\/cvss\/v2\/guide
-- * __CVSS v3.0__ — https:\/\/www.first.org\/cvss\/v3-0\/
-- * __CVSS v3.1__ — https:\/\/www.first.org\/cvss\/v3-1\/
-- * __CVSS v4.0__ — https:\/\/www.first.org\/cvss\/v4.0\/specification-document
--
-- Vector string formats:
--
-- * v4.0: @CVSS:4.0\/AV:N\/AC:L\/...@
-- * v3.1: @CVSS:3.1\/AV:N\/AC:L\/...@
-- * v3.0: @CVSS:3.0\/AV:N\/AC:L\/...@
-- * v2.0: @AV:N\/AC:L\/Au:N\/...@ (no prefix)
module Security.CVSS
  ( -- * Types
    CVSS (..),
    CVSSVersion (..),
    CVSSNomenclature (..),
    Rating (..),
    CVSSError (..),
    Metric (..),
    MetricShortName,
    MetricValueChar,
    showCVSSError,
    toRating,
    toRating20,

    -- * Parser
    parseCVSS,

    -- * Helpers
    cvssVectorString,
    cvssVectorStringOrdered,
    cvssScore,
    cvss20TemporalScore,
    cvss20EnvironmentalScore,
    cvss30TemporalScore,
    cvss30EnvironmentalScore,
    cvss31TemporalScore,
    cvss31EnvironmentalScore,
    cvss40score,
    cvss40BaseScore,
    cvss40EnvironmentalScore,
    cvssInfo,
    cvssSupplementalInfo,

    -- * Nomenclature
    determineNomenclature,
    cvssScoreWithNomenclature,
    showCVSSWithNomenclature,
  )
where

import Data.List (find)
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import Data.Text qualified as Text
import Security.CVSS.Internal (CVSSDB (..), allMetrics, doCVSSInfo, miShortName)
import Security.CVSS.Types (CVSS (..), CVSSError (..), CVSSNomenclature (..), CVSSVersion (..), Metric (..), MetricShortName (..), MetricValueChar (..), Rating (..), showCVSSError, toRating, toRating20)
import Security.CVSS.V20 (cvss20DB, cvss20EnvironmentalScore, cvss20TemporalScore, cvss20score, validateCvss20)
import Security.CVSS.V30 (cvss30DB, cvss30EnvironmentalScore, cvss30TemporalScore, cvss30score, validateCvss30)
import Security.CVSS.V31 (cvss31DB, cvss31EnvironmentalScore, cvss31TemporalScore, cvss31score, validateCvss31)
import Security.CVSS.V40 (cvss40BaseScore, cvss40DB, cvss40EnvironmentalScore, cvss40SupplementalInfo, cvss40score, hasEnvironmentalMetrics40, hasThreatMetrics40, validateCvss40)

-- | Parse a CVSS vector string into a 'CVSS' value.
--
-- The version is detected from the prefix:
--
-- * @CVSS:4.0\/...@ → CVSS40
-- * @CVSS:3.1\/...@ → CVSS31
-- * @CVSS:3.0\/...@ → CVSS30
-- * Any other string without a @CVSS:@ prefix → CVSS20
-- * @CVSS:@ with an unknown version → 'Left' 'UnknownVersion'
parseCVSS :: Text -> Either CVSSError CVSS
parseCVSS txt
  | "CVSS:4.0/" `Text.isPrefixOf` txt = CVSS CVSS40 <$> validateComponents True validateCvss40
  | "CVSS:3.1/" `Text.isPrefixOf` txt = CVSS CVSS31 <$> validateComponents True validateCvss31
  | "CVSS:3.0/" `Text.isPrefixOf` txt = CVSS CVSS30 <$> validateComponents True validateCvss30
  | "CVSS:" `Text.isPrefixOf` txt = Left UnknownVersion
  | otherwise = CVSS CVSS20 <$> validateComponents False validateCvss20
  where
    validateComponents withPrefix validator = do
      metrics <- traverse splitComponent $ components withPrefix
      _ <- validator metrics
      pure metrics

    components withPrefix = (if withPrefix then drop 1 else id) $ Text.split (== '/') txt
    splitComponent :: Text -> Either CVSSError Metric
    splitComponent componentTxt = case Text.breakOnEnd ":" componentTxt of
      ("", _) -> Left EmptyComponent
      (_, "") -> Left (MissingValue componentTxt)
      (nameWithColon, valueText) ->
        let name = Text.init nameWithColon
         in Right (Metric (MetricShortName name) (MetricValueChar valueText))

-- | Compute the CVSS score for any supported version.
-- Dispatches to the appropriate version-specific scorer.
cvssScore :: CVSS -> (Rating, Float)
cvssScore cvss = case cvssVersion cvss of
  CVSS40 -> cvss40score (cvssMetrics cvss)
  CVSS31 -> cvss31score (cvssMetrics cvss)
  CVSS30 -> cvss30score (cvssMetrics cvss)
  CVSS20 -> cvss20score (cvssMetrics cvss)

-- | Look up human-readable descriptions for each metric in the vector.
cvssInfo :: CVSS -> [Text]
cvssInfo cvss = doCVSSInfo (cvssDB (cvssVersion cvss)) (cvssMetrics cvss)

-- | Render the CVSS vector string preserving the original metric order.
cvssVectorString :: CVSS -> Text
cvssVectorString = cvssShow False

-- | Render the CVSS vector string in canonical (specification-defined) metric order.
cvssVectorStringOrdered :: CVSS -> Text
cvssVectorStringOrdered = cvssShow True

-- | Internal: render a CVSS vector string, optionally ordering metrics
-- according to the specification.
cvssShow :: Bool -> CVSS -> Text
cvssShow ordered cvss = case cvssVersion cvss of
  CVSS40 -> Text.intercalate "/" ("CVSS:4.0" : components)
  CVSS31 -> Text.intercalate "/" ("CVSS:3.1" : components)
  CVSS30 -> Text.intercalate "/" ("CVSS:3.0" : components)
  CVSS20 -> Text.intercalate "/" components
  where
    components = map toComponent (cvssOrder (cvssMetrics cvss))
    toComponent :: Metric -> Text
    toComponent (Metric (MetricShortName name) (MetricValueChar value)) = name <> ":" <> value
    cvssOrder metrics
      | ordered = mapMaybe getMetric (allMetrics (cvssDB (cvssVersion cvss)))
      | otherwise = metrics
      where
        getMetric mi = find (\metric -> miShortName mi == mName metric) metrics

-- | Retrieve supplemental metric info for CVSS v4.0 vectors.
-- Returns 'Nothing' for all other CVSS versions.
cvssSupplementalInfo :: CVSS -> Maybe Text
cvssSupplementalInfo cvss = case cvssVersion cvss of
  CVSS40 -> Security.CVSS.V40.cvss40SupplementalInfo (cvssMetrics cvss)
  _ -> Nothing

-- | Get the metric database for a given CVSS version.
cvssDB :: CVSSVersion -> CVSSDB
cvssDB v = case v of
  CVSS40 -> cvss40DB
  CVSS31 -> cvss31DB
  CVSS30 -> cvss30DB
  CVSS20 -> cvss20DB

-- | Determine the CVSS nomenclature (CVSS-B, CVSS-BT, CVSS-BE, CVSS-BTE)
-- for a CVSS v4.0 vector based on which metric groups are present.
-- For v2.x and v3.x, always returns 'CVSS_B'.
determineNomenclature :: CVSS -> CVSSNomenclature
determineNomenclature cvss = case cvssVersion cvss of
  CVSS40 ->
    let metrics = cvssMetrics cvss
        hasT = hasThreatMetrics40 metrics
        hasE = hasEnvironmentalMetrics40 metrics
     in case (hasT, hasE) of
          (False, False) -> CVSS_B
          (True, False) -> CVSS_BT
          (False, True) -> CVSS_BE
          (True, True) -> CVSS_BTE
  _ -> CVSS_B

-- | Compute the score along with the CVSS nomenclature.
cvssScoreWithNomenclature :: CVSS -> (Rating, Float, CVSSNomenclature)
cvssScoreWithNomenclature cvss =
  let (rating, score) = cvssScore cvss
      nomen = determineNomenclature cvss
   in (rating, score, nomen)

-- | Render a CVSS vector with its nomenclature, rating, and score
-- in the format @CVSS-B:Medium\/6.5@ (or CVSS-BT, CVSS-BE, CVSS-BTE).
showCVSSWithNomenclature :: CVSS -> Text
showCVSSWithNomenclature cvss =
  let (rating, score, nomen) = cvssScoreWithNomenclature cvss
      nomenStr = case nomen of
        CVSS_B -> "CVSS-B"
        CVSS_BT -> "CVSS-BT"
        CVSS_BE -> "CVSS-BE"
        CVSS_BTE -> "CVSS-BTE"
   in nomenStr <> ":" <> Text.pack (show rating) <> "/" <> Text.pack (show score)
