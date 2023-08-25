{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

{- | This module provides a CVSS parser and utility functions
 adapted from https://www.first.org/cvss/v3.1/specification-document
-}
module Security.CVSS (
    -- * Type
    CVSS (cvssVersion),
    CVSSVersion (..),
    Rating (..),
    parseCVSS,

    -- * Helpers
    cvssVectorString,
    cvssVectorStringOrdered,
    cvssScore,
    cvssInfo,
) where

import Data.Foldable (traverse_)
import Data.List (find, group, sort)
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import Data.Text qualified as Text
import GHC.Float (powerFloat)

-- | The CVSS version.
data CVSSVersion
    = -- | Version 3.1: https://www.first.org/cvss/v3-1/
      CVSS31

-- | Parsed CVSS string obtained with 'parseCVSS'.
data CVSS = CVSS
    { cvssVersion :: CVSSVersion
    -- ^ The CVSS Version.
    , cvssMetrics :: [Metric]
    -- ^ The metrics are stored as provided by the user
    }

instance Show CVSS where
    show = Text.unpack . cvssVectorString

-- | CVSS Rating obtained with 'cvssScore'
data Rating = None | Low | Medium | High | Critical
    deriving (Enum, Eq, Ord, Show)

-- | Implementation of Section 5. "Qualitative Severity Rating Scale"
toRating :: Float -> Rating
toRating score
    | score <= 0 = None
    | score < 4 = Low
    | score < 7 = Medium
    | score < 9 = High
    | otherwise = Critical

type Metric = (Text, Char)

-- example CVSS string: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N

-- | Parse a CVSS string.
parseCVSS :: Text -> Either Text CVSS
parseCVSS txt
    | "CVSS:3.1/" `Text.isPrefixOf` txt = parseCVSS31
    | otherwise = Left "Unknown CVSS version"
  where
    parseCVSS31 =
        CVSS CVSS31 <$> do
            metrics <- traverse splitComponent components
            validateCvss31 metrics

    components = drop 1 $ Text.split (== '/') txt
    splitComponent :: Text -> Either Text Metric
    splitComponent componentTxt = case Text.unsnoc componentTxt of
        Nothing -> Left "Empty component"
        Just (rest, c) -> case Text.unsnoc rest of
            Just (name, ':') -> Right (name, c)
            _ -> Left "Expected :"

-- | Compute the base score.
cvssScore :: CVSS -> (Rating, Float)
cvssScore cvss = case cvssVersion cvss of
    CVSS31 -> cvss31score (cvssMetrics cvss)

-- | Explain the CVSS metrics.
cvssInfo :: CVSS -> [Text]
cvssInfo cvss = case cvssVersion cvss of
    CVSS31 -> cvss31info (cvssMetrics cvss)

-- | Format the CVSS back to its original string.
cvssVectorString :: CVSS -> Text
cvssVectorString = cvssShow False

-- | Format the CVSS to the prefered ordered vector string.
cvssVectorStringOrdered :: CVSS -> Text
cvssVectorStringOrdered = cvssShow True

cvssShow :: Bool -> CVSS -> Text
cvssShow ordered cvss = case cvssVersion cvss of
    CVSS31 -> Text.intercalate "/" ("CVSS:3.1" : map toComponent (cvss31Order (cvssMetrics cvss)))
  where
    toComponent (name, value) = Text.snoc (name <> ":") value
    cvss31Order xs
        | ordered = mapMaybe getMetric allMetrics
        | otherwise = xs
      where
        getMetric mi = find (\(name, _) -> miShortName mi == name) xs

-- | Description of a metric group.
data MetricGroup = MetricGroup
    { mgName :: Text
    , mgMetrics :: [MetricInfo]
    }

-- | Description of a single metric.
data MetricInfo = MetricInfo
    { miName :: Text
    , miShortName :: Text
    , miRequired :: Bool
    , miValues :: [MetricValue]
    }

-- | Description of a single metric value
data MetricValue = MetricValue
    { mvName :: Text
    , mvChar :: Char
    , mvNum :: Float
    , mvNumChangedScope :: Maybe Float
    , mvDesc :: Text
    }

-- | CVSS3.1 metrics pulled from section 2. "Base Metrics" and section section 7.4. "Metric Values"
cvss31 :: [MetricGroup]
cvss31 =
    [ MetricGroup "Base" baseMetrics
    , MetricGroup "Temporal" temporalMetrics
    , MetricGroup "Environmental" environmentalMetrics
    ]
  where
    baseMetrics =
        [ MetricInfo
            "Attack Vector"
            "AV"
            True
            [ MetricValue "Network" 'N' 0.85 Nothing "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet."
            , MetricValue "Adjacent" 'A' 0.62 Nothing "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology."
            , MetricValue "Local" 'L' 0.55 Nothing "The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities."
            , MetricValue "Physical" 'P' 0.2 Nothing "The attack requires the attacker to physically touch or manipulate the vulnerable component."
            ]
        , MetricInfo
            "Attack Complexity"
            "AC"
            True
            [ MetricValue "Low" 'L' 0.77 Nothing "Specialized access conditions or extenuating circumstances do not exist."
            , MetricValue "High" 'H' 0.44 Nothing "A successful attack depends on conditions beyond the attacker's control."
            ]
        , MetricInfo
            "Privileges Required"
            "PR"
            True
            [ MetricValue "None" 'N' 0.85 Nothing "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack."
            , MetricValue "Low" 'L' 0.62 (Just 0.68) "The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user."
            , MetricValue "High" 'H' 0.27 (Just 0.5) "The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
            ]
        , MetricInfo
            "User Interaction"
            "UI"
            True
            [ MetricValue "None" 'N' 0.85 Nothing "The vulnerable system can be exploited without interaction from any user."
            , MetricValue "Required" 'R' 0.62 Nothing "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited."
            ]
        , MetricInfo
            "Scope"
            "S"
            True
            [ -- Note: not defined as contants in specification
              MetricValue "Unchanged" 'U' Unchanged Nothing "An exploited vulnerability can only affect resources managed by the same security authority."
            , MetricValue "Changed" 'C' Changed Nothing "An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component."
            ]
        , MetricInfo
            "Confidentiality Impact"
            "C"
            True
            [ mkHigh "There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker."
            , mkLow "There is some loss of confidentiality."
            , mkNone "There is no loss of confidentiality within the impacted component."
            ]
        , MetricInfo
            "Integrity Impact"
            "I"
            True
            [ mkHigh "There is a total loss of integrity, or a complete loss of protection."
            , mkLow "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited."
            , mkNone "There is no loss of integrity within the impacted component."
            ]
        , MetricInfo
            "Availability Impact"
            "A"
            True
            [ mkHigh "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component"
            , mkLow "Performance is reduced or there are interruptions in resource availability."
            , mkNone "There is no impact to availability within the impacted component."
            ]
        ]
    mkHigh = MetricValue "High" 'H' 0.56 Nothing
    mkLow = MetricValue "Low" 'L' 0.22 Nothing
    mkNone = MetricValue "None" 'N' 0 Nothing
    -- TODOs
    temporalMetrics = []
    environmentalMetrics = []

pattern Unchanged :: Float
pattern Unchanged = 6.42
pattern Changed :: Float
pattern Changed = 7.52

cvss31info :: [Metric] -> [Text]
cvss31info = map showMetricInfo
  where
    showMetricInfo metric = case mapMaybe (getInfo metric) cvss31 of
        [(mg, mi, mv)] ->
            mconcat [mgName mg, " ", miName mi, ": ", mvName mv, " (", mvDesc mv, ")"]
        _ -> error $ "The impossible have happened for " <> show metric
    getInfo (name, value) mg = do
        mi <- find (\mi -> miShortName mi == name) (mgMetrics mg)
        mv <- find (\mv -> mvChar mv == value) (miValues mi)
        pure (mg, mi, mv)

allMetrics :: [MetricInfo]
allMetrics = concatMap mgMetrics cvss31

-- | Implementation of the Appendix A - "Floating Point Rounding"
roundup :: Float -> Float
roundup input
    | int_input `mod` 10000 == 0 = fromIntegral int_input / 100000
    | otherwise = (fromIntegral (floor_int (fromIntegral int_input / 10000)) + 1) / 10
  where
    floor_int :: Float -> Int
    floor_int = floor
    int_input :: Int
    int_input = round (input * 100000)

-- | Implementation of section 7.1. Base Metrics Equations
cvss31score :: [Metric] -> (Rating, Float)
cvss31score metrics = (toRating score, score)
  where
    iss = 1 - (1 - gm "Confidentiality Impact") * (1 - gm "Integrity Impact") * (1 - gm "Availability Impact")
    impact
        | scope == Unchanged = scope * iss
        | otherwise = scope * (iss - 0.029) - 3.25 * powerFloat (iss - 0.02) 15
    exploitability = 8.22 * gm "Attack Vector" * gm "Attack Complexity" * gm "Privileges Required" * gm "User Interaction"
    score
        | impact <= 0 = 0
        | scope == Unchanged = roundup (min (impact + exploitability) 10)
        | otherwise = roundup (min (1.08 * (impact + exploitability)) 10)
    scope = gm "Scope"

    gm :: Text -> Float
    gm name = case getMetric name of
        Nothing -> error $ "The impossible have happened, unknown metric: " <> Text.unpack name
        Just v -> v
    getMetric :: Text -> Maybe Float
    getMetric name = do
        mi <- find (\mi -> miName mi == name) allMetrics
        valueChar <- lookup (miShortName mi) metrics
        mv <- find (\mv -> mvChar mv == valueChar) (miValues mi)
        pure $ case mvNumChangedScope mv of
            Just value | scope /= Unchanged -> value
            _ -> mvNum mv

validateCvss31 :: [Metric] -> Either Text [Metric]
validateCvss31 metrics = do
    traverse_ (\t -> t metrics) [validateUnique, validateKnown, validateRequired]
    pure metrics

{- | Check for duplicates metric

 >>> validateUnique [("AV", 'N'), ("AC", 'L'), ("AV", 'L')]
 Left "Duplicated \"AV\""
-}
validateUnique :: [Metric] -> Either Text ()
validateUnique = traverse_ checkDouble . group . sort . map fst
  where
    checkDouble [] = error "The impossible have happened"
    checkDouble [_] = pure ()
    checkDouble (n : _) = Left $ "Duplicated \"" <> n <> "\""

{- | Check for unknown metric

 >>> validateKnown [("AV", 'M')]
 Left "Unknown value: 'M'"

 >>> validateKnown [("AW", 'L')]
 Left "Unknown metric: \"AW\""
-}
validateKnown :: [Metric] -> Either Text ()
validateKnown = traverse_ checkKnown
  where
    checkKnown (name, value) = do
        mi <- case find (\mi -> miShortName mi == name) allMetrics of
            Nothing -> Left $ "Unknown metric: \"" <> name <> "\""
            Just m -> pure m
        case find (\mv -> mvChar mv == value) (miValues mi) of
            Nothing -> Left $ "Unknown value: '" <> Text.pack (show value) <> "'"
            Just _ -> pure ()

{- | Check for required metric

 >>> validateRequired []
 Left "Missing \"Attack Vector\""
-}
validateRequired :: [Metric] -> Either Text ()
validateRequired metrics = traverse_ checkRequired allMetrics
  where
    checkRequired mi
        | miRequired mi
        , Nothing <- lookup (miShortName mi) metrics =
            Left $ "Missing \"" <> miName mi <> "\""
        | otherwise = pure ()
