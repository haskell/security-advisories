{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeApplications #-}

-- | This module provides a CVSS parser and utility functions
-- adapted from https://www.first.org/cvss/v3.1/specification-document
module Security.CVSS
  ( -- * Type
    CVSS (cvssVersion),
    CVSSVersion (..),
    Rating (..),

    -- * Parser
    parseCVSS,
    CVSSError (..),

    -- * Helpers
    cvssVectorString,
    cvssVectorStringOrdered,
    cvssScore,
    cvssInfo,
  )
where

import Data.Coerce (coerce)
import Data.Foldable (traverse_)
import Data.List (find, group, sort)
import Data.Maybe (mapMaybe)
import Data.String (IsString)
import Data.Text (Text)
import Data.Text qualified as Text
import GHC.Float (powerFloat)

-- | The CVSS version.
data CVSSVersion
  = -- | Version 3.1: https://www.first.org/cvss/v3-1/
    CVSS31
  | -- | Version 3.0: https://www.first.org/cvss/v3.0/
    CVSS30
  | -- | Version 2.0: https://www.first.org/cvss/v2/
    CVSS20
  deriving (Eq)

-- | Parsed CVSS string obtained with 'parseCVSS'.
data CVSS = CVSS
  { -- | The CVSS Version.
    cvssVersion :: CVSSVersion,
    -- | The metrics are stored as provided by the user
    cvssMetrics :: [Metric]
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

data CVSSError
  = UnknownVersion
  | EmptyComponent
  | MissingValue Text
  | DuplicateMetric Text
  | MissingRequiredMetric Text
  | UnknownMetric Text
  | UnknownValue Text Char

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
  UnknownValue name value -> "Unknown value '" <> Text.pack (show value) <> "' for \"" <> name <> "\""

newtype MetricShortName = MetricShortName Text
  deriving newtype (Eq, IsString, Ord, Show)

newtype MetricValueChar = MetricValueChar Char
  deriving newtype (Eq, Ord, Show)

data Metric = Metric
  { mName :: MetricShortName,
    mChar :: MetricValueChar
  }
  deriving (Show)

-- example CVSS string: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N

-- | Parse a CVSS string.
parseCVSS :: Text -> Either CVSSError CVSS
parseCVSS txt
  | "CVSS:3.1/" `Text.isPrefixOf` txt = CVSS CVSS31 <$> validateComponents validateCvss31
  | "CVSS:3.0/" `Text.isPrefixOf` txt = CVSS CVSS30 <$> validateComponents validateCvss30
  | "CVSS:2.0/" `Text.isPrefixOf` txt = CVSS CVSS20 <$> validateComponents validateCvss20
  | otherwise = Left UnknownVersion
  where
    validateComponents validator = do
      metrics <- traverse splitComponent components
      validator metrics

    components = drop 1 $ Text.split (== '/') txt
    splitComponent :: Text -> Either CVSSError Metric
    splitComponent componentTxt = case Text.unsnoc componentTxt of
      Nothing -> Left EmptyComponent
      Just (rest, c) -> case Text.unsnoc rest of
        Just (name, ':') -> Right (Metric (MetricShortName name) (MetricValueChar c))
        _ -> Left (MissingValue componentTxt)

-- | Compute the base score.
cvssScore :: CVSS -> (Rating, Float)
cvssScore cvss = case cvssVersion cvss of
  CVSS31 -> cvss31score (cvssMetrics cvss)
  CVSS30 -> cvss30score (cvssMetrics cvss)
  CVSS20 -> cvss20score (cvssMetrics cvss)

-- | Explain the CVSS metrics.
cvssInfo :: CVSS -> [Text]
cvssInfo cvss = doCVSSInfo (cvssDB (cvssVersion cvss)) (cvssMetrics cvss)

-- | Format the CVSS back to its original string.
cvssVectorString :: CVSS -> Text
cvssVectorString = cvssShow False

-- | Format the CVSS to the prefered ordered vector string.
cvssVectorStringOrdered :: CVSS -> Text
cvssVectorStringOrdered = cvssShow True

cvssShow :: Bool -> CVSS -> Text
cvssShow ordered cvss = case cvssVersion cvss of
  CVSS31 -> Text.intercalate "/" ("CVSS:3.1" : components)
  CVSS30 -> Text.intercalate "/" ("CVSS:3.0" : components)
  CVSS20 -> Text.intercalate "/" ("CVSS:2.0" : components)
  where
    components = map toComponent (cvssOrder (cvssMetrics cvss))
    toComponent :: Metric -> Text
    toComponent (Metric (MetricShortName name) (MetricValueChar value)) = Text.snoc (name <> ":") value
    cvssOrder metrics
      | ordered = mapMaybe getMetric (allMetrics (cvssDB (cvssVersion cvss)))
      | otherwise = metrics
      where
        getMetric mi = find (\metric -> miShortName mi == mName metric) metrics

newtype CVSSDB = CVSSDB [MetricGroup]

cvssDB :: CVSSVersion -> CVSSDB
cvssDB v = case v of
  CVSS31 -> cvss31
  CVSS30 -> cvss30
  CVSS20 -> cvss20

-- | Description of a metric group.
data MetricGroup = MetricGroup
  { mgName :: Text,
    mgMetrics :: [MetricInfo]
  }

-- | Description of a single metric.
data MetricInfo = MetricInfo
  { miName :: Text,
    miShortName :: MetricShortName,
    miRequired :: Bool,
    miValues :: [MetricValue]
  }

-- | Description of a single metric value
data MetricValue = MetricValue
  { mvName :: Text,
    mvChar :: MetricValueChar,
    mvNum :: Float,
    mvNumChangedScope :: Maybe Float,
    mvDesc :: Text
  }

-- | CVSS3.1 metrics pulled from section 2. "Base Metrics" and section section 7.4. "Metric Values"
cvss31 :: CVSSDB
cvss31 =
  CVSSDB
    [ MetricGroup "Base" baseMetrics,
      MetricGroup "Temporal" temporalMetrics,
      MetricGroup "Environmental" environmentalMetrics
    ]
  where
    baseMetrics =
      [ MetricInfo
          "Attack Vector"
          "AV"
          True
          [ MetricValue "Network" (C 'N') 0.85 Nothing "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet.",
            MetricValue "Adjacent" (C 'A') 0.62 Nothing "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.",
            MetricValue "Local" (C 'L') 0.55 Nothing "The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities.",
            MetricValue "Physical" (C 'P') 0.2 Nothing "The attack requires the attacker to physically touch or manipulate the vulnerable component."
          ],
        MetricInfo
          "Attack Complexity"
          "AC"
          True
          [ MetricValue "Low" (C 'L') 0.77 Nothing "Specialized access conditions or extenuating circumstances do not exist.",
            MetricValue "High" (C 'H') 0.44 Nothing "A successful attack depends on conditions beyond the attacker's control."
          ],
        MetricInfo
          "Privileges Required"
          "PR"
          True
          [ MetricValue "None" (C 'N') 0.85 Nothing "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.",
            MetricValue "Low" (C 'L') 0.62 (Just 0.68) "The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user.",
            MetricValue "High" (C 'H') 0.27 (Just 0.5) "The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
          ],
        MetricInfo
          "User Interaction"
          "UI"
          True
          [ MetricValue "None" (C 'N') 0.85 Nothing "The vulnerable system can be exploited without interaction from any user.",
            MetricValue "Required" (C 'R') 0.62 Nothing "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited."
          ],
        MetricInfo
          "Scope"
          "S"
          True
          [ -- Note: not defined as contants in specification
            MetricValue "Unchanged" (C 'U') Unchanged Nothing "An exploited vulnerability can only affect resources managed by the same security authority.",
            MetricValue "Changed" (C 'C') Changed Nothing "An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component."
          ],
        MetricInfo
          "Confidentiality Impact"
          "C"
          True
          [ mkHigh "There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker.",
            mkLow "There is some loss of confidentiality.",
            mkNone "There is no loss of confidentiality within the impacted component."
          ],
        MetricInfo
          "Integrity Impact"
          "I"
          True
          [ mkHigh "There is a total loss of integrity, or a complete loss of protection.",
            mkLow "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited.",
            mkNone "There is no loss of integrity within the impacted component."
          ],
        MetricInfo
          "Availability Impact"
          "A"
          True
          [ mkHigh "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component",
            mkLow "Performance is reduced or there are interruptions in resource availability.",
            mkNone "There is no impact to availability within the impacted component."
          ]
      ]
    mkHigh = MetricValue "High" (C 'H') 0.56 Nothing
    mkLow = MetricValue "Low" (C 'L') 0.22 Nothing
    mkNone = MetricValue "None" (C 'N') 0 Nothing
    -- TODOs
    temporalMetrics = []
    environmentalMetrics = []

pattern C :: Char -> MetricValueChar
pattern C c = MetricValueChar c

pattern Unchanged :: Float
pattern Unchanged = 6.42

pattern Changed :: Float
pattern Changed = 7.52

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

allMetrics :: CVSSDB -> [MetricInfo]
allMetrics (CVSSDB db) = concatMap mgMetrics db

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
    gm = getMetricValue cvss31 metrics scope

getMetricValue :: CVSSDB -> [Metric] -> Float -> Text -> Float
getMetricValue db metrics scope name = case mValue of
  Nothing -> error $ "The impossible have happened, unknown metric: " <> Text.unpack name
  Just v -> v
  where
    mValue = do
      mi <- find (\mi -> miName mi == name) (allMetrics db)
      Metric _ valueChar <- find (\metric -> miShortName mi == mName metric) metrics
      mv <- find (\mv -> mvChar mv == valueChar) (miValues mi)
      pure $ case mvNumChangedScope mv of
        Just value | scope /= Unchanged -> value
        _ -> mvNum mv

validateCvss31 :: [Metric] -> Either CVSSError [Metric]
validateCvss31 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss31, validateRequired cvss31]
  pure metrics

cvss30 :: CVSSDB
cvss30 =
  CVSSDB
    [ MetricGroup "Base" baseMetrics
    ]
  where
    baseMetrics =
      [ MetricInfo
          "Attack Vector"
          "AV"
          True
          [ MetricValue "Network" (C 'N') 0.85 Nothing "A vulnerability exploitable with network access means the vulnerable component is bound to the network stack and the attacker's path is through OSI layer 3 (the network layer).",
            MetricValue "Adjacent" (C 'A') 0.62 Nothing "A vulnerability exploitable with adjacent network access means the vulnerable component is bound to the network stack",
            MetricValue "Local" (C 'L') 0.55 Nothing "A vulnerability exploitable with Local access means that the vulnerable component is not bound to the network stack, and the attacker's path is via read/write/execute capabilities.",
            MetricValue "Physical" (C 'P') 0.2 Nothing "A vulnerability exploitable with Physical access requires the attacker to physically touch or manipulate the vulnerable component."
          ],
        MetricInfo
          "Attack Complexity"
          "AC"
          True
          [ MetricValue "Low" (C 'L') 0.77 Nothing "Specialized access conditions or extenuating circumstances do not exist.",
            MetricValue "High" (C 'H') 0.44 Nothing "A successful attack depends on conditions beyond the attacker's control."
          ],
        MetricInfo
          "Privileges Required"
          "PR"
          True
          [ MetricValue "None" (C 'N') 0.85 Nothing "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.",
            MetricValue "Low" (C 'L') 0.62 (Just 0.68) "The attacker is authorized with (i.e. requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user.",
            MetricValue "High" (C 'H') 0.27 (Just 0.5) "The attacker is authorized with (i.e. requires) privileges that provide significant (e.g. administrative) control over the vulnerable component that could affect component-wide settings and files."
          ],
        MetricInfo
          "User Interaction"
          "UI"
          True
          [ MetricValue "None" (C 'N') 0.85 Nothing "The vulnerable system can be exploited without interaction from any user.",
            MetricValue "Required" (C 'R') 0.62 Nothing "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited."
          ],
        MetricInfo
          "Scope"
          "S"
          True
          [ MetricValue "Unchanged" (C 'U') Unchanged Nothing "An exploited vulnerability can only affect resources managed by the same authority.",
            MetricValue "Changed" (C 'C') Changed Nothing "An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable component."
          ],
        MetricInfo
          "Confidentiality Impact"
          "C"
          True
          [ mkHigh "There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker.",
            mkLow "There is some loss of confidentiality.",
            mkNone "There is no loss of confidentiality within the impacted component."
          ],
        MetricInfo
          "Integrity Impact"
          "I"
          True
          [ mkHigh "There is a total loss of integrity, or a complete loss of protection.",
            mkLow "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited.",
            mkNone "There is no loss of integrity within the impacted component."
          ],
        MetricInfo
          "Availability Impact"
          "A"
          True
          [ mkHigh "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component",
            mkLow "Performance is reduced or there are interruptions in resource availability.",
            mkNone "There is no impact to availability within the impacted component."
          ]
      ]
    mkHigh = MetricValue "High" (C 'H') 0.56 Nothing
    mkLow = MetricValue "Low" (C 'L') 0.22 Nothing
    mkNone = MetricValue "None" (C 'N') 0 Nothing

-- | Implementation of Section 8.1 "Base"
cvss30score :: [Metric] -> (Rating, Float)
cvss30score metrics = (toRating score, score)
  where
    score
      | impact <= 0 = 0
      | scope == Unchanged = roundup (min (impact + exploitability) 10)
      | otherwise = roundup (min (1.08 * (impact + exploitability)) 10)
    impact
      | scope == Unchanged = scope * iscBase
      | otherwise = scope * (iscBase - 0.029) - 3.25 * powerFloat (iscBase - 0.02) 15
    iscBase = 1 - (1 - gm "Confidentiality Impact") * (1 - gm "Integrity Impact") * (1 - gm "Availability Impact")
    scope = gm "Scope"

    exploitability = 8.22 * gm "Attack Vector" * gm "Attack Complexity" * gm "Privileges Required" * gm "User Interaction"
    gm = getMetricValue cvss30 metrics scope

validateCvss30 :: [Metric] -> Either CVSSError [Metric]
validateCvss30 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss30, validateRequired cvss30]
  pure metrics

cvss20 :: CVSSDB
cvss20 =
  CVSSDB
    [ MetricGroup "Base" baseMetrics
    ]
  where
    baseMetrics =
      [ MetricInfo
          "Access Vector"
          "AV"
          True
          [ MetricValue "Local" (C 'L') 0.395 Nothing "A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account.",
            MetricValue "Adjacent Network" (C 'A') 0.646 Nothing "A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software.",
            MetricValue "Network" (C 'N') 1.0 Nothing "A vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access."
          ],
        MetricInfo
          "Access Complexity"
          "AC"
          True
          [ MetricValue "High" (C 'H') 0.35 Nothing "Specialized access conditions exist.",
            MetricValue "Medium" (C 'M') 0.61 Nothing "The access conditions are somewhat specialized.",
            MetricValue "Low" (C 'L') 0.71 Nothing "Specialized access conditions or extenuating circumstances do not exist."
          ],
        MetricInfo
          "Authentication"
          "Au"
          True
          [ MetricValue "Multiple" (C 'M') 0.45 Nothing "Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time.",
            MetricValue "Single" (C 'S') 0.56 Nothing "The vulnerability requires an attacker to be logged into the system (such as at a command line or via a desktop session or web interface).",
            MetricValue "None" (C 'N') 0.704 Nothing "Authentication is not required to exploit the vulnerability."
          ],
        MetricInfo
          "Confidentiality Impact"
          "C"
          True
          [ mkNone "There is no impact to the confidentiality of the system.",
            mkPartial "There is considerable informational disclosure.",
            mkComplete "There is total information disclosure, resulting in all system files being revealed."
          ],
        MetricInfo
          "Integrity Impact"
          "I"
          True
          [ mkNone "There is no impact to the integrity of the system.",
            mkPartial "Modification of some system files or information is possible, but the attacker does not have control over what can be modified, or the scope of what the attacker can affect is limited.",
            mkComplete "There is a total compromise of system integrity."
          ],
        MetricInfo
          "Availability Impact"
          "A"
          True
          [ mkNone "There is no impact to the availability of the system.",
            mkPartial "There is reduced performance or interruptions in resource availability.",
            mkComplete "There is a total shutdown of the affected resource."
          ]
      ]
    mkNone = MetricValue "None" (C 'N') 0 Nothing
    mkPartial = MetricValue "Partial" (C 'P') 0.275 Nothing
    mkComplete = MetricValue "Complete" (C 'C') 0.660 Nothing

validateCvss20 :: [Metric] -> Either CVSSError [Metric]
validateCvss20 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss20, validateRequired cvss20]
  pure metrics

-- | Implementation of section 3.2.1. "Base Equation"
cvss20score :: [Metric] -> (Rating, Float)
cvss20score metrics = (toRating score, score)
  where
    score = round_to_1_decimal ((0.6 * impact + 0.4 * exploitability - 1.5) * fImpact)
    impact = 10.41 * (1 - (1 - gm "Confidentiality Impact") * (1 - gm "Integrity Impact") * (1 - gm "Availability Impact"))
    exploitability = 20 * gm "Access Vector" * gm "Access Complexity" * gm "Authentication"
    fImpact
      | impact == 0 = 0
      | otherwise = 1.176

    round_to_1_decimal :: Float -> Float
    round_to_1_decimal x = fromIntegral @Int (round (x * 10)) / 10

    gm :: Text -> Float
    gm = getMetricValue cvss20 metrics 0

-- | Check for duplicates metric
--
-- >>> validateUnique [("AV", (C 'N')), ("AC", (C 'L')), ("AV", (C 'L'))]
-- Left "Duplicated \"AV\""
validateUnique :: [Metric] -> Either CVSSError ()
validateUnique = traverse_ checkDouble . group . sort . map mName
  where
    checkDouble [] = error "The impossible have happened"
    checkDouble [_] = pure ()
    checkDouble (MetricShortName n : _) = Left (DuplicateMetric n)

-- | Check for unknown metric
--
-- >>> validateKnown [("AV", (C 'M'))]
-- Left "Unknown value: (C 'M')"
--
-- >>> validateKnown [("AW", (C 'L'))]
-- Left "Unknown metric: \"AW\""
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

-- | Check for required metric
--
-- >>> validateRequired []
-- Left "Missing \"Attack Vector\""
validateRequired :: CVSSDB -> [Metric] -> Either CVSSError ()
validateRequired db metrics = traverse_ checkRequired (allMetrics db)
  where
    checkRequired mi
      | miRequired mi,
        Nothing <- find (\metric -> miShortName mi == mName metric) metrics =
          Left (MissingRequiredMetric (miName mi))
      | otherwise = pure ()
