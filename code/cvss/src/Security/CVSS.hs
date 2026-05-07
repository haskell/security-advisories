{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}

-- | This module provides a CVSS parser and utility functions
-- adapted from https://www.first.org/cvss/v3.1/specification-document
module Security.CVSS
  ( -- * Type
    CVSS (..),
    CVSSVersion (..),
    Rating (..),

    -- * Parser
    parseCVSS,
    CVSSError (..),

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
    cvssInfo,
    toRating20,
  )
where

import Data.Coerce (coerce)
import Data.Foldable (traverse_)
import Data.List (find, group, sort)
import Data.Map qualified as Map
import Data.Maybe (catMaybes, fromMaybe, mapMaybe)
import Data.String (IsString)
import Data.Text (Text)
import Data.Text qualified as Text
import GHC.Float (powerFloat)

-- | The CVSS version.
data CVSSVersion
  = -- | Version 4.0: https://www.first.org/cvss/v4.0/
    CVSS40
  | -- | Version 3.1: https://www.first.org/cvss/v3-1/
    CVSS31
  | -- | Version 3.0: https://www.first.org/cvss/v3.0/
    CVSS30
  | -- | Version 2.0: https://www.first.org/cvss/v2/
    CVSS20
  deriving (Eq, Show)

-- | Parsed CVSS string obtained with 'parseCVSS'.
data CVSS = CVSS
  { -- | The CVSS Version.
    cvssVersion :: CVSSVersion,
    -- | The metrics are stored as provided by the user
    cvssMetrics :: [Metric]
  }
  deriving stock (Eq)

instance Show CVSS where
  show = Text.unpack . cvssVectorString

-- | CVSS Rating obtained with 'cvssScore'
data Rating = None | Low | Medium | High | Critical
  deriving (Enum, Eq, Ord, Show)

-- CVSS 4.0 Data Types

-- | Equivalence class level for CVSS 4.0 MacroVector
data EQLevel = EQ0 | EQ1 | EQ2
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | MacroVector for CVSS 4.0 scoring (EQ1-EQ6)
data MacroVector = MacroVector
  { mvEQ1 :: EQLevel,
    mvEQ2 :: EQLevel,
    mvEQ3 :: EQLevel,
    mvEQ4 :: EQLevel,
    mvEQ5 :: EQLevel,
    mvEQ6 :: EQLevel
  }
  deriving (Eq, Ord, Show)

-- | Severity level (float wrapped for type safety)
newtype Severity = Severity Float
  deriving newtype (Eq, Ord, Num, Fractional, Real, RealFrac)

instance Show Severity where
  show (Severity f) = show f

-- | Result of computing EQ1 (AV/PR/UI)
data EQ1Result = EQ1Result
  { eq1Level :: EQLevel,
    eq1AV :: Severity,
    eq1PR :: Severity,
    eq1UI :: Severity
  }
  deriving (Eq, Show)

-- | Result of computing EQ2 (AC/AT)
data EQ2Result = EQ2Result
  { eq2Level :: EQLevel,
    eq2AC :: Severity,
    eq2AT :: Severity
  }
  deriving (Eq, Show)

-- | Result of computing EQ3 (VC/VI/VA)
data EQ3Result = EQ3Result
  { eq3Level :: EQLevel,
    eq3VC :: Severity,
    eq3VI :: Severity,
    eq3VA :: Severity
  }
  deriving (Eq, Show)

-- | Result of computing EQ4 (SC/SI/SA)
data EQ4Result = EQ4Result
  { eq4Level :: EQLevel,
    eq4SC :: Severity,
    eq4SI :: Severity,
    eq4SA :: Severity
  }
  deriving (Eq, Show)

-- | Result of computing EQ5 (E - Exploit Maturity)
data EQ5Result = EQ5Result
  { eq5Level :: EQLevel,
    eq5E :: Severity
  }
  deriving (Eq, Show)

-- | Result of computing EQ6 (CR/IR/AR)
data EQ6Result = EQ6Result
  { eq6Level :: EQLevel,
    eq6CR :: Severity,
    eq6IR :: Severity,
    eq6AR :: Severity
  }
  deriving (Eq, Show)

-- | Maximum severity levels for interpolation
data MaxSeverities = MaxSeverities
  { msAV :: Severity,
    msPR :: Severity,
    msUI :: Severity,
    msAC :: Severity,
    msAT :: Severity,
    msVC :: Severity,
    msVI :: Severity,
    msVA :: Severity,
    msSC :: Severity,
    msSI :: Severity,
    msSA :: Severity,
    msE :: Severity,
    msCR :: Severity,
    msIR :: Severity,
    msAR :: Severity
  }
  deriving (Eq, Show)

-- | Available distances for interpolation
data AvailableDistances = AvailableDistances
  { adEQ1 :: Maybe Float,
    adEQ2 :: Maybe Float,
    adEQ3 :: Maybe Float,
    adEQ4 :: Maybe Float,
    adEQ5 :: Maybe Float
  }
  deriving (Eq, Show)

-- | Severity groups for interpolation
data SeverityGroups = SeverityGroups
  { sgEQ1 :: [Severity],
    sgEQ2 :: [Severity],
    sgEQ3 :: [Severity],
    sgEQ4 :: [Severity],
    sgEQ5 :: [Severity]
  }
  deriving (Eq, Show)

-- End CVSS 4.0 Data Types

-- | Implementation of Section 5. "Qualitative Severity Rating Scale"
toRating :: Float -> Rating
toRating score
  | score <= 0 = None
  | score < 4 = Low
  | score < 7 = Medium
  | score < 9 = High
  | otherwise = Critical

-- | CVSS v2.0 Qualitative Severity Rating Scale (Section 5)
-- v2 uses different bands: Low (0.0-3.9), Medium (4.0-6.9), High (7.0-10.0)
toRating20 :: Float -> Rating
toRating20 score
  | score <= 0 = None
  | score < 4 = Low
  | score < 7 = Medium
  | otherwise = High

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

newtype MetricShortName = MetricShortName Text
  deriving newtype (Eq, IsString, Ord, Show)

newtype MetricValueChar = MetricValueChar Text
  deriving newtype (Eq, IsString, Ord, Show)

data Metric = Metric
  { mName :: MetricShortName,
    mChar :: MetricValueChar
  }
  deriving (Eq, Show)

-- example CVSS string: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N

-- | Parse a CVSS string.
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
      validator metrics

    components withPrefix = (if withPrefix then drop 1 else id) $ Text.split (== '/') txt
    splitComponent :: Text -> Either CVSSError Metric
    splitComponent componentTxt = case Text.breakOnEnd ":" componentTxt of
      ("", _) -> Left EmptyComponent
      (_, "") -> Left (MissingValue componentTxt)
      (nameWithColon, valueText) ->
        let name = Text.init nameWithColon
         in Right (Metric (MetricShortName name) (MetricValueChar valueText))

-- | Compute the base score.
cvssScore :: CVSS -> (Rating, Float)
cvssScore cvss = case cvssVersion cvss of
  CVSS40 -> cvss40score (cvssMetrics cvss)
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

newtype CVSSDB = CVSSDB [MetricGroup]

cvssDB :: CVSSVersion -> CVSSDB
cvssDB v = case v of
  CVSS40 -> cvss40
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
          avValues,
        MetricInfo
          "Attack Complexity"
          "AC"
          True
          acValues,
        MetricInfo
          "Privileges Required"
          "PR"
          True
          prValues,
        MetricInfo
          "User Interaction"
          "UI"
          True
          uiValues,
        MetricInfo
          "Scope"
          "S"
          True
          sValues,
        MetricInfo
          "Confidentiality Impact"
          "C"
          True
          cValues,
        MetricInfo
          "Integrity Impact"
          "I"
          True
          iValues,
        MetricInfo
          "Availability Impact"
          "A"
          True
          aValues
      ]
    avValues =
      [ MetricValue "Network" (C "N") 0.85 Nothing "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet.",
        MetricValue "Adjacent" (C "A") 0.62 Nothing "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.",
        MetricValue "Local" (C "L") 0.55 Nothing "The vulnerable component is not bound to the network stack and the attacker's path is via read/write/execute capabilities.",
        MetricValue "Physical" (C "P") 0.2 Nothing "The attack requires the attacker to physically touch or manipulate the vulnerable component."
      ]
    acValues =
      [ MetricValue "Low" (C "L") 0.77 Nothing "Specialized access conditions or extenuating circumstances do not exist.",
        MetricValue "High" (C "H") 0.44 Nothing "A successful attack depends on conditions beyond the attacker's control."
      ]
    prValues =
      [ MetricValue "None" (C "N") 0.85 Nothing "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.",
        MetricValue "Low" (C "L") 0.62 (Just 0.68) "The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user.",
        MetricValue "High" (C "H") 0.27 (Just 0.5) "The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
      ]
    uiValues =
      [ MetricValue "None" (C "N") 0.85 Nothing "The vulnerable system can be exploited without interaction from any user.",
        MetricValue "Required" (C "R") 0.62 Nothing "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited."
      ]
    sValues =
      [ MetricValue "Unchanged" (C "U") Unchanged Nothing "An exploited vulnerability can only affect resources managed by the same security authority.",
        MetricValue "Changed" (C "C") Changed Nothing "An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component."
      ]
    cValues =
      [ mkHigh "There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker.",
        mkLow "There is some loss of confidentiality.",
        mkNone "There is no loss of confidentiality within the impacted component."
      ]
    iValues =
      [ mkHigh "There is a total loss of integrity, or a complete loss of protection.",
        mkLow "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited.",
        mkNone "There is no loss of integrity within the impacted component."
      ]
    aValues =
      [ mkHigh "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component",
        mkLow "Performance is reduced or there are interruptions in resource availability.",
        mkNone "There is no impact to availability within the impacted component."
      ]
    mkHigh = MetricValue "High" (C "H") 0.56 Nothing
    mkLow = MetricValue "Low" (C "L") 0.22 Nothing
    mkNone = MetricValue "None" (C "N") 0 Nothing
    temporalMetrics =
      [ MetricInfo
          "Exploit Code Maturity"
          "E"
          False
          [ mkTemporalUndef "High",
            MetricValue "High" (C "H") 1 Nothing "Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available. Exploit code works in every situation, or is actively being delivered via an autonomous agent (such as a worm or virus). Network-connected systems are likely to encounter scanning or exploitation attempts. Exploit development has reached the level of reliable, widely available, easy-to-use automated tools.",
            MetricValue "Functional" (C "F") 0.97 Nothing "Functional exploit code is available. The code works in most situations where the vulnerability exists.",
            MetricValue "Proof of Concept" (C "P") 0.94 Nothing "Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.",
            MetricValue "Unproven" (C "U") 0.91 Nothing "No exploit code is available, or an exploit is theoretical."
          ],
        MetricInfo
          "Remediation Level"
          "RL"
          False
          [ mkTemporalUndef "Unavailable",
            MetricValue "Unavailable" (C "U") 1 Nothing "There is either no solution available or it is impossible to apply.",
            MetricValue "Workaround" (C "W") 0.97 Nothing "There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.",
            MetricValue "Temporary Fix" (C "T") 0.96 Nothing "There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.",
            MetricValue "Official Fix" (C "O") 0.95 Nothing "A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available."
          ],
        MetricInfo
          "Report Confidence"
          "RC"
          False
          [ mkTemporalUndef "Confirmed",
            MetricValue "Confirmed" (C "C") 1 Nothing "Detailed reports exist, or functional reproduction is possible (functional exploits may provide this). Source code is available to independently verify the assertions of the research, or the author or vendor of the affected code has confirmed the presence of the vulnerability.",
            MetricValue "Reasonable" (C "R") 0.96 Nothing "Significant details are published, but researchers either do not have full confidence in the root cause, or do not have access to source code to fully confirm all of the interactions that may lead to the result. Reasonable confidence exists, however, that the bug is reproducible and at least one impact is able to be verified (proof-of-concept exploits may provide this). An example is a detailed write-up of research into a vulnerability with an explanation (possibly obfuscated or \"left as an exercise to the reader\") that gives assurances on how to reproduce the results.",
            MetricValue "Unknown" (C "U") 0.92 Nothing "There are reports of impacts that indicate a vulnerability is present. The reports indicate that the cause of the vulnerability is unknown, or reports may differ on the cause or impacts of the vulnerability. Reporters are uncertain of the true nature of the vulnerability, and there is little confidence in the validity of the reports or whether a static Base Score can be applied given the differences described. An example is a bug report which notes that an intermittent but non-reproducible crash occurs, with evidence of memory corruption suggesting that denial of service, or possible more serious impacts, may result."
          ]
      ]
    mkTemporalUndef m = MetricValue "Not Defined" (C "X") 1 Nothing $ mkTemporalUndefMsg m
    mkTemporalUndefMsg m = "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning " <> m <> "."
    environmentalMetrics =
      [ MetricInfo
          "Confidentiality Requirement"
          "CR"
          False
          [ mkEnvUndef,
            mkEnvHigh "Confidentiality",
            mkEnvMedium "Confidentiality",
            mkEnvLow "Confidentiality"
          ],
        MetricInfo
          "Integrity Requirement"
          "IR"
          False
          [ mkEnvUndef,
            mkEnvHigh "Integrity",
            mkEnvMedium "Integrity",
            mkEnvLow "Integrity"
          ],
        MetricInfo
          "Availability Requirement"
          "AR"
          False
          [ mkEnvUndef,
            mkEnvHigh "Availability",
            mkEnvMedium "Availability",
            mkEnvLow "Availability"
          ],
        -- Modified Base Metric - the same values as the corresponding Base Metric as well as Not Defined (the default).
        MetricInfo "Modified Attack Vector" "MAV" False $ mkModifiedUndef : avValues,
        MetricInfo "Modified Attack Complexity" "MAC" False $ mkModifiedUndef : acValues,
        MetricInfo "Modified Privileges Required" "MPR" False $ mkModifiedUndef : prValues,
        MetricInfo "Modified User Interaction" "MUI" False $ mkModifiedUndef : uiValues,
        MetricInfo "Modified Scope" "MS" False $ mkModifiedUndef : sValues,
        MetricInfo "Modified Confidentiality" "MC" False $ mkModifiedUndef : cValues,
        MetricInfo "Modified Integrity" "MI" False $ mkModifiedUndef : iValues,
        MetricInfo "Modified Availability" "MA" False $ mkModifiedUndef : aValues
      ]
    mkEnvUndef = MetricValue "Not Defined" (C "X") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium."
    mkEnvHighMsg m = "Loss of " <> m <> " is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
    mkEnvHigh m = MetricValue "High" (C "H") 1.5 Nothing $ mkEnvHighMsg m
    mkEnvMediumMsg m = "Loss of " <> m <> " is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
    mkEnvMedium m = MetricValue "Medium" (C "M") 1 Nothing $ mkEnvMediumMsg m
    mkEnvLowMsg m = "Loss of " <> m <> " is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
    mkEnvLow m = MetricValue "Low" (C "L") 0.5 Nothing $ mkEnvLowMsg m
    mkModifiedUndef = MetricValue "Not Defined" (C "X") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Score" -- Not Defined (X): mvNum is ignored in scoring; getModifiedMetricValue substitutes the base metric value

pattern C :: Text -> MetricValueChar
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

cvss31score :: [Metric] -> (Rating, Float)
cvss31score metrics
  | hasEnvironmentalMetrics metrics = cvss31EnvironmentalScore metrics
  | hasTemporalMetrics metrics = cvss31TemporalScore metrics
  | otherwise = cvss31BaseScore metrics

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

hasEnvironmentalMetrics20 :: [Metric] -> Bool
hasEnvironmentalMetrics20 = any (\metric -> mName metric `elem` ["CDP", "TD", "CR", "IR", "AR"])

-- | Implementation of section 7.1. Base Metrics Equations
cvss31BaseScore :: [Metric] -> (Rating, Float)
cvss31BaseScore metrics = (toRating score, score)
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

cvss31TemporalScore :: [Metric] -> (Rating, Float)
cvss31TemporalScore metrics = (toRating score, score)
  where
    (_, baseScore) = cvss31BaseScore metrics
    exploitCodeMaturity = optionalMetric metrics 1.0 "Exploit Code Maturity"
    remediationLevel = optionalMetric metrics 1.0 "Remediation Level"
    reportConfidence = optionalMetric metrics 1.0 "Report Confidence"
    score = roundup (baseScore * exploitCodeMaturity * remediationLevel * reportConfidence)

-- | Implementation of section 7.3. Environmental Metrics Equations
cvss31EnvironmentalScore :: [Metric] -> (Rating, Float)
cvss31EnvironmentalScore metrics = (toRating score, score)
  where
    {- MISS = Minimum (
      1 - [(1 - ConfidentialityRequirement × ModifiedConfidentiality)
           × (1 - IntegrityRequirement × ModifiedIntegrity)
           × (1 - AvailabilityRequirement × ModifiedAvailability) ], 0.915)
    -}
    miss =
      min
        ( 1
            - (1 - confidentialityRequirement * modifiedConfidentiality)
              * (1 - integrityRequirement * modifiedIntegrity)
              * (1 - availabilityRequirement * modifiedAvailability)
        )
        0.915
    {-
    ModifiedImpact =
    If ModifiedScope is Unchanged 6.42 × MISS
    If ModifiedScope is Changed   7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)^13
    -}
    modifiedImpact
      | modifiedScope == Unchanged = 6.42 * miss
      | otherwise = 7.52 * (miss - 0.029) - 3.25 * powerFloat (miss * 0.9731 - 0.02) 13

    {-
      ModifiedExploitability = 8.22 × ModifiedAttackVector × ModifiedAttackComplexity
        × ModifiedPrivilegesRequired × ModifiedUserInteraction
    -}
    modifiedExploitability =
      8.22
        * modifiedAttackVector
        * modifiedAttackComplexity
        * modifiedPrivilegesRequired
        * modifiedUserInteraction

    {-
    EnvironmentalScore =
    If ModifiedImpact \<= 0   0, else
    If ModifiedScope is Unchanged
       Roundup ( Roundup [Minimum ([ModifiedImpact + ModifiedExploitability], 10) ]
           × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
    If ModifiedScope is Changed
    	Roundup ( Roundup [Minimum (1.08 × [ModifiedImpact + ModifiedExploitability], 10) ]
    	   × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
    -}
    envScoreHelper
      | modifiedImpact <= 0 = 0
      | modifiedScope == Unchanged =
          roundup (min (modifiedImpact + modifiedExploitability) 10)
      | otherwise =
          roundup (min (1.08 * (modifiedImpact + modifiedExploitability)) 10)

    score
      | modifiedImpact <= 0 = 0
      | otherwise =
          roundup
            ( envScoreHelper
                * exploitCodeMaturity
                * remediationLevel
                * reportConfidence
            )

    exploitCodeMaturity = optionalMetric metrics 1.0 "Exploit Code Maturity"
    remediationLevel = optionalMetric metrics 1.0 "Remediation Level"
    reportConfidence = optionalMetric metrics 1.0 "Report Confidence"
    confidentialityRequirement = optionalMetric metrics 1.0 "Confidentiality Requirement"
    integrityRequirement = optionalMetric metrics 1.0 "Integrity Requirement"
    availabilityRequirement = optionalMetric metrics 1.0 "Availability Requirement"
    modifiedAttackVector = getModifiedMetricValue cvss31 metrics "Modified Attack Vector" "Attack Vector" modifiedScope
    modifiedAttackComplexity = getModifiedMetricValue cvss31 metrics "Modified Attack Complexity" "Attack Complexity" modifiedScope
    modifiedPrivilegesRequired = getModifiedMetricValue cvss31 metrics "Modified Privileges Required" "Privileges Required" modifiedScope
    modifiedUserInteraction = getModifiedMetricValue cvss31 metrics "Modified User Interaction" "User Interaction" modifiedScope
    modifiedScope = getModifiedMetricValue cvss31 metrics "Modified Scope" "Scope" Unchanged
    modifiedConfidentiality = getModifiedMetricValue cvss31 metrics "Modified Confidentiality" "Confidentiality Impact" modifiedScope
    modifiedIntegrity = getModifiedMetricValue cvss31 metrics "Modified Integrity" "Integrity Impact" modifiedScope
    modifiedAvailability = getModifiedMetricValue cvss31 metrics "Modified Availability" "Availability Impact" modifiedScope

    {- Missing or X modified metrics fall back to the corresponding base metric
    MAV:X  => use AV
    MAC:X  => use AC
    MPR:X  => use PR
    MUI:X  => use UI
    MS:X   => use S
    MC:X   => use C
    MI:X   => use I
    MA:X   => use A
    -}
    getModifiedMetricValue :: CVSSDB -> [Metric] -> Text -> Text -> Float -> Float
    getModifiedMetricValue db ms modifiedName baseName scope =
      case lookupMetricValueChar db ms modifiedName of
        Just (C "X") -> getMetricValue db ms scope baseName
        Just _ -> getMetricValue db ms scope modifiedName
        Nothing -> getMetricValue db ms scope baseName

optionalMetric :: [Metric] -> Float -> Text -> Float
optionalMetric metrics defaultValue =
  getMetricValueOr cvss31 metrics defaultValue Unchanged

-- e.g. for "Attack Vector" lookup MetricInfo "Attack Vector" "AV" True avValues
lookupMetricInfo :: CVSSDB -> Text -> Maybe MetricInfo
lookupMetricInfo db name =
  find (\mi -> miName mi == name) (allMetrics db)

-- what char value the parsed vector have e.g. in AV:N, for "Attack Vector" returns Just (C 'N').
lookupMetricValueChar :: CVSSDB -> [Metric] -> Text -> Maybe MetricValueChar
lookupMetricValueChar db metrics name = do
  mi <- lookupMetricInfo db name
  Metric _ valueChar <- find (\metric -> miShortName mi == mName metric) metrics
  pure valueChar

-- strict lookup for required base metrics
getMetricValue :: CVSSDB -> [Metric] -> Float -> Text -> Float
getMetricValue db metrics scope name = case lookupMetricValue db metrics scope name of
  Nothing -> error $ "The impossible have happened, unknown metric: " <> Text.unpack name
  Just value -> value

-- Converts the parsed value char into a numeric CVSS value. Example: AV:N -> 0.85, RL:O -> 0.95
lookupMetricValue :: CVSSDB -> [Metric] -> Float -> Text -> Maybe Float
lookupMetricValue db metrics scope name = do
  mi <- lookupMetricInfo db name
  valueChar <- lookupMetricValueChar db metrics name
  mv <- find (\mv -> mvChar mv == valueChar) (miValues mi)
  pure $ case mvNumChangedScope mv of
    Just value | scope /= Unchanged -> value
    _ -> mvNum mv

-- lookup for optional temporal/environmental metrics
getMetricValueOr :: CVSSDB -> [Metric] -> Float -> Float -> Text -> Float
getMetricValueOr db metrics defaultValue scope name = case lookupMetricValue db metrics scope name of
  Nothing -> defaultValue
  Just value -> value

validateCvss31 :: [Metric] -> Either CVSSError [Metric]
validateCvss31 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss31, validateRequired cvss31]
  pure metrics

cvss30 :: CVSSDB
cvss30 =
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
          avValues,
        MetricInfo
          "Attack Complexity"
          "AC"
          True
          acValues,
        MetricInfo
          "Privileges Required"
          "PR"
          True
          prValues,
        MetricInfo
          "User Interaction"
          "UI"
          True
          uiValues,
        MetricInfo
          "Scope"
          "S"
          True
          sValues,
        MetricInfo
          "Confidentiality Impact"
          "C"
          True
          cValues,
        MetricInfo
          "Integrity Impact"
          "I"
          True
          iValues,
        MetricInfo
          "Availability Impact"
          "A"
          True
          aValues
      ]
    avValues =
      [ MetricValue "Network" (C "N") 0.85 Nothing "A vulnerability exploitable with network access means that the vulnerable component is bound to the network stack and the attacker's path is through OSI layer 3 (the network layer).",
        MetricValue "Adjacent" (C "A") 0.62 Nothing "A vulnerability exploitable with adjacent network access means that the vulnerable component is bound to the network stack",
        MetricValue "Local" (C "L") 0.55 Nothing "A vulnerability exploitable with Local access means that the vulnerable component is not bound to the network stack, and the attacker's path is via read/write/execute capabilities.",
        MetricValue "Physical" (C "P") 0.2 Nothing "A vulnerability exploitable with Physical access requires the attacker to physically touch or manipulate the vulnerable component."
      ]
    acValues =
      [ MetricValue "Low" (C "L") 0.77 Nothing "Specialized access conditions or extenuating circumstances do not exist.",
        MetricValue "High" (C "H") 0.44 Nothing "A successful attack depends on conditions beyond the attacker's control."
      ]
    prValues =
      [ MetricValue "None" (C "N") 0.85 Nothing "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.",
        MetricValue "Low" (C "L") 0.62 (Just 0.68) "The attacker is authorized with (i.e. requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user.",
        MetricValue "High" (C "H") 0.27 (Just 0.5) "The attacker is authorized with (i.e. requires) privileges that provide significant (e.g., administrative) control over the vulnerable component that could affect component-wide settings and files."
      ]
    uiValues =
      [ MetricValue "None" (C "N") 0.85 Nothing "The vulnerable system can be exploited without interaction from any user.",
        MetricValue "Required" (C "R") 0.62 Nothing "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited."
      ]
    sValues =
      [ MetricValue "Unchanged" (C "U") Unchanged Nothing "An exploited vulnerability can only affect resources managed by the same authority.",
        MetricValue "Changed" (C "C") Changed Nothing "An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable component."
      ]
    cValues =
      [ mkHigh "There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker.",
        mkLow "There is some loss of confidentiality.",
        mkNone "There is no loss of confidentiality within the impacted component."
      ]
    iValues =
      [ mkHigh "There is a total loss of integrity, or a complete loss of protection.",
        mkLow "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited.",
        mkNone "There is no loss of integrity within the impacted component."
      ]
    aValues =
      [ mkHigh "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component",
        mkLow "Performance is reduced or there are interruptions in resource availability.",
        mkNone "There is no impact to availability within the impacted component."
      ]
    mkHigh = MetricValue "High" (C "H") 0.56 Nothing
    mkLow = MetricValue "Low" (C "L") 0.22 Nothing
    mkNone = MetricValue "None" (C "N") 0 Nothing
    temporalMetrics =
      [ MetricInfo
          "Exploit Code Maturity"
          "E"
          False
          [ mkTemporalUndef "High",
            MetricValue "High" (C "H") 1 Nothing "Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available. Exploit code works in every situation, or is actively being delivered via an autonomous agent (such as a worm or virus). Network-connected systems are likely to encounter scanning or exploitation attempts. Exploit development has reached the level of reliable, widely available, easy-to-use automated tools.",
            MetricValue "Functional" (C "F") 0.97 Nothing "Functional exploit code is available. The code works in most situations where the vulnerability exists.",
            MetricValue "Proof of Concept" (C "P") 0.94 Nothing "Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.",
            MetricValue "Unproven" (C "U") 0.91 Nothing "No exploit code is available, or an exploit is theoretical."
          ],
        MetricInfo
          "Remediation Level"
          "RL"
          False
          [ mkTemporalUndef "Unavailable",
            MetricValue "Unavailable" (C "U") 1 Nothing "There is either no solution available or it is impossible to apply.",
            MetricValue "Workaround" (C "W") 0.97 Nothing "There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.",
            MetricValue "Temporary Fix" (C "T") 0.96 Nothing "There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.",
            MetricValue "Official Fix" (C "O") 0.95 Nothing "A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available."
          ],
        MetricInfo
          "Report Confidence"
          "RC"
          False
          [ mkTemporalUndef "Confirmed",
            MetricValue "Confirmed" (C "C") 1 Nothing "Detailed reports exist, or functional reproduction is possible (functional exploits may provide this). Source code is available to independently verify the assertions of the research, or the author or vendor of the affected code has confirmed the presence of the vulnerability.",
            MetricValue "Reasonable" (C "R") 0.96 Nothing "Significant details are published, but researchers either do not have full confidence in the root cause, or do not have access to source code to fully confirm all of the interactions that may lead to the result. Reasonable confidence exists, however, that the bug is reproducible and at least one impact is able to be verified (proof-of-concept exploits may provide this). An example is a detailed write-up of research into a vulnerability with an explanation (possibly obfuscated or \"left as an exercise to the reader\") that gives assurances on how to reproduce the results.",
            MetricValue "Unknown" (C "U") 0.92 Nothing "There are reports of impacts that indicate a vulnerability is present. The reports indicate that the cause of the vulnerability is unknown, or reports may differ on the cause or impacts of the vulnerability. Reporters are uncertain of the true nature of the vulnerability, and there is little confidence in the validity of the reports or whether a static Base Score can be applied given the differences described. An example is a bug report which notes that an intermittent but non-reproducible crash occurs, with evidence of memory corruption suggesting that denial of service, or possible more serious impacts, may result."
          ]
      ]
    mkTemporalUndef m = MetricValue "Not Defined" (C "X") 1 Nothing $ mkTemporalUndefMsg m
    mkTemporalUndefMsg m = "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning " <> m <> "."
    environmentalMetrics =
      [ MetricInfo
          "Confidentiality Requirement"
          "CR"
          False
          [ mkEnvUndef,
            mkEnvHigh "Confidentiality",
            mkEnvMedium "Confidentiality",
            mkEnvLow "Confidentiality"
          ],
        MetricInfo
          "Integrity Requirement"
          "IR"
          False
          [ mkEnvUndef,
            mkEnvHigh "Integrity",
            mkEnvMedium "Integrity",
            mkEnvLow "Integrity"
          ],
        MetricInfo
          "Availability Requirement"
          "AR"
          False
          [ mkEnvUndef,
            mkEnvHigh "Availability",
            mkEnvMedium "Availability",
            mkEnvLow "Availability"
          ],
        MetricInfo "Modified Attack Vector" "MAV" False $ mkModifiedUndef : avValues,
        MetricInfo "Modified Attack Complexity" "MAC" False $ mkModifiedUndef : acValues,
        MetricInfo "Modified Privileges Required" "MPR" False $ mkModifiedUndef : prValues,
        MetricInfo "Modified User Interaction" "MUI" False $ mkModifiedUndef : uiValues,
        MetricInfo "Modified Scope" "MS" False $ mkModifiedUndef : sValues,
        MetricInfo "Modified Confidentiality" "MC" False $ mkModifiedUndef : cValues,
        MetricInfo "Modified Integrity" "MI" False $ mkModifiedUndef : iValues,
        MetricInfo "Modified Availability" "MA" False $ mkModifiedUndef : aValues
      ]
    mkEnvUndef = MetricValue "Not Defined" (C "X") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium."
    mkEnvHighMsg m = "Loss of " <> m <> " is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
    mkEnvHigh m = MetricValue "High" (C "H") 1.5 Nothing $ mkEnvHighMsg m
    mkEnvMediumMsg m = "Loss of " <> m <> " is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
    mkEnvMedium m = MetricValue "Medium" (C "M") 1 Nothing $ mkEnvMediumMsg m
    mkEnvLowMsg m = "Loss of " <> m <> " is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
    mkEnvLow m = MetricValue "Low" (C "L") 0.5 Nothing $ mkEnvLowMsg m
    mkModifiedUndef = MetricValue "Not Defined" (C "X") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Score"

-- | Implementation of Section 8.1 "Base"
cvss30BaseScore :: [Metric] -> (Rating, Float)
cvss30BaseScore metrics = (toRating score, score)
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

cvss30score :: [Metric] -> (Rating, Float)
cvss30score metrics
  | hasEnvironmentalMetrics metrics = cvss30EnvironmentalScore metrics
  | hasTemporalMetrics metrics = cvss30TemporalScore metrics
  | otherwise = cvss30BaseScore metrics

cvss30TemporalScore :: [Metric] -> (Rating, Float)
cvss30TemporalScore metrics = (toRating score, score)
  where
    (_, baseScore) = cvss30BaseScore metrics
    exploitCodeMaturity = getMetricValueOr cvss30 metrics 1.0 Unchanged "Exploit Code Maturity"
    remediationLevel = getMetricValueOr cvss30 metrics 1.0 Unchanged "Remediation Level"
    reportConfidence = getMetricValueOr cvss30 metrics 1.0 Unchanged "Report Confidence"
    score = roundup (baseScore * exploitCodeMaturity * remediationLevel * reportConfidence)

cvss30EnvironmentalScore :: [Metric] -> (Rating, Float)
cvss30EnvironmentalScore metrics = (toRating score, score)
  where
    miss =
      min
        ( 1
            - (1 - confidentialityRequirement * modifiedConfidentiality)
              * (1 - integrityRequirement * modifiedIntegrity)
              * (1 - availabilityRequirement * modifiedAvailability)
        )
        0.915

    modifiedImpact
      | modifiedScope == Unchanged = 6.42 * miss
      | otherwise = 7.52 * (miss - 0.029) - 3.25 * powerFloat (miss - 0.02) 15

    modifiedExploitability =
      8.22
        * modifiedAttackVector
        * modifiedAttackComplexity
        * modifiedPrivilegesRequired
        * modifiedUserInteraction

    envScoreHelper
      | modifiedImpact <= 0 = 0
      | modifiedScope == Unchanged =
          roundup (min (modifiedImpact + modifiedExploitability) 10)
      | otherwise =
          roundup (min (1.08 * (modifiedImpact + modifiedExploitability)) 10)

    score
      | modifiedImpact <= 0 = 0
      | otherwise =
          roundup
            ( envScoreHelper
                * exploitCodeMaturity
                * remediationLevel
                * reportConfidence
            )

    exploitCodeMaturity = getMetricValueOr cvss30 metrics 1.0 Unchanged "Exploit Code Maturity"
    remediationLevel = getMetricValueOr cvss30 metrics 1.0 Unchanged "Remediation Level"
    reportConfidence = getMetricValueOr cvss30 metrics 1.0 Unchanged "Report Confidence"
    confidentialityRequirement = getMetricValueOr cvss30 metrics 1.0 Unchanged "Confidentiality Requirement"
    integrityRequirement = getMetricValueOr cvss30 metrics 1.0 Unchanged "Integrity Requirement"
    availabilityRequirement = getMetricValueOr cvss30 metrics 1.0 Unchanged "Availability Requirement"
    modifiedAttackVector = getModifiedMetricValue cvss30 metrics "Modified Attack Vector" "Attack Vector" modifiedScope
    modifiedAttackComplexity = getModifiedMetricValue cvss30 metrics "Modified Attack Complexity" "Attack Complexity" modifiedScope
    modifiedPrivilegesRequired = getModifiedMetricValue cvss30 metrics "Modified Privileges Required" "Privileges Required" modifiedScope
    modifiedUserInteraction = getModifiedMetricValue cvss30 metrics "Modified User Interaction" "User Interaction" modifiedScope
    modifiedScope = getModifiedMetricValue cvss30 metrics "Modified Scope" "Scope" Unchanged
    modifiedConfidentiality = getModifiedMetricValue cvss30 metrics "Modified Confidentiality" "Confidentiality Impact" modifiedScope
    modifiedIntegrity = getModifiedMetricValue cvss30 metrics "Modified Integrity" "Integrity Impact" modifiedScope
    modifiedAvailability = getModifiedMetricValue cvss30 metrics "Modified Availability" "Availability Impact" modifiedScope

    getModifiedMetricValue :: CVSSDB -> [Metric] -> Text -> Text -> Float -> Float
    getModifiedMetricValue db ms modifiedName baseName scope =
      case lookupMetricValueChar db ms modifiedName of
        Just (C "X") -> getMetricValue db ms scope baseName
        Just _ -> getMetricValue db ms scope modifiedName
        Nothing -> getMetricValue db ms scope baseName

validateCvss30 :: [Metric] -> Either CVSSError [Metric]
validateCvss30 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss30, validateRequired cvss30]
  pure metrics

cvss20 :: CVSSDB
cvss20 =
  CVSSDB
    [ MetricGroup "Base" baseMetrics,
      MetricGroup "Temporal" temporalMetrics,
      MetricGroup "Environmental" environmentalMetrics
    ]
  where
    baseMetrics =
      [ MetricInfo
          "Access Vector"
          "AV"
          True
          [ MetricValue "Local" (C "L") 0.395 Nothing "A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account.",
            MetricValue "Adjacent Network" (C "A") 0.646 Nothing "A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software.",
            MetricValue "Network" (C "N") 1.0 Nothing "A vulnerability exploitable with network access means that the vulnerable software is bound to the network stack and the attacker does not require local network access or local access."
          ],
        MetricInfo
          "Access Complexity"
          "AC"
          True
          [ MetricValue "High" (C "H") 0.35 Nothing "Specialized access conditions exist.",
            MetricValue "Medium" (C "M") 0.61 Nothing "The access conditions are somewhat specialized.",
            MetricValue "Low" (C "L") 0.71 Nothing "Specialized access conditions or extenuating circumstances do not exist."
          ],
        MetricInfo
          "Authentication"
          "Au"
          True
          [ MetricValue "Multiple" (C "M") 0.45 Nothing "Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time.",
            MetricValue "Single" (C "S") 0.56 Nothing "The vulnerability requires an attacker to be logged into the system (such as at a command line or via a desktop session or web interface).",
            MetricValue "None" (C "N") 0.704 Nothing "Authentication is not required to exploit the vulnerability."
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
    mkNone = MetricValue "None" (C "N") 0 Nothing
    mkPartial = MetricValue "Partial" (C "P") 0.275 Nothing
    mkComplete = MetricValue "Complete" (C "C") 0.660 Nothing
    temporalMetrics =
      [ MetricInfo
          "Exploitability"
          "E"
          False
          [ MetricValue "Not Defined" (C "ND") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score.",
            MetricValue "Unproven" (C "U") 0.85 Nothing "No exploit code is available, or an exploit is theoretical.",
            MetricValue "Proof of Concept" (C "POC") 0.9 Nothing "Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems.",
            MetricValue "Functional" (C "F") 0.95 Nothing "Functional exploit code is available. The code works in most situations where the vulnerability exists.",
            MetricValue "High" (C "H") 1.0 Nothing "Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available."
          ],
        MetricInfo
          "Remediation Level"
          "RL"
          False
          [ MetricValue "Not Defined" (C "ND") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score.",
            MetricValue "Official Fix" (C "OF") 0.87 Nothing "A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.",
            MetricValue "Temporary Fix" (C "TF") 0.9 Nothing "There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.",
            MetricValue "Workaround" (C "W") 0.95 Nothing "There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.",
            MetricValue "Unavailable" (C "U") 1.0 Nothing "There is either no solution available or it is impossible to apply."
          ],
        MetricInfo
          "Report Confidence"
          "RC"
          False
          [ MetricValue "Not Defined" (C "ND") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score.",
            MetricValue "Unconfirmed" (C "UC") 0.9 Nothing "There are reports of impacts that indicate a vulnerability is present. The reports indicate that the cause of the vulnerability is unknown, or reports may differ on the cause or impacts of the vulnerability.",
            MetricValue "Uncorroborated" (C "UR") 0.95 Nothing "Significant details are published, but researchers either do not have full confidence in the root cause.",
            MetricValue "Confirmed" (C "C") 1.0 Nothing "Detailed reports exist, or functional reproduction is possible (functional exploits may provide this). Source code is available to independently verify the assertions of the research."
          ]
      ]
    environmentalMetrics =
      [ MetricInfo
          "Confidentiality Requirement"
          "CR"
          False
          [ MetricValue "Not Defined" (C "ND") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.",
            MetricValue "Low" (C "L") 0.5 Nothing "Loss of the metric is likely to have only a limited adverse effect on the organization or individuals associated with the organization.",
            MetricValue "Medium" (C "M") 1 Nothing "Loss of the metric is likely to have a serious adverse effect on the organization or individuals associated with the organization.",
            MetricValue "High" (C "H") 1.5 Nothing "Loss of the metric is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization."
          ],
        MetricInfo
          "Integrity Requirement"
          "IR"
          False
          [ MetricValue "Not Defined" (C "ND") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.",
            MetricValue "Low" (C "L") 0.5 Nothing "Loss of the metric is likely to have only a limited adverse effect on the organization or individuals associated with the organization.",
            MetricValue "Medium" (C "M") 1 Nothing "Loss of the metric is likely to have a serious adverse effect on the organization or individuals associated with the organization.",
            MetricValue "High" (C "H") 1.5 Nothing "Loss of the metric is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization."
          ],
        MetricInfo
          "Availability Requirement"
          "AR"
          False
          [ MetricValue "Not Defined" (C "ND") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.",
            MetricValue "Low" (C "L") 0.5 Nothing "Loss of the metric is likely to have only a limited adverse effect on the organization or individuals associated with the organization.",
            MetricValue "Medium" (C "M") 1 Nothing "Loss of the metric is likely to have a serious adverse effect on the organization or individuals associated with the organization.",
            MetricValue "High" (C "H") 1.5 Nothing "Loss of the metric is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization."
          ],
        MetricInfo
          "Collateral Damage Potential"
          "CDP"
          False
          [ MetricValue "Not Defined" (C "ND") 0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning None.",
            MetricValue "None" (C "N") 0 Nothing "There is no potential for loss of physical assets or loss of human life.",
            MetricValue "Low" (C "L") 0.1 Nothing "There is a negligible loss of physical assets or a minor loss of human life.",
            MetricValue "Low-Medium" (C "LM") 0.3 Nothing "There is a significant loss of physical assets or a significant loss of human life.",
            MetricValue "Medium-High" (C "MH") 0.4 Nothing "There is a massive loss of physical assets or a major loss of human life.",
            MetricValue "High" (C "H") 0.5 Nothing "There is a catastrophic loss of physical assets or a massive loss of human life."
          ],
        MetricInfo
          "Target Distribution"
          "TD"
          False
          [ MetricValue "Not Defined" (C "ND") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning High.",
            MetricValue "None" (C "N") 0 Nothing "There is no significant effect on the organization.",
            MetricValue "Low" (C "L") 0.25 Nothing "The vulnerable component affects a minority of the organization.",
            MetricValue "Medium" (C "M") 0.75 Nothing "The vulnerable component affects a significant portion of the organization.",
            MetricValue "High" (C "H") 1 Nothing "The vulnerable component affects the entire organization."
          ]
      ]

validateCvss20 :: [Metric] -> Either CVSSError [Metric]
validateCvss20 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss20, validateRequired cvss20]
  pure metrics

validateCvss40 :: [Metric] -> Either CVSSError [Metric]
validateCvss40 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss40, validateRequired cvss40]
  pure metrics

cvss40 :: CVSSDB
cvss40 =
  CVSSDB
    [ MetricGroup "Base" baseMetrics,
      MetricGroup "Supplemental" supplementalMetrics,
      MetricGroup "Environmental" environmentalMetrics,
      MetricGroup "Threat" threatMetrics
    ]
  where
    baseMetrics =
      [ MetricInfo "Attack Vector" "AV" True avValues,
        MetricInfo "Attack Complexity" "AC" True acValues,
        MetricInfo "Attack Requirements" "AT" True atValues,
        MetricInfo "Privileges Required" "PR" True prValues,
        MetricInfo "User Interaction" "UI" True uiValues,
        MetricInfo "Confidentiality Impact to the Vulnerable System" "VC" True vcValues,
        MetricInfo "Integrity Impact to the Vulnerable System" "VI" True viValues,
        MetricInfo "Availability Impact to the Vulnerable System" "VA" True vaValues,
        MetricInfo "Subsequent System Confidentiality Impact" "SC" True scValues,
        MetricInfo "Subsequent System Integrity Impact" "SI" True siValues,
        MetricInfo "Subsequent System Availability Impact" "SA" True saValues
      ]
    avValues =
      [ MetricValue "Network" (C "N") 0 Nothing "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet.",
        MetricValue "Adjacent" (C "A") 0 Nothing "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.",
        MetricValue "Local" (C "L") 0 Nothing "The vulnerable component is not bound to the network stack and the attacker's path is via read/write/execute capabilities.",
        MetricValue "Physical" (C "P") 0 Nothing "The attack requires the attacker to physically touch or manipulate the vulnerable component."
      ]
    acValues =
      [ MetricValue "Low" (C "L") 0 Nothing "Specialized access conditions or extenuating circumstances do not exist.",
        MetricValue "High" (C "H") 0 Nothing "A successful attack depends on conditions beyond the attacker's control."
      ]
    atValues =
      [ MetricValue "Present" (C "P") 0 Nothing "The conditions described in Attack Vector, Attack Complexity, Privileges Required, and User Interaction exist in the environment.",
        MetricValue "Absent" (C "N") 0 Nothing "The conditions described in Attack Vector, Attack Complexity, Privileges Required, and User Interaction do NOT exist in the environment."
      ]
    prValues =
      [ MetricValue "None" (C "N") 0 Nothing "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.",
        MetricValue "Low" (C "L") 0 Nothing "The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user.",
        MetricValue "High" (C "H") 0 Nothing "The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
      ]
    uiValues =
      [ MetricValue "None" (C "N") 0 Nothing "The vulnerable system can be exploited without interaction from any user.",
        MetricValue "Passive" (C "P") 0 Nothing "The human user must be engaged in some form of passive interaction (e.g., read an email, view a file).",
        MetricValue "Active" (C "A") 0 Nothing "The human user must be engaged in some form of active interaction (e.g., click a link, run a program)."
      ]
    vcValues =
      [ mkImpactHigh "There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker.",
        mkImpactLow "There is some loss of confidentiality.",
        mkImpactNone "There is no loss of confidentiality within the impacted component."
      ]
    viValues =
      [ mkImpactHigh "There is a total loss of integrity, or a complete loss of protection.",
        mkImpactLow "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited.",
        mkImpactNone "There is no loss of integrity within the impacted component."
      ]
    vaValues =
      [ mkImpactHigh "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component.",
        mkImpactLow "Performance is reduced or there are interruptions in resource availability.",
        mkImpactNone "There is no impact to availability within the impacted component."
      ]
    scValues =
      [ mkImpactHigh "There is total loss of confidentiality, resulting in all resources within the Subsequent System being divulged to the attacker.",
        mkImpactLow "There is some loss of confidentiality.",
        mkImpactNone "There is no loss of confidentiality within the Subsequent System."
      ]
    siValues =
      [ mkImpactHigh "There is a total loss of integrity, or a complete loss of protection.",
        mkImpactLow "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited.",
        mkImpactNone "There is no loss of integrity within the Subsequent System."
      ]
    saValues =
      [ mkImpactHigh "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Subsequent System.",
        mkImpactLow "Performance is reduced or there are interruptions in resource availability.",
        mkImpactNone "There is no impact to availability within the Subsequent System."
      ]
    mkImpactHigh = MetricValue "High" (C "H") 0 Nothing
    mkImpactLow = MetricValue "Low" (C "L") 0 Nothing
    mkImpactNone = MetricValue "None" (C "N") 0 Nothing
    supplementalMetrics =
      [ MetricInfo "Safety" "S" False sValues,
        MetricInfo "Automatable" "AU" False auValues,
        MetricInfo "Recovery" "R" False rValues,
        MetricInfo "Value Density" "V" False vValues,
        MetricInfo "Vulnerability Response Effort" "RE" False reValues,
        MetricInfo "Provider Urgency" "U" False uValues
      ]
    sValues =
      [ mkSuppUndef,
        MetricValue "Negligible" (C "N") 0 Nothing "There is little to no safety impact to human life.",
        MetricValue "Present" (C "P") 0 Nothing "There is a potential for non-trivial negative impact on human life."
      ]
    auValues =
      [ mkSuppUndef,
        MetricValue "No" (C "N") 0 Nothing "The attacker cannot reliably cause the specific impact or the effort required is beyond the attacker's capabilities.",
        MetricValue "Yes" (C "Y") 0 Nothing "The attacker can reliably cause the specific impact using the available exploitation techniques and capabilities."
      ]
    rValues =
      [ mkSuppUndef,
        MetricValue "Automatic" (C "A") 0 Nothing "Recovery is performed by the system without human intervention.",
        MetricValue "User" (C "U") 0 Nothing "Recovery is performed by a system administrator.",
        MetricValue "Irreversible" (C "I") 0 Nothing "Recovery is impossible."
      ]
    vValues =
      [ mkSuppUndef,
        MetricValue "Diffuse" (C "D") 0 Nothing "The vulnerable component impacts a large number of organizations or users.",
        MetricValue "Concentrated" (C "C") 0 Nothing "The vulnerable component impacts a small number of organizations or users."
      ]
    reValues =
      [ mkSuppUndef,
        MetricValue "Low" (C "L") 0 Nothing "The effort required to respond to the vulnerability is low.",
        MetricValue "Moderate" (C "M") 0 Nothing "The effort required to respond to the vulnerability is moderate.",
        MetricValue "High" (C "H") 0 Nothing "The effort required to respond to the vulnerability is high."
      ]
    uValues =
      [ mkSuppUndef,
        MetricValue "Clear" (C "C") 0 Nothing "The provider urges immediate action to resolve the vulnerability.",
        MetricValue "Amber" (C "A") 0 Nothing "The provider urges action to resolve the vulnerability in a timely manner.",
        MetricValue "Green" (C "G") 0 Nothing "The provider recommends the vulnerability be resolved, but the urgency is lower."
      ]
    mkSuppUndef = MetricValue "Not Defined" (C "X") 0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall score."
    environmentalMetrics =
      [ MetricInfo "Confidentiality Requirement" "CR" False crValues,
        MetricInfo "Integrity Requirement" "IR" False irValues,
        MetricInfo "Availability Requirement" "AR" False arValues,
        MetricInfo "Modified Attack Vector" "MAV" False $ mkEnvUndef : avValues,
        MetricInfo "Modified Attack Complexity" "MAC" False $ mkEnvUndef : acValues,
        MetricInfo "Modified Attack Requirements" "MAT" False $ mkEnvUndef : atValues,
        MetricInfo "Modified Privileges Required" "MPR" False $ mkEnvUndef : prValues,
        MetricInfo "Modified User Interaction" "MUI" False $ mkEnvUndef : uiValues,
        MetricInfo "Modified Confidentiality Impact to the Vulnerable System" "MVC" False $ mkEnvUndef : vcValues,
        MetricInfo "Modified Integrity Impact to the Vulnerable System" "MVI" False $ mkEnvUndef : viValues,
        MetricInfo "Modified Availability Impact to the Vulnerable System" "MVA" False $ mkEnvUndef : vaValues,
        MetricInfo "Modified Subsequent System Confidentiality Impact" "MSC" False $ mkEnvUndef : scValues,
        MetricInfo "Modified Subsequent System Integrity Impact" "MSI" False $ mkEnvUndef : siValues,
        MetricInfo "Modified Subsequent System Availability Impact" "MSA" False $ mkEnvUndef : saValues
      ]
    crValues =
      [ mkEnvUndef,
        MetricValue "Low" (C "L") 0 Nothing "Loss of confidentiality is likely to have only a limited adverse effect on an organization or individuals associated with the organization (e.g., employees, customers).",
        MetricValue "Medium" (C "M") 0 Nothing "Loss of confidentiality is likely to have a serious adverse effect on an organization or individuals associated with the organization (e.g., employees, customers).",
        MetricValue "High" (C "H") 0 Nothing "Loss of confidentiality is likely to have a catastrophic adverse effect on an organization or individuals associated with the organization (e.g., employees, customers)."
      ]
    irValues =
      [ mkEnvUndef,
        MetricValue "Low" (C "L") 0 Nothing "Loss of integrity is likely to have only a limited adverse effect on an organization or individuals associated with the organization (e.g., employees, customers).",
        MetricValue "Medium" (C "M") 0 Nothing "Loss of integrity is likely to have a serious adverse effect on an organization or individuals associated with the organization (e.g., employees, customers).",
        MetricValue "High" (C "H") 0 Nothing "Loss of integrity is likely to have a catastrophic adverse effect on an organization or individuals associated with the organization (e.g., employees, customers)."
      ]
    arValues =
      [ mkEnvUndef,
        MetricValue "Low" (C "L") 0 Nothing "Loss of availability is likely to have only a limited adverse effect on an organization or individuals associated with the organization (e.g., employees, customers).",
        MetricValue "Medium" (C "M") 0 Nothing "Loss of availability is likely to have a serious adverse effect on an organization or individuals associated with the organization (e.g., employees, customers).",
        MetricValue "High" (C "H") 0 Nothing "Loss of availability is likely to have a catastrophic adverse effect on an organization or individuals associated with the organization (e.g., employees, customers)."
      ]
    mkEnvUndef = MetricValue "Not Defined" (C "X") 0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium."
    threatMetrics =
      [ MetricInfo "Exploit Maturity" "E" False eValues
      ]
    eValues =
      [ mkThreatUndef,
        MetricValue "Unreported" (C "U") 0 Nothing "The vulnerability has not been reported to the vendor or the vendor has not been given the opportunity to respond.",
        MetricValue "Proof of Concept" (C "P") 0 Nothing "Proof of concept code exists, or the vulnerability is theoretical.",
        MetricValue "Attacked" (C "A") 0 Nothing "The vulnerability has been exploited in the wild."
      ]
    mkThreatUndef = MetricValue "Not Defined" (C "X") 0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Threat Score, i.e., it has the same effect on scoring as assigning Unreported."

-- | Implementation of section 3.2.1. "Base Equation"
cvss20score :: [Metric] -> (Rating, Float)
cvss20score metrics
  | hasEnvironmentalMetrics20 metrics = cvss20EnvironmentalScore metrics
  | hasTemporalMetrics metrics = cvss20TemporalScore metrics
  | otherwise = cvss20BaseScore metrics

cvss20BaseScore :: [Metric] -> (Rating, Float)
cvss20BaseScore metrics = (toRating20 score, score)
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

cvss20TemporalScore :: [Metric] -> (Rating, Float)
cvss20TemporalScore metrics = (toRating20 score, score)
  where
    (_, baseScore) = cvss20BaseScore metrics
    exploitability = optionalMetric20 metrics 1.0 "Exploitability"
    remediationLevel = optionalMetric20 metrics 1.0 "Remediation Level"
    reportConfidence = optionalMetric20 metrics 1.0 "Report Confidence"
    score = round_to_1_decimal (baseScore * exploitability * remediationLevel * reportConfidence)

    round_to_1_decimal :: Float -> Float
    round_to_1_decimal x = fromIntegral @Int (round (x * 10)) / 10

optionalMetric20 :: [Metric] -> Float -> Text -> Float
optionalMetric20 metrics defaultValue =
  getMetricValueOr cvss20 metrics defaultValue 0

cvss20EnvironmentalScore :: [Metric] -> (Rating, Float)
cvss20EnvironmentalScore metrics = (toRating20 score, score)
  where
    securityRequirement = getMetricValueOr cvss20 metrics 1 0
    confidentialityRequirement = securityRequirement "Confidentiality Requirement"
    integrityRequirement = securityRequirement "Integrity Requirement"
    availabilityRequirement = securityRequirement "Availability Requirement"

    cVal = gm "Confidentiality Impact"
    iVal = gm "Integrity Impact"
    aVal = gm "Availability Impact"

    adjustedImpact = min 10.0 (10.41 * (1 - (1 - cVal * confidentialityRequirement) * (1 - iVal * integrityRequirement) * (1 - aVal * availabilityRequirement)))

    exploitability = 20 * gm "Access Vector" * gm "Access Complexity" * gm "Authentication"

    fAdj
      | adjustedImpact == 0 = 0
      | otherwise = 1.176

    adjustedBase = round_to_1_decimal ((0.6 * adjustedImpact + 0.4 * exploitability - 1.5) * fAdj)

    exploitabilityTemporal = optionalMetric20 metrics 1.0 "Exploitability"
    remediationLevel = optionalMetric20 metrics 1.0 "Remediation Level"
    reportConfidence = optionalMetric20 metrics 1.0 "Report Confidence"
    adjustedTemporal = round_to_1_decimal (adjustedBase * exploitabilityTemporal * remediationLevel * reportConfidence)

    collateralDamagePotential = optionalMetric20 metrics 0 "Collateral Damage Potential"
    targetDistribution = optionalMetric20 metrics 1 "Target Distribution"

    score = round_to_1_decimal ((adjustedTemporal + (10 - adjustedTemporal) * collateralDamagePotential) * targetDistribution)

    gm :: Text -> Float
    gm = getMetricValue cvss20 metrics 0

    round_to_1_decimal :: Float -> Float
    round_to_1_decimal x = fromIntegral @Int (round (x * 10)) / 10

-- | CVSS 4.0 scoring - MacroVector based algorithm
cvss40score :: [Metric] -> (Rating, Float)
cvss40score metrics
  | hasEnvironmentalMetrics40 metrics = error "CVSS 4.0 environmental scoring not yet implemented"
  | hasThreatMetrics40 metrics = error "CVSS 4.0 threat scoring not yet implemented"
  | otherwise = cvss40BaseScore metrics

hasThreatMetrics40 :: [Metric] -> Bool
hasThreatMetrics40 = any (\metric -> mName metric == "E")

hasEnvironmentalMetrics40 :: [Metric] -> Bool
hasEnvironmentalMetrics40 metrics =
  any
    ( \metric ->
        let n = coerce (mName metric) :: Text
         in n
              `elem` [ "CR",
                       "IR",
                       "AR",
                       "MAV",
                       "MAC",
                       "MAT",
                       "MPR",
                       "MUI",
                       "MVC",
                       "MVI",
                       "MVA",
                       "MSC",
                       "MSI",
                       "MSA"
                     ]
    )
    metrics

-- | Get metric value char, defaulting to X for base metrics if not present
getMetricValueChar40 :: [Metric] -> Text -> MetricValueChar
getMetricValueChar40 metrics name =
  case find (\metric -> mName metric == MetricShortName name) metrics of
    Nothing -> C "X"
    Just (Metric _ char) -> char

-- | Helper to get first char from metric value
getChar40 :: [Metric] -> Text -> Char
getChar40 metrics name = case getMetricValueChar40 metrics name of
  C c -> Text.head c

-- | CVSS 4.0 base score implementation
cvss40BaseScore :: [Metric] -> (Rating, Float)
cvss40BaseScore metrics = (toRating finalScore, finalScore)
  where
    finalScore = round40 (max 0.0 (min 10.0 value))
    value = lookupScore - meanDistance

    mv = macroVectorFromMetrics metrics
    lookupScore = macroVectorLookup mv

    EQ1Result {eq1Level = eq1, eq1AV = avLevel, eq1PR = prLevel, eq1UI = uiLevel} = computeEQ1 metrics
    EQ2Result {eq2Level = eq2, eq2AC = acLevel, eq2AT = atLevel} = computeEQ2 metrics
    EQ3Result {eq3Level = eq3, eq3VC = vcLevel, eq3VI = viLevel, eq3VA = vaLevel} = computeEQ3 metrics
    EQ4Result {eq4Level = eq4, eq4SC = scLevel, eq4SI = siLevel, eq4SA = saLevel} = computeEQ4 metrics
    EQ5Result {eq5Level = eq5, eq5E = eLevel} = computeEQ5 metrics
    EQ6Result {eq6Level = eq6, eq6CR = crLevel, eq6IR = irLevel, eq6AR = arLevel} = computeEQ6 (vcLevel, viLevel, vaLevel) metrics

    currentSeverities =
      SeverityGroups
        { sgEQ1 = [avLevel, prLevel, uiLevel],
          sgEQ2 = [acLevel, atLevel],
          sgEQ3 = [vcLevel, viLevel, vaLevel, crLevel, irLevel, arLevel],
          sgEQ4 = [scLevel, siLevel, saLevel],
          sgEQ5 = [eLevel]
        }

    maxSeverities = getMaxSeverities mv

    availableDistances = getAvailableDistances lookupScore mv

    meanDistance = computeMeanDistance currentSeverities availableDistances maxSeverities

    round40 :: Float -> Float
    round40 x = fromIntegral @Int (round (x * 10 + 0.0001)) / 10

-- | Convert metrics to MacroVector
macroVectorFromMetrics :: [Metric] -> MacroVector
macroVectorFromMetrics metrics =
  MacroVector
    { mvEQ1 = eq1Level (computeEQ1 metrics),
      mvEQ2 = eq2Level (computeEQ2 metrics),
      mvEQ3 = eq3Level (computeEQ3 metrics),
      mvEQ4 = eq4Level (computeEQ4 metrics),
      mvEQ5 = eq5Level (computeEQ5 metrics),
      mvEQ6 = eq6Level (computeEQ6 (vcLevel, viLevel, vaLevel) metrics)
    }
  where
    EQ3Result {eq3VC = vcLevel, eq3VI = viLevel, eq3VA = vaLevel} = computeEQ3 metrics

-- | Lookup score from MacroVector
macroVectorLookup :: MacroVector -> Float
macroVectorLookup mv = case Map.lookup (macroVectorToText mv) cvss40LookupTable of
  Nothing -> error $ "CVSS 4.0: invalid MacroVector: " <> show mv
  Just s -> s

-- | Convert MacroVector to Text for lookup table
macroVectorToText :: MacroVector -> Text
macroVectorToText MacroVector {..} =
  Text.pack $ concat [eqLevelToChar mvEQ1, eqLevelToChar mvEQ2, eqLevelToChar mvEQ3, eqLevelToChar mvEQ4, eqLevelToChar mvEQ5, eqLevelToChar mvEQ6]
  where
    eqLevelToChar EQ0 = "0"
    eqLevelToChar EQ1 = "1"
    eqLevelToChar EQ2 = "2"

-- | Compute EQ1 (AV/PR/UI) - 3 levels (EQ0, EQ1, EQ2)
computeEQ1 :: [Metric] -> EQ1Result
computeEQ1 metrics =
  EQ1Result
    { eq1Level = eq1,
      eq1AV = avLevel,
      eq1PR = prLevel,
      eq1UI = uiLevel
    }
  where
    avChar = getChar40 metrics "AV"
    prChar = getChar40 metrics "PR"
    uiChar = getChar40 metrics "UI"

    avLevel = Severity $ Map.findWithDefault 0.3 avChar avLevels
    prLevel = Severity $ Map.findWithDefault 0.2 prChar prLevels
    uiLevel = Severity $ Map.findWithDefault 0.2 uiChar uiLevels

    eq1
      | avChar == 'N' && prChar == 'N' && uiChar == 'N' = EQ0
      | (avChar == 'N' || prChar == 'N' || uiChar == 'N') && not (avChar == 'N' && prChar == 'N' && uiChar == 'N') && avChar /= 'P' = EQ1
      | avChar == 'P' || not (avChar == 'N' || prChar == 'N' || uiChar == 'N') = EQ2
      | otherwise = EQ1

-- | Compute EQ2 (AC/AT) - 2 levels (EQ0, EQ1)
computeEQ2 :: [Metric] -> EQ2Result
computeEQ2 metrics =
  EQ2Result
    { eq2Level = eq2,
      eq2AC = acLevel,
      eq2AT = atLevel
    }
  where
    acChar = getChar40 metrics "AC"
    atChar = getChar40 metrics "AT"

    acLevel = Severity $ Map.findWithDefault 0.1 acChar acLevels
    atLevel = Severity $ Map.findWithDefault 0.1 atChar atLevels

    eq2
      | acChar == 'L' && atChar == 'N' = EQ0
      | otherwise = EQ1

-- | Compute EQ3 (VC/VI/VA) - 3 levels (EQ0, EQ1, EQ2)
computeEQ3 :: [Metric] -> EQ3Result
computeEQ3 metrics =
  EQ3Result
    { eq3Level = eq3,
      eq3VC = vcLevel,
      eq3VI = viLevel,
      eq3VA = vaLevel
    }
  where
    vcChar = getChar40 metrics "VC"
    viChar = getChar40 metrics "VI"
    vaChar = getChar40 metrics "VA"

    vcLevel = Severity $ Map.findWithDefault 0.2 vcChar vcLevels
    viLevel = Severity $ Map.findWithDefault 0.2 viChar viLevels
    vaLevel = Severity $ Map.findWithDefault 0.2 vaChar vaLevels

    eq3
      | vcChar == 'H' && viChar == 'H' = EQ0
      | not (vcChar == 'H' && viChar == 'H') && (vcChar == 'H' || viChar == 'H' || vaChar == 'H') = EQ1
      | not (vcChar == 'H' || viChar == 'H' || vaChar == 'H') = EQ2
      | otherwise = EQ1

-- | Compute EQ4 (SC/SI/SA) - 3 levels (EQ0, EQ1, EQ2)
computeEQ4 :: [Metric] -> EQ4Result
computeEQ4 metrics =
  EQ4Result
    { eq4Level = eq4,
      eq4SC = scLevel,
      eq4SI = siLevel,
      eq4SA = saLevel
    }
  where
    scChar = getChar40 metrics "SC"
    siChar = getChar40 metrics "SI"
    saChar = getChar40 metrics "SA"

    scLevel = Severity $ Map.findWithDefault 0.3 scChar scLevels
    siLevel = Severity $ Map.findWithDefault 0.3 siChar siLevels
    saLevel = Severity $ Map.findWithDefault 0.3 saChar saLevels

    eq4
      | siChar == 'S' || saChar == 'S' = EQ0
      | siChar == 'H' && saChar == 'N' && scChar == 'H' = EQ0
      | not (siChar == 'S' || saChar == 'S') && (scChar == 'H' || siChar == 'H' || saChar == 'H') = EQ1
      | not (siChar == 'S' || saChar == 'S') && not (scChar == 'H' || siChar == 'H' || saChar == 'H') = EQ2
      | otherwise = EQ1

-- | Compute EQ5 (E - Exploit Maturity) - 3 levels (EQ0, EQ1, EQ2)
computeEQ5 :: [Metric] -> EQ5Result
computeEQ5 metrics =
  EQ5Result
    { eq5Level = eq5,
      eq5E = eLevel
    }
  where
    eChar = getChar40 metrics "E"
    eLevel = Severity $ Map.findWithDefault 0.0 eChar eLevels

    eq5
      | eChar == 'A' = EQ0
      | eChar == 'P' = EQ1
      | eChar == 'U' = EQ2
      | otherwise = EQ0

-- | Compute EQ6 (VC/VI/VA + CR/IR/AR) - 2 levels (EQ0, EQ1)
computeEQ6 :: (Severity, Severity, Severity) -> [Metric] -> EQ6Result
computeEQ6 (Severity vcLevel, Severity viLevel, Severity vaLevel) metrics =
  EQ6Result
    { eq6Level = eq6,
      eq6CR = crLevel,
      eq6IR = irLevel,
      eq6AR = arLevel
    }
  where
    crChar = getChar40 metrics "CR"
    irChar = getChar40 metrics "IR"
    arChar = getChar40 metrics "AR"

    crLevel = Severity $ Map.findWithDefault 0.0 crChar crLevels
    irLevel = Severity $ Map.findWithDefault 0.0 irChar irLevels
    arLevel = Severity $ Map.findWithDefault 0.0 arChar arLevels

    eq6
      | (crChar == 'H' && vcLevel == 0.0) || (irChar == 'H' && viLevel == 0.0) || (arChar == 'H' && vaLevel == 0.0) = EQ0
      | otherwise = EQ1

-- | Get max severity levels for each EQ group based on the MacroVector
getMaxSeverities :: MacroVector -> MaxSeverities
getMaxSeverities MacroVector {..} =
  MaxSeverities
    { msAV = Severity avMax,
      msPR = Severity prMax,
      msUI = Severity uiMax,
      msAC = Severity acMax,
      msAT = Severity atMax,
      msVC = Severity vcMax,
      msVI = Severity viMax,
      msVA = Severity vaMax,
      msSC = Severity scMax,
      msSI = Severity siMax,
      msSA = Severity saMax,
      msE = Severity eMax,
      msCR = Severity crMax,
      msIR = Severity irMax,
      msAR = Severity arMax
    }
  where
    avMax = case mvEQ1 of
      EQ0 -> 0.0
      EQ1 -> 0.3
      EQ2 -> 0.4
    prMax = case mvEQ1 of
      EQ0 -> 0.0
      _ -> 0.2
    uiMax = case mvEQ1 of
      EQ0 -> 0.0
      _ -> 0.2
    acMax = case mvEQ2 of
      EQ0 -> 0.0
      EQ1 -> 0.1
    atMax = case mvEQ2 of
      EQ0 -> 0.0
      EQ1 -> 0.1
    vcMax = case mvEQ3 of
      EQ0 -> 0.0
      EQ1 -> 0.1
      EQ2 -> 0.2
    viMax = case mvEQ3 of
      EQ0 -> 0.0
      EQ1 -> 0.1
      EQ2 -> 0.2
    vaMax = case mvEQ3 of
      EQ0 -> 0.0
      EQ1 -> 0.1
      EQ2 -> 0.2
    scMax = case mvEQ4 of
      EQ0 -> 0.1
      EQ1 -> 0.1
      EQ2 -> 0.3
    siMax = case mvEQ4 of
      EQ0 -> 0.0
      EQ1 -> 0.1
      EQ2 -> 0.3
    saMax = case mvEQ4 of
      EQ0 -> 0.0
      EQ1 -> 0.1
      EQ2 -> 0.3
    eMax = 0.0
    crMax = 0.0
    irMax = 0.0
    arMax = 0.0

-- | Get available distances to next-lower MacroVector for each EQ group
getAvailableDistances :: Float -> MacroVector -> AvailableDistances
getAvailableDistances score mv =
  AvailableDistances
    { adEQ1 = getNextScore (incEQ 0 mv) score,
      adEQ2 = getNextScore (incEQ 1 mv) score,
      adEQ3 = getNextScore (incEQ 2 mv) score,
      adEQ4 = getNextScore (incEQ 3 mv) score,
      adEQ5 = getNextScore (incEQ 4 mv) score
    }
  where
    incEQ :: Int -> MacroVector -> MacroVector
    incEQ idx MacroVector {..} = case idx of
      0 -> mv {mvEQ1 = incrementEQ mvEQ1}
      1 -> mv {mvEQ2 = incrementEQ mvEQ2}
      2 -> mv {mvEQ3 = incrementEQ mvEQ3}
      3 -> mv {mvEQ4 = incrementEQ mvEQ4}
      4 -> mv {mvEQ5 = incrementEQ mvEQ5}
      _ -> mv

    incrementEQ :: EQLevel -> EQLevel
    incrementEQ EQ0 = EQ1
    incrementEQ EQ1 = EQ2
    incrementEQ EQ2 = EQ2

    getNextScore :: MacroVector -> Float -> Maybe Float
    getNextScore mv' s = do
      ns <- Map.lookup (macroVectorToText mv') cvss40LookupTable
      pure (s - ns)

-- | Compute mean normalized distance for interpolation
computeMeanDistance :: SeverityGroups -> AvailableDistances -> MaxSeverities -> Float
computeMeanDistance currentSgs availableDists maxSvs = meanDist
  where
    allNormalized =
      [ normalize c d m
        | (c, d, m) <- zip3WithGroups currentSgs (repeatDistances availableDists) maxSvs
      ]
    flattened = catMaybes allNormalized
    count = fromIntegral @Int (length flattened)
    meanDist = if count > 0 then sum flattened / count else 0.0

    zip3WithGroups :: SeverityGroups -> [Maybe Float] -> MaxSeverities -> [(Severity, Maybe Float, Severity)]
    zip3WithGroups SeverityGroups {..} dists MaxSeverities {..} =
      concat
        [ zip3 sgEQ1 (repeat $ dists !! 0) [msAV, msPR, msUI],
          zip3 sgEQ2 (repeat $ dists !! 1) [msAC, msAT],
          zip3 sgEQ3 (repeat $ dists !! 2) [msVC, msVI, msVA, msCR, msIR, msAR],
          zip3 sgEQ4 (repeat $ dists !! 3) [msSC, msSI, msSA],
          zip3 sgEQ5 (repeat $ dists !! 4) [msE]
        ]

    repeatDistances :: AvailableDistances -> [Maybe Float]
    repeatDistances AvailableDistances {..} = [adEQ1, adEQ2, adEQ3, adEQ4, adEQ5]

    normalize :: Severity -> Maybe Float -> Severity -> Maybe Float
    normalize (Severity curr) avail (Severity maxSev)
      | availJust && maxSev > 0 = Just ((curr - maxSev) / maxSev * fromMaybe 0 avail)
      | otherwise = Nothing
      where
        availJust
          | Just a <- avail, a > 0 = True
          | otherwise = False

-- | Numeric level mappings for CVSS 4.0 metrics
avLevels :: Map.Map Char Float
avLevels = Map.fromList [('N', 0.0), ('A', 0.1), ('L', 0.2), ('P', 0.3)]

prLevels :: Map.Map Char Float
prLevels = Map.fromList [('N', 0.0), ('L', 0.1), ('H', 0.2)]

uiLevels :: Map.Map Char Float
uiLevels = Map.fromList [('N', 0.0), ('P', 0.1), ('A', 0.2)]

acLevels :: Map.Map Char Float
acLevels = Map.fromList [('L', 0.0), ('H', 0.1)]

atLevels :: Map.Map Char Float
atLevels = Map.fromList [('N', 0.0), ('P', 0.1)]

vcLevels :: Map.Map Char Float
vcLevels = Map.fromList [('H', 0.0), ('L', 0.1), ('N', 0.2)]

viLevels :: Map.Map Char Float
viLevels = Map.fromList [('H', 0.0), ('L', 0.1), ('N', 0.2)]

vaLevels :: Map.Map Char Float
vaLevels = Map.fromList [('H', 0.0), ('L', 0.1), ('N', 0.2)]

scLevels :: Map.Map Char Float
scLevels = Map.fromList [('H', 0.1), ('L', 0.2), ('N', 0.3)]

siLevels :: Map.Map Char Float
siLevels = Map.fromList [('S', 0.0), ('H', 0.1), ('L', 0.2), ('N', 0.3)]

saLevels :: Map.Map Char Float
saLevels = Map.fromList [('S', 0.0), ('H', 0.1), ('L', 0.2), ('N', 0.3)]

crLevels :: Map.Map Char Float
crLevels = Map.fromList [('H', 0.0), ('M', 0.1), ('L', 0.2)]

irLevels :: Map.Map Char Float
irLevels = Map.fromList [('H', 0.0), ('M', 0.1), ('L', 0.2)]

arLevels :: Map.Map Char Float
arLevels = Map.fromList [('H', 0.0), ('M', 0.1), ('L', 0.2)]

eLevels :: Map.Map Char Float
eLevels = Map.fromList [('A', 0.0), ('P', 1.0), ('U', 2.0)]

-- | CVSS 4.0 lookup table - MacroVector to base score
cvss40LookupTable :: Map.Map Text Float
cvss40LookupTable =
  Map.fromList
    [ ("000000", 10.0),
      ("000001", 9.9),
      ("000010", 9.8),
      ("000011", 9.5),
      ("000020", 9.5),
      ("000021", 9.2),
      ("000100", 10.0),
      ("000101", 9.6),
      ("000110", 9.3),
      ("000111", 8.7),
      ("000120", 9.1),
      ("000121", 8.1),
      ("000200", 9.3),
      ("000201", 9.0),
      ("000210", 8.9),
      ("000211", 8.0),
      ("000220", 8.1),
      ("000221", 6.8),
      ("001000", 9.8),
      ("001001", 9.5),
      ("001010", 9.5),
      ("001011", 9.2),
      ("001020", 9.0),
      ("001021", 8.4),
      ("001100", 9.3),
      ("001101", 9.2),
      ("001110", 8.9),
      ("001111", 8.1),
      ("001120", 8.1),
      ("001121", 6.5),
      ("001200", 8.8),
      ("001201", 8.0),
      ("001210", 7.8),
      ("001211", 7.0),
      ("001220", 6.9),
      ("001221", 4.8),
      ("002001", 9.2),
      ("002011", 8.2),
      ("002021", 7.2),
      ("002101", 7.9),
      ("002111", 6.9),
      ("002121", 5.0),
      ("002201", 6.9),
      ("002211", 5.5),
      ("002221", 2.7),
      ("010000", 9.9),
      ("010001", 9.7),
      ("010010", 9.5),
      ("010011", 9.2),
      ("010020", 9.2),
      ("010021", 8.5),
      ("010100", 9.5),
      ("010101", 9.1),
      ("010110", 9.0),
      ("010111", 8.3),
      ("010120", 8.4),
      ("010121", 7.1),
      ("010200", 9.2),
      ("010201", 8.1),
      ("010210", 8.2),
      ("010211", 7.1),
      ("010220", 7.2),
      ("010221", 5.3),
      ("011000", 9.5),
      ("011001", 9.3),
      ("011010", 9.2),
      ("011011", 8.5),
      ("011020", 8.5),
      ("011021", 7.3),
      ("011100", 9.2),
      ("011101", 8.2),
      ("011110", 8.0),
      ("011111", 7.2),
      ("011120", 7.0),
      ("011121", 5.9),
      ("011200", 8.4),
      ("011201", 7.0),
      ("011210", 7.1),
      ("011211", 5.2),
      ("011220", 5.0),
      ("011221", 3.0),
      ("012001", 8.6),
      ("012011", 7.5),
      ("012021", 5.2),
      ("012101", 7.1),
      ("012111", 5.2),
      ("012121", 2.9),
      ("012201", 6.3),
      ("012211", 2.9),
      ("012221", 1.7),
      ("100000", 9.8),
      ("100001", 9.5),
      ("100010", 9.4),
      ("100011", 8.7),
      ("100020", 9.1),
      ("100021", 8.1),
      ("100100", 9.4),
      ("100101", 8.9),
      ("100110", 8.6),
      ("100111", 7.4),
      ("100120", 7.7),
      ("100121", 6.4),
      ("100200", 8.7),
      ("100201", 7.5),
      ("100210", 7.4),
      ("100211", 6.3),
      ("100220", 6.3),
      ("100221", 4.9),
      ("101000", 9.4),
      ("101001", 8.9),
      ("101010", 8.8),
      ("101011", 7.7),
      ("101020", 7.6),
      ("101021", 6.7),
      ("101100", 8.6),
      ("101101", 7.6),
      ("101110", 7.4),
      ("101111", 5.8),
      ("101120", 5.9),
      ("101121", 5.0),
      ("101200", 7.2),
      ("101201", 5.7),
      ("101210", 5.7),
      ("101211", 5.2),
      ("101220", 5.2),
      ("101221", 2.5),
      ("102001", 8.3),
      ("102011", 7.0),
      ("102021", 5.4),
      ("102101", 6.5),
      ("102111", 5.8),
      ("102121", 2.6),
      ("102201", 5.3),
      ("102211", 2.1),
      ("102221", 1.3),
      ("110000", 9.5),
      ("110001", 9.0),
      ("110010", 8.8),
      ("110011", 7.6),
      ("110020", 7.6),
      ("110021", 7.0),
      ("110100", 9.0),
      ("110101", 7.7),
      ("110110", 7.5),
      ("110111", 6.2),
      ("110120", 6.1),
      ("110121", 5.3),
      ("110200", 7.7),
      ("110201", 6.6),
      ("110210", 6.8),
      ("110211", 5.9),
      ("110220", 5.2),
      ("110221", 3.0),
      ("111000", 8.9),
      ("111001", 7.8),
      ("111010", 7.6),
      ("111011", 6.7),
      ("111020", 6.2),
      ("111021", 5.8),
      ("111100", 7.4),
      ("111101", 5.9),
      ("111110", 5.7),
      ("111111", 5.7),
      ("111120", 4.7),
      ("111121", 2.3),
      ("111200", 6.1),
      ("111201", 5.2),
      ("111210", 5.7),
      ("111211", 2.9),
      ("111220", 2.4),
      ("111221", 1.6),
      ("112001", 7.1),
      ("112011", 5.9),
      ("112021", 3.0),
      ("112101", 5.8),
      ("112111", 2.6),
      ("112121", 1.5),
      ("112201", 2.3),
      ("112211", 1.3),
      ("112221", 0.6),
      ("200000", 9.3),
      ("200001", 8.7),
      ("200010", 8.6),
      ("200011", 7.2),
      ("200020", 7.5),
      ("200021", 5.8),
      ("200100", 8.6),
      ("200101", 7.4),
      ("200110", 7.4),
      ("200111", 6.1),
      ("200120", 5.6),
      ("200121", 3.4),
      ("200200", 7.0),
      ("200201", 5.4),
      ("200210", 5.2),
      ("200211", 4.0),
      ("200220", 4.0),
      ("200221", 2.2),
      ("201000", 8.5),
      ("201001", 7.5),
      ("201010", 7.4),
      ("201011", 5.5),
      ("201020", 6.2),
      ("201021", 5.1),
      ("201100", 7.2),
      ("201101", 5.7),
      ("201110", 5.5),
      ("201111", 4.1),
      ("201120", 4.6),
      ("201121", 1.9),
      ("201200", 5.3),
      ("201201", 3.6),
      ("201210", 3.4),
      ("201211", 1.9),
      ("201220", 1.9),
      ("201221", 0.8),
      ("202001", 6.4),
      ("202011", 5.1),
      ("202021", 2.0),
      ("202101", 4.7),
      ("202111", 2.1),
      ("202121", 1.1),
      ("202201", 2.4),
      ("202211", 0.9),
      ("202221", 0.4),
      ("210000", 8.8),
      ("210001", 7.5),
      ("210010", 7.3),
      ("210011", 5.3),
      ("210020", 6.0),
      ("210021", 5.0),
      ("210100", 7.3),
      ("210101", 5.5),
      ("210110", 5.9),
      ("210111", 4.0),
      ("210120", 4.1),
      ("210121", 2.0),
      ("210200", 5.4),
      ("210201", 4.3),
      ("210210", 4.5),
      ("210211", 2.2),
      ("210220", 2.0),
      ("210221", 1.1),
      ("211000", 7.5),
      ("211001", 5.5),
      ("211010", 5.8),
      ("211011", 4.5),
      ("211020", 4.0),
      ("211021", 2.1),
      ("211100", 6.1),
      ("211101", 5.1),
      ("211110", 4.8),
      ("211111", 1.8),
      ("211120", 2.0),
      ("211121", 0.9),
      ("211200", 4.6),
      ("211201", 1.8),
      ("211210", 1.7),
      ("211211", 0.7),
      ("211220", 0.8),
      ("211221", 0.2),
      ("212001", 5.3),
      ("212011", 2.4),
      ("212021", 1.4),
      ("212101", 2.4),
      ("212111", 1.2),
      ("212121", 0.5),
      ("212201", 1.0),
      ("212211", 0.3),
      ("212221", 0.1)
    ]

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
