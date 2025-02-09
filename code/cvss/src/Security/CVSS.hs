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

import Control.Applicative ( Alternative((<|>)) ) 
import Data.Coerce (coerce)
import Data.Foldable (traverse_)
import Data.List (find, group, sort)
import Data.Maybe (mapMaybe, fromMaybe)
import Data.String (IsString)
import Data.Text (Text)
import Data.Text qualified as Text
import GHC.Float (powerFloat)
import Security.V4_0.CVSS40Lookup (lookupScore, maxComposed, maxComposedEQ3, maxSeverity, maxSeverityeq3eq6)
import qualified Data.Map as Map
import Data.Either (rights)

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
  deriving (Eq)

-- | Parsed CVSS string obtained with 'parseCVSS'.
data CVSS = CVSS
  { -- | The CVSS Version.
    cvssVersion :: CVSSVersion,
    -- | The metrics are stored as provided by the user
    cvssMetrics :: [Metric]
  }
  deriving stock (Eq)

data CVSSScore = Zero | One | Two deriving (Show)

toText :: MetricShortName -> Text
toText (MetricShortName t) = t

defaultMetricValue :: MetricShortName -> Maybe MetricValueKey
defaultMetricValue metricValue =
  let isXValue = elem metricValue ["MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MSC", "MSA", "MSI", "S", "AU", "R", "V", "RE", "U"]
      isAValue = elem metricValue ["E"]
      isHValue = elem metricValue ["CR", "IR", "AR"] in
        if isXValue then Just $ C 'X' else
          if isAValue then Just $ C 'A' else
            if isHValue then Just $ C 'H' else Nothing


getCvssMetric :: [Metric] -> MetricShortName -> Maybe Metric
getCvssMetric metrics shortName = find (\c -> mName c == shortName) metrics

getCvssMetricChar :: [Metric] -> MetricShortName -> Maybe MetricValueKey
getCvssMetricChar metrics shortName = case getCvssMetric metrics shortName of
                Just c -> Just $ mChar c
                Nothing -> Nothing

getCvssMetricCharOverriden :: [Metric] -> MetricShortName -> Maybe MetricValueKey
getCvssMetricCharOverriden metrics shortName =
  let
    overridingName = MetricShortName (Text.pack $ "M" <> Text.unpack (toText shortName))
    overridingMetricChar = getCvssMetricChar metrics overridingName
    metricChar = getCvssMetricChar metrics shortName
    defaultMetricChar = defaultMetricValue shortName in
      overridingMetricChar <|> metricChar <|> defaultMetricChar

getCvssMetricV :: CVSSDB -> [Metric] -> MetricShortName -> Float
getCvssMetricV db metrics shortName =
  let metricChar = getCvssMetricCharOverriden metrics shortName in
    case metricChar of
          Just c -> let v = concatMap miValues (filter (\m -> miShortName m == shortName) $ allMetrics db) in
                        case find (\mv -> mvChar mv == c) v of
                          Just metricValue -> mvNum metricValue
                          Nothing -> 0.0
          Nothing -> 0.0


hasCvssMetricWithValueR :: [Metric] -> MetricShortName -> MetricValueKey -> Bool
hasCvssMetricWithValueR metrics shortName mchar =
    case getCvssMetricCharOverriden metrics shortName of
      Just c -> c == mchar
      Nothing -> False

castCVSSScoreToInt :: CVSSScore -> Int
castCVSSScoreToInt Zero = 0
castCVSSScoreToInt One  = 1
castCVSSScoreToInt Two  = 2

calcEq1 :: [Metric] -> CVSSScore
calcEq1 metrics =
  let hasC = hasCvssMetricWithValueR metrics in
  if hasC "AV" (C 'N') && hasC "PR" (C 'N') && hasC "UI" (C 'N') then Zero else
    (if (hasC "AV" (C 'N') || hasC "PR" (C 'N') || hasC "UI" (C 'N')) &&
      not (hasC "AV" (C 'N') && hasC "PR" (C 'N') && hasC "UI" (C 'N')) &&
      not (hasC "AV" (C 'P')) then One else Two)--(if hasC "AV" (C 'P') || not (hasC "AV" (C 'N') || hasC "PR" (C 'N') || hasC "UI" (C 'N')) then Two else error "blabla EQ1"))

calcEq2 :: [Metric] -> CVSSScore
calcEq2 metrics =
  let hasC = hasCvssMetricWithValueR metrics in
    if hasC "AC" (C 'L') && hasC "AT" (C 'N') then Zero else One

calcEq3 :: [Metric] -> CVSSScore
calcEq3 metrics =
  let hasC = hasCvssMetricWithValueR metrics in
    if hasC "VC" (C 'H') && hasC "VI" (C 'H') then Zero else
      if hasC "VC" (C 'H') || hasC "VI" (C 'H') || hasC "VA" (C 'H') then One else Two

calcEq4 :: [Metric] -> CVSSScore
calcEq4 metrics =
  let hasC = hasCvssMetricWithValueR metrics in
    if hasC "MSI" (C 'S') || hasC "MSA" (C 'S') then Zero else
      if hasC "SC" (C 'H') || hasC "SI" (C 'H') || hasC "SA" (C 'H') then One else Two


calcEq5 :: [Metric] -> CVSSScore
calcEq5 metrics =
  let hasC = hasCvssMetricWithValueR metrics in
    if hasC "E" (C 'A') then Zero else
      if hasC "E" (C 'P') then One else
        if hasC "E" (C 'U') then Two else Zero

calcEq6 :: [Metric] -> CVSSScore
calcEq6 metrics =
  let hasC = hasCvssMetricWithValueR metrics in
    if (hasC "CR" (C 'H') && hasC "VC" (C 'H'))
      || (hasC "IR" (C 'H') && hasC "VI" (C 'H'))
      || (hasC "AR" (C 'H') && hasC "VA" (C 'H')) then Zero else
        if not ((hasC "CR" (C 'H') && hasC "VC" (C 'H'))
          || (hasC "IR" (C 'H') && hasC "VI" (C 'H'))
          || (hasC "AR" (C 'H') && hasC "VA" (C 'H'))) then One else
            -- if hasC "CR" (C 'X') || hasC "IR" (C 'X') || hasC "AR" (C 'X') then Zero else 
              Zero


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
  | UnknownValue Text MetricValueKey

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

data MetricValueKey = MetricValueKey Char String
  deriving stock (Eq, Ord, Show)

data Metric = Metric
  { mName :: MetricShortName,
    mChar :: MetricValueKey
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
    splitComponent componentTxt
      | Text.null componentTxt = Left EmptyComponent
      | otherwise = 
          let (name, valueWithColon) = Text.breakOn ":" componentTxt
              value = Text.drop 1 valueWithColon
          in if Text.null value
            then Left (MissingValue componentTxt)
            else Right (Metric (MetricShortName name) (S (Text.head value) (Text.unpack $ Text.tail value)))

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
    toComponent (Metric (MetricShortName name) (MetricValueKey c value)) = (name <> ":") <> Text.cons c (Text.pack value)
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
    mvChar :: MetricValueKey,
    mvNum :: Float,
    mvNumChangedScope :: Maybe Float,
    mvDesc :: Text
  }

-- | CVSS4.0 metrics pulled from the specification https://www.first.org/cvss/v4.0/specification-document
cvss40 :: CVSSDB
cvss40 =
  CVSSDB
    [ MetricGroup "Base" baseMetrics,
      MetricGroup "Threat" threatMetrics,
      MetricGroup "Environmental" environmentalMetrics,
      MetricGroup "Supplemental" supplementalMetrics
    ]
  where
    baseMetrics = [ MetricInfo
        "Attack Vector"
        "AV"
        True
        [MetricValue "Network" (C 'N') 0.0 Nothing "The vulnerable system is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers)."
        ,MetricValue "Adjacent" (C 'A') 0.1 Nothing "The vulnerable system is bound to a protocol stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared proximity (e.g., Bluetooth, NFC, or IEEE 802.11) or logical network (e.g., local IP subnet), or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN within an administrative network zone)."
        ,MetricValue "Local" (C 'L') 0.2 Nothing "The vulnerable system is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or through terminal emulation (e.g., SSH); or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document)."
        ,MetricValue "Physical" (C 'P') 0.3 Nothing "The attack requires the attacker to physically touch or manipulate the vulnerable system. Physical interaction may be brief (e.g., evil maid attack) or persistent."]
      ,MetricInfo
        "Attack Complexity"
        "AC"
        True
        [MetricValue "Low" (C 'L') 0.0 Nothing "The attacker must take no measurable action to exploit the vulnerability. The attack requires no target-specific circumvention to exploit the vulnerability. An attacker can expect repeatable success against the vulnerable system."
        ,MetricValue "High" (C 'H') 0.1 Nothing "The successful attack depends on the evasion or circumvention of security-enhancing techniques in place that would otherwise hinder the attack. These include: Evasion of exploit mitigation techniques, for example, circumvention of address space randomization (ASLR) or data execution prevention (DEP) must be performed for the attack to be successful; Obtaining target-specific secrets. The attacker must gather some target-specific secret before the attack can be successful. A secret is any piece of information that cannot be obtained through any amount of reconnaissance. To obtain the secret the attacker must perform additional attacks or break otherwise secure measures (e.g. knowledge of a secret key may be needed to break a crypto channel). This operation must be performed for each attacked target."]
      ,MetricInfo
        "Attack Requirements"
        "AT"
        True
        [MetricValue "None" (C 'N') 0.0 Nothing "The successful attack does not depend on the deployment and execution conditions of the vulnerable system. The attacker can expect to be able to reach the vulnerability and execute the exploit under all or most instances of the vulnerability."
          ,MetricValue "Present" (C 'P') 0.1 Nothing "The successful attack depends on the presence of specific deployment and execution conditions of the vulnerable system that enable the attack. These include: a race condition must be won to successfully exploit the vulnerability (the successfulness of the attack is conditioned on execution conditions that are not under full control of the attacker, or the attack may need to be launched multiple times against a single target before being successful); the attacker must inject themselves into the logical network path between the target and the resource requested by the victim (e.g. vulnerabilities requiring an on-path attacker)."]
      ,MetricInfo
        "Privileges Required"
        "PR"
        True
        [MetricValue "None" (C 'N') 0.0 Nothing "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack."
          ,MetricValue "Low" (C 'L') 0.1 Nothing "The attacker requires privileges that provide basic capabilities that are typically limited to settings and resources owned by a single low-privileged user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources."
          ,MetricValue "High" (C 'H') 0.2 Nothing "The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable system allowing full access to the vulnerable system’s settings and files."]
      ,MetricInfo
        "User Interaction"
        "UI"
        True
        [MetricValue "None" (C 'N') 0.0 Nothing "The vulnerable system can be exploited without interaction from any human user, other than the attacker."
          ,MetricValue "Passive" (C 'P') 0.1 Nothing "Successful exploitation of this vulnerability requires limited interaction by the targeted user with the vulnerable system and the attacker’s payload. These interactions would be considered involuntary and do not require that the user actively subvert protections built into the vulnerable system."
          ,MetricValue "Active" (C 'A') 0.2 Nothing "Successful exploitation of this vulnerability requires a targeted user to perform specific, conscious interactions with the vulnerable system and the attacker’s payload, or the user’s interactions would actively subvert protection mechanisms which would lead to exploitation of the vulnerability."]
      ,MetricInfo
        "Confidentiality"
        "VC"
        True
        [MetricValue "High" (C 'H') 0.0 Nothing "There is a total loss of confidentiality, resulting in all information within the Vulnerable System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server."
          ,MetricValue "Low" (C 'L') 0.1 Nothing "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Vulnerable System."
          ,MetricValue "None" (C 'N') 0.2 Nothing "There is no loss of confidentiality within the Vulnerable System."]
      ,MetricInfo
        "Integrity"
        "VI"
        True
        [MetricValue "High" (C 'H') 0.0 Nothing "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the vulnerable system. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the vulnerable system."
          ,MetricValue "Low" (C 'L') 0.1 Nothing "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Vulnerable System."
          ,MetricValue "None" (C 'N') 0.2 Nothing "There is no loss of integrity within the Vulnerable System."]
      ,MetricInfo
        "Availability"
        "VA"
        True
        [MetricValue "High" (C 'H') 0.0 Nothing "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Vulnerable System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Vulnerable System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable)."
          ,MetricValue "Low" (C 'L') 0.1 Nothing "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Vulnerable System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Vulnerable System."
          ,MetricValue "None" (C 'N') 0.2 Nothing "There is no impact to availability within the Vulnerable System."]
      ,MetricInfo
        "Confidentiality"
        "SC"
        True
        [MetricValue "High" (C 'H') 0.1 Nothing "There is a total loss of confidentiality, resulting in all resources within the Subsequent System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server."
          ,MetricValue "Low" (C 'L') 0.2 Nothing "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Subsequent System."
          ,MetricValue "None" (C 'N') 0.3 Nothing "There is no loss of confidentiality within the Subsequent System or all confidentiality impact is constrained to the Vulnerable System."]
      ,MetricInfo
        "Integrity"
        "SI"
        True
        [MetricValue "High" (C 'H') 0.1 Nothing "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the Subsequent System. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the Subsequent System."
          ,MetricValue "Low" (C 'L') 0.2 Nothing "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Subsequent System."
          ,MetricValue "None" (C 'N') 0.3 Nothing "There is no loss of integrity within the Subsequent System or all integrity impact is constrained to the Vulnerable System."]
      ,MetricInfo
        "Availability"
        "SA"
        True
        [MetricValue "High" (C 'H') 0.1 Nothing "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Subsequent System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Subsequent System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable)."
          ,MetricValue "Low" (C 'L') 0.2 Nothing "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Subsequent System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Subsequent System."
          ,MetricValue "None" (C 'N') 0.3 Nothing "There is no impact to availability within the Subsequent System or all availability impact is constrained to the Vulnerable System."]
      ]
    threatMetrics = [MetricInfo
        "Exploit Maturity"
        "E"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The Exploit Maturity metric is not being used.  Reliable threat intelligence is not available to determine Exploit Maturity characteristics."
          ,MetricValue "Attacked" (C 'A') 0.0 Nothing "Based on threat intelligence sources either of the following must apply: Attacks targeting this vulnerability (attempted or successful) have been reported Solutions to simplify attempts to exploit the vulnerability are publicly or privately available (such as exploit toolkits)"
          ,MetricValue "POC" (C 'P') 0.1 Nothing "Based on threat intelligence sources each of the following must apply: Proof-of-concept is publicly available No knowledge of reported attempts to exploit this vulnerability No knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability"
          ,MetricValue "Unreported" (C 'U') 0.2 Nothing "Based on threat intelligence sources each of the following must apply: No knowledge of publicly available proof-of-concept No knowledge of reported attempts to exploit this vulnerability No knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability"]
      ]
    environmentalMetrics = [MetricInfo
        "Attack Vector"
        "MAV"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "Network" (C 'N') 0.0 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Adjacent" (C 'A') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Local" (C 'L') 0.2 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Physical" (C 'P') 0.3 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Attack Complexity"
        "MAC"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "Low" (C 'L') 0.0 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "High" (C 'H') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Attack Requirements"
        "MAT"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "None" (C 'N') 0.0 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Present" (C 'P') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Privileges Required"
        "MPR"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "None" (C 'N') 0.0 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Low" (C 'L') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "High" (C 'H') 0.2 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "User Interaction"
        "MUI"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "None" (C 'N') 0.0 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Passive" (C 'P') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Active" (C 'A') 0.2 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Confidentiality"
        "MVC"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "High" (C 'H') 0.0 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Low" (C 'L') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "None" (C 'N') 0.2 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Integrity"
        "MVI"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "High" (C 'H') 0.0 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Low" (C 'L') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "None" (C 'N') 0.2 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Availability"
        "MVA"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "High" (C 'H') 0.0 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Low" (C 'L') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "None" (C 'N') 0.2 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Confidentiality"
        "MSC"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "High" (C 'H') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Low" (C 'L') 0.2 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Negligible" (C 'N') 0.3 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Integrity"
        "MSI"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "Safety" (C 'S') 0.0 Nothing "The exploited vulnerability will result in integrity impacts that could cause serious injury or worse (categories of \"Marginal\" or worse as described in IEC 61508) to a human actor or participant."
          ,MetricValue "High" (C 'H') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Low" (C 'L') 0.2 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Negligible" (C 'N') 0.3 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Availability"
        "MSA"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "Safety" (C 'S') 0.0 Nothing "The exploited vulnerability will result in availability impacts that could cause serious injury or worse (categories of \"Marginal\" or worse as described in IEC 61508) to a human actor or participant."
          ,MetricValue "High" (C 'H') 0.1 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Low" (C 'L') 0.2 Nothing "This metric values has the same definition as the Base Metric value defined above."
          ,MetricValue "Negligible" (C 'N') 0.3 Nothing "This metric values has the same definition as the Base Metric value defined above."]
      ,MetricInfo
        "Confidentiality Requirements"
        "CR"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score"
          ,MetricValue "High" (C 'H') 0.0 Nothing "Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization."
          ,MetricValue "Medium" (C 'M') 0.1 Nothing "Loss of Confidentiality is likely to have a serious adverse effect on the organization or individuals associated with the organization."
          ,MetricValue "Low" (C 'L') 0.2 Nothing "Loss of Confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization."]
      ,MetricInfo
        "Integrity Requirements"
        "IR"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score"
          ,MetricValue "High" (C 'H') 0.0 Nothing "Loss of Integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization."
          ,MetricValue "Medium" (C 'M') 0.1 Nothing "Loss of Integrity is likely to have a serious adverse effect on the organization or individuals associated with the organization."
          ,MetricValue "Low" (C 'L') 0.2 Nothing "Loss of Integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization."]
      ,MetricInfo
        "Availability Requirements"
        "AR"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score"
          ,MetricValue "High" (C 'H') 0.0 Nothing "Loss of Availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization."
          ,MetricValue "Medium" (C 'M') 0.1 Nothing "Loss of Availability is likely to have a serious adverse effect on the organization or individuals associated with the organization."
          ,MetricValue "Low" (C 'L') 0.2 Nothing "Loss of Availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization."]
      ]
    supplementalMetrics = [MetricInfo
        "Safety"
        "S"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "Negligible" (C 'N') 0.0 Nothing "Consequences of the vulnerability meet definition of IEC 61508 consequence category \"negligible.\""
          ,MetricValue "Present" (C 'P') 0.0 Nothing "Consequences of the vulnerability meet definition of IEC 61508 consequence categories of \"marginal,\" \"critical,\" or \"catastrophic.\""]
      ,MetricInfo
        "Automatable"
        "AU"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "No" (C 'N') 0.0 Nothing "Attackers cannot reliably automate all 4 steps of the kill chain for this vulnerability for some reason. These steps are reconnaissance, weaponization, delivery, and exploitation."
          ,MetricValue "Yes" (C 'Y') 0.0 Nothing "Attackers can reliably automate all 4 steps of the kill chain. These steps are reconnaissance, weaponization, delivery, and exploitation (e.g., the vulnerability is “wormable”)."]
      ,MetricInfo
        "Recovery"
        "R"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "Automatic" (C 'A') 0.0 Nothing "The system recovers services automatically after an attack has been performed."
          ,MetricValue "User" (C 'U') 0.0 Nothing "The system requires manual intervention by the user to recover services, after an attack has been performed."
          ,MetricValue "Irrecoverable" (C 'I') 0.0 Nothing "The system services are irrecoverable by the user, after an attack has been performed."]
      ,MetricInfo
        "Value Density"
        "V"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "Diffuse" (C 'D') 0.0 Nothing "The vulnerable system has limited resources. That is, the resources that the attacker will gain control over with a single exploitation event are relatively small. An example of Diffuse (think: limited) Value Density would be an attack on a single email client vulnerability."
          ,MetricValue "Concentrated" (C 'C') 0.0 Nothing "The vulnerable system is rich in resources. Heuristically, such systems are often the direct responsibility of “system operators” rather than users. An example of Concentrated (think: broad) Value Density would be an attack on a central email server."]
      ,MetricInfo
        "Vulnerability Response Effort"
        "RE"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "Low" (C 'L') 0.0 Nothing "The effort required to respond to a vulnerability is low/trivial. Examples include: communication on better documentation, configuration workarounds, or guidance from the vendor that does not require an immediate update, upgrade, or replacement by the consuming entity, such as firewall filter configuration."
          ,MetricValue "Moderate" (C 'M') 0.0 Nothing "The actions required to respond to a vulnerability require some effort on behalf of the consumer and could cause minimal service impact to implement. Examples include: simple remote update, disabling of a subsystem, or a low-touch software upgrade such as a driver update."
          ,MetricValue "High" (C 'H') 0.0 Nothing "The actions required to respond to a vulnerability are significant and/or difficult, and may possibly lead to an extended, scheduled service impact.  This would need to be considered for scheduling purposes including honoring any embargo on deployment of the selected response. Alternatively, response to the vulnerability in the field is not possible remotely. The only resolution to the vulnerability involves physical replacement (e.g. units deployed would have to be recalled for a depot level repair or replacement). Examples include: a highly privileged driver update, microcode or UEFI BIOS updates, or software upgrades requiring careful analysis and understanding of any potential infrastructure impact before implementation. A UEFI BIOS update that impacts Trusted Platform Module (TPM) attestation without impacting disk encryption software such as Bit locker is a good recent example. Irreparable failures such as non-bootable flash subsystems, failed disks or solid-state drives (SSD), bad memory modules, network devices, or other non-recoverable under warranty hardware, should also be scored as having a High effort."]
      ,MetricInfo
        "Provider Urgency"
        "U"
        False
        [MetricValue "Not Defined" (C 'X') 0.0 Nothing "The metric has not been evaluated."
          ,MetricValue "Clear" (S 'C' "lear") 0.0 Nothing "Provider has assessed the impact of this vulnerability as having no urgency (Informational)."
          ,MetricValue "Green" (S 'G' "reen") 0.0 Nothing "Provider has assessed the impact of this vulnerability as having a reduced urgency."
          ,MetricValue "Amber" (S 'A' "mber") 0.0 Nothing "Provider has assessed the impact of this vulnerability as having a moderate urgency."
          ,MetricValue "Red" (S 'R' "ed") 0.0 Nothing "Provider has assessed the impact of this vulnerability as having the highest urgency." ]
      ]

validateCvss40 :: [Metric] -> Either CVSSError [Metric]
validateCvss40 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss40, validateRequired cvss40]
  pure metrics

cvss4macroVector :: [Metric] -> [Int]
cvss4macroVector metrics = map (\eq -> castCVSSScoreToInt $ eq metrics) [calcEq1, calcEq2, calcEq3, calcEq4, calcEq5, calcEq6]

calculateEq3Eq6NextLowerMacro :: Int -> Int -> Int -> Int -> Int -> Int -> Maybe Float
calculateEq3Eq6NextLowerMacro eq1 eq2 eq3 eq4 eq5 eq6 =
  if eq3 == 0 && eq6 == 0 then
    let eq3eq6_next_lower_macro_left = [eq1, eq2, eq3, eq4, eq5, eq6 + 1]
        eq3eq6_next_lower_macro_right = [eq1, eq2, eq3 + 1, eq4, eq5, eq6]
        score_eq3eq6_next_lower_macro_left = Map.lookup eq3eq6_next_lower_macro_left lookupScore
        score_eq3eq6_next_lower_macro_right =  Map.lookup  eq3eq6_next_lower_macro_right lookupScore in
          max score_eq3eq6_next_lower_macro_left score_eq3eq6_next_lower_macro_right
  else
    Map.lookup eq3eq6_next_lower_macro lookupScore where
      eq3eq6_next_lower_macro
        | eq3 == 1 && eq6 == 1 = [eq1, eq2, eq3 + 1, eq4, eq5, eq6]
        | eq3 == 0 && eq6 == 1 = [eq1, eq2, eq3 + 1, eq4, eq5, eq6]
        | eq3 == 1 && eq6 == 0 = [eq1, eq2, eq3, eq4, eq5, eq6 + 1]
        | otherwise = [eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1]


calcMaxVectors :: Int -> Int -> Int -> Int -> Int -> Int -> [Text]
calcMaxVectors eq1 eq2 eq3 eq4 eq5 eq6 =
 let eq1_maxes = maxComposed !! 0 !! eq1
     eq2_maxes = maxComposed !! 1 !! eq2
     eq3_eq6_maxes = maxComposedEQ3 !! eq3 !! eq6
     eq4_maxes = maxComposed !! 3 !! eq4
     eq5_maxes = maxComposed !! 4 !! eq5 in
      [eq1_max <> eq2_max <> eq3_eq6_max <> eq4_max <> eq5_max |
        eq1_max <- eq1_maxes,
        eq2_max <- eq2_maxes,
        eq3_eq6_max <- eq3_eq6_maxes,
        eq4_max <- eq4_maxes,
        eq5_max <- eq5_maxes]


-- | Parse a CVSS string.
parseMaxVectors :: Text -> Either CVSSError CVSS
parseMaxVectors txt = CVSS CVSS40 <$> parseMetrics
  where
    parseMetrics = traverse splitComponent components

    components = init $ Text.split (== '/') txt
    splitComponent :: Text -> Either CVSSError Metric
    splitComponent componentTxt = case Text.unsnoc componentTxt of
      Nothing -> Left EmptyComponent
      Just (rest, c) -> case Text.unsnoc rest of
        Just (name, ':') -> Right (Metric (MetricShortName name) (C c))
        _ -> Left (MissingValue componentTxt)

calcSeverities :: [Metric] -> [Text] -> [Float]
calcSeverities metrics maxVectors =
  let calculatedSeverities = map calcMaxVectorSeverities parsedMaxVectors in
    case find (all (>= 0.0)) calculatedSeverities of
      Just [ severityDistanceAV, severityDistancePR, severityDistanceUI, severityDistanceAC, severityDistanceAT
             , severityDistanceVC, severityDistanceVI, severityDistanceVA, severityDistanceSC, severityDistanceSI
             , severityDistanceSA, severityDistanceCR, severityDistanceIR, severityDistanceAR ] ->
        [ severityDistanceAV + severityDistancePR + severityDistanceUI
          , severityDistanceAC + severityDistanceAT
          , severityDistanceVC + severityDistanceVI + severityDistanceVA + severityDistanceCR + severityDistanceIR + severityDistanceAR
          , severityDistanceSC + severityDistanceSI + severityDistanceSA
          , 0
          ]
      Nothing -> [0, 0, 0, 0, 0]
    where
      gm :: [Metric] -> MetricShortName -> Float
      gm = getCvssMetricV cvss40
      pMaxVectors = map parseMaxVectors maxVectors
      parsedMaxVectors = rights pMaxVectors
      calcMaxVectorSeverities maxVector =
        let
          severityDistanceAV = gm metrics "AV" - gm (cvssMetrics maxVector) "AV"
          severityDistancePR = gm metrics "PR" - gm (cvssMetrics maxVector) "PR"
          severityDistanceUI = gm metrics "UI" - gm (cvssMetrics maxVector) "UI"
          severityDistanceAC = gm metrics "AC" - gm (cvssMetrics maxVector) "AC"
          severityDistanceAT = gm metrics "AT" - gm (cvssMetrics maxVector) "AT"
          severityDistanceVC = gm metrics "VC" - gm (cvssMetrics maxVector) "VC"
          severityDistanceVI = gm metrics "VI" - gm (cvssMetrics maxVector) "VI"
          severityDistanceVA = gm metrics "VA" - gm (cvssMetrics maxVector) "VA"
          severityDistanceSC = gm metrics "SC" - gm (cvssMetrics maxVector) "SC"
          severityDistanceSI = gm metrics "SI" - gm (cvssMetrics maxVector) "SI"
          severityDistanceSA = gm metrics "SA" - gm (cvssMetrics maxVector) "SA"
          severityDistanceCR = gm metrics "CR" - gm (cvssMetrics maxVector) "CR"
          severityDistanceIR = gm metrics "IR" - gm (cvssMetrics maxVector) "IR"
          severityDistanceAR = gm metrics "AR" - gm (cvssMetrics maxVector) "AR"
        in [ severityDistanceAV, severityDistancePR, severityDistanceUI, severityDistanceAC, severityDistanceAT
              , severityDistanceVC, severityDistanceVI, severityDistanceVA, severityDistanceSC, severityDistanceSI
              , severityDistanceSA, severityDistanceCR, severityDistanceIR, severityDistanceAR ]

calcMeanDistance :: Maybe Float -> [Maybe Float] -> [Int] -> [Float] -> Int -> Float
calcMeanDistance Nothing _ _ _ _ = 0
calcMeanDistance (Just value) nextLowerMacro macroVector currentSeverities eq6 =
  if nExistingLower == 0.0 then 0.0 else sum normalizedSeverities / nExistingLower where
    normalizedSeverities = zipWith calcNormalizedSeverity [0..] [0, 0, 0, 0, 0]
    nExistingLower :: Float
    nExistingLower = sum (zipWith (\i _ -> case nextLowerMacro !! i of
                                Just _ -> 1
                                Nothing -> 0) [0..] [0 :: Integer, 0, 0, 0, 0])
    calcNormalizedSeverity :: Int -> Int -> Float
    calcNormalizedSeverity i _ =
      case nextLowerMacro !! i of
        Just nextLowerMacroValue ->
          if i == 4 then 0 else
            let availableDistanceEqi = value - nextLowerMacroValue
                eqi = macroVector !! i
                localMaxSeverity = (if i /= 2 then maxSeverity !! i !! eqi else maxSeverityeq3eq6 !! eqi !! eq6) * 0.1
                percentToNextEqiSeverity :: Float
                percentToNextEqiSeverity = currentSeverities !! i / localMaxSeverity in
              availableDistanceEqi * percentToNextEqiSeverity
        Nothing -> 0

cvss40score :: [Metric] -> (Rating, Float)
cvss40score metrics = (toRating score, score)
  where score =
          let hasC metricName = hasCvssMetricWithValueR metrics metricName (C 'N')
              shortcut = if hasC "VC" && hasC "VI" && hasC "VA" && hasC "SC" && hasC "SI" && hasC "SA" then Just (0.0 :: Float) else Nothing
              macroVector = cvss4macroVector metrics
              eq1 = macroVector !! 0
              eq2 = macroVector !! 1
              eq3 = macroVector !! 2
              eq4 = macroVector !! 3
              eq5 = macroVector !! 4
              eq6 = macroVector !! 5
              nextLowerMacro :: [Maybe Float]
              nextLowerMacro = [
                  Map.lookup [eq1 + 1, eq2, eq3, eq4, eq5, eq6] lookupScore
                , Map.lookup [eq1, eq2 + 1, eq3, eq4, eq5, eq6] lookupScore
                , calculateEq3Eq6NextLowerMacro eq1 eq2 eq3 eq4 eq5 eq6
                , Map.lookup [eq1, eq2, eq3, eq4 + 1, eq5, eq6] lookupScore
                , Map.lookup [eq1, eq2, eq3, eq4, eq5 + 1, eq6] lookupScore
                ]
              maxVectors = calcMaxVectors eq1 eq2 eq3 eq4 eq5 eq6
              currentSeverities = calcSeverities metrics maxVectors
              lookedUpValue = Map.lookup macroVector lookupScore
              meanDistance = calcMeanDistance lookedUpValue nextLowerMacro macroVector currentSeverities eq6
              unboxedLookedUpValue = fromMaybe 0.0 lookedUpValue
              resultValue = unboxedLookedUpValue - meanDistance in
                case shortcut of
                  Just r -> r
                  Nothing -> if resultValue < 0 then 0.0 else if resultValue > 10 then 10.0 else fromIntegral (round (resultValue * 10)) / 10

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

pattern C :: Char -> MetricValueKey
pattern C c = MetricValueKey c ""


pattern S :: Char -> String -> MetricValueKey
pattern S c s = MetricValueKey c s

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
        Nothing -> Left (UnknownValue (coerce name) char)
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
