{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}

module Security.CVSS.V40
  ( cvss40DB,
    validateCvss40,
    cvss40score,
    cvss40BaseScore,
    cvss40ThreatScore,
    cvss40EnvironmentalScore,
  )
where

import Data.Coerce (coerce)
import Data.Foldable (traverse_)
import Data.List (find)
import Data.Map qualified as Map
import Data.Text (Text)
import Data.Text qualified as Text
import Security.CVSS.Internal
import Security.CVSS.Types

data EQLevel = EQ0 | EQ1 | EQ2
  deriving (Eq, Ord, Show, Enum, Bounded)

data MacroVector = MacroVector
  { mvEQ1 :: EQLevel,
    mvEQ2 :: EQLevel,
    mvEQ3 :: EQLevel,
    mvEQ4 :: EQLevel,
    mvEQ5 :: EQLevel,
    mvEQ6 :: EQLevel
  }
  deriving (Eq, Ord, Show)

newtype Severity = Severity Float
  deriving newtype (Eq, Ord, Num, Fractional, Real, RealFrac)

instance Show Severity where
  show (Severity f) = show f

data EQ1Result = EQ1Result
  { eq1Level :: EQLevel,
    eq1AV :: Severity,
    eq1PR :: Severity,
    eq1UI :: Severity
  }
  deriving (Eq, Show)

data EQ2Result = EQ2Result
  { eq2Level :: EQLevel,
    eq2AC :: Severity,
    eq2AT :: Severity
  }
  deriving (Eq, Show)

data EQ3Result = EQ3Result
  { eq3Level :: EQLevel,
    eq3VC :: Severity,
    eq3VI :: Severity,
    eq3VA :: Severity
  }
  deriving (Eq, Show)

data EQ4Result = EQ4Result
  { eq4Level :: EQLevel,
    eq4SC :: Severity,
    eq4SI :: Severity,
    eq4SA :: Severity
  }
  deriving (Eq, Show)

data EQ5Result = EQ5Result
  { eq5Level :: EQLevel,
    eq5E :: Severity
  }
  deriving (Eq, Show)

data EQ6Result = EQ6Result
  { eq6Level :: EQLevel,
    eq6CR :: Severity,
    eq6IR :: Severity,
    eq6AR :: Severity
  }
  deriving (Eq, Show)

type MaxComposedEQ1 = [(Severity, Severity, Severity)]

type MaxComposedEQ2 = [(Severity, Severity, Severity)]

type MaxComposedEQ3EQ6 = [(Severity, Severity, Severity, Severity, Severity, Severity)]

type MaxComposedEQ4 = [(Severity, Severity, Severity)]

data CVSS40_AV = AV_Network | AV_Adjacent | AV_Local | AV_Physical
  deriving (Eq, Show, Enum, Bounded)

data CVSS40_PR = PR_None | PR_Low | PR_High
  deriving (Eq, Show, Enum, Bounded)

data CVSS40_UI = UI_None | UI_Passive | UI_Active
  deriving (Eq, Show, Enum, Bounded)

data CVSS40_AC = AC_Low | AC_High
  deriving (Eq, Show, Enum, Bounded)

data CVSS40_AT = AT_Absent | AT_Present
  deriving (Eq, Show, Enum, Bounded)

data CVSS40_ImpactValue = Impact_High | Impact_Low | Impact_None
  deriving (Eq, Show, Enum, Bounded)

data CVSS40_SubsequentImpactValue = SI_Safety | SI_High | SI_Low | SI_None
  deriving (Eq, Show, Enum, Bounded)

data CVSS40_SecurityReqValue = SR_High | SR_Medium | SR_Low
  deriving (Eq, Show, Enum, Bounded)

data CVSS40_ExploitMaturity = EM_Attacked | EM_PoC | EM_Unreported
  deriving (Eq, Show, Enum, Bounded)

pattern C :: Text -> MetricValueChar
pattern C c = MetricValueChar c

{-# COMPLETE C #-}

cvss40DB :: CVSSDB
cvss40DB =
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
    mkImpactSafety = MetricValue "Safety" (C "S") 0 Nothing "There is a predictable potential to cause injury categorized as Marginal or worse."
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
        MetricInfo "Modified Subsequent System Integrity Impact" "MSI" False $ [MetricValue "Not Defined" (C "X") 0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.", mkImpactSafety, mkImpactHigh "There is a total loss of integrity, or a complete loss of protection.", mkImpactLow "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited.", mkImpactNone "There is no loss of integrity within the Subsequent System."],
        MetricInfo "Modified Subsequent System Availability Impact" "MSA" False $ [MetricValue "Not Defined" (C "X") 0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.", mkImpactSafety, mkImpactHigh "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Subsequent System.", mkImpactLow "Performance is reduced or there are interruptions in resource availability.", mkImpactNone "There is no impact to availability within the Subsequent System."]
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
    mkThreatUndef = MetricValue "Not Defined" (C "X") 0 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values. According to the CVSS 4.0 specification, this is the default value and is equivalent to Attacked (A) for scoring purposes (assuming the worst case)."

validateCvss40 :: [Metric] -> Either CVSSError [Metric]
validateCvss40 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss40DB, validateRequired cvss40DB]
  pure metrics

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

getMetricValueChar40 :: [Metric] -> Text -> MetricValueChar
getMetricValueChar40 metrics name =
  case find (\metric -> mName metric == MetricShortName name) metrics of
    Nothing -> C "X"
    Just (Metric _ char) -> char

getChar40 :: [Metric] -> Text -> Char
getChar40 metrics name = case getMetricValueChar40 metrics name of
  C c -> Text.head c

parseAV :: Char -> CVSS40_AV
parseAV 'N' = AV_Network
parseAV 'A' = AV_Adjacent
parseAV 'L' = AV_Local
parseAV 'P' = AV_Physical
parseAV _ = AV_Physical

parsePR :: Char -> CVSS40_PR
parsePR 'N' = PR_None
parsePR 'L' = PR_Low
parsePR 'H' = PR_High
parsePR _ = PR_High

parseUI :: Char -> CVSS40_UI
parseUI 'N' = UI_None
parseUI 'P' = UI_Passive
parseUI 'A' = UI_Active
parseUI _ = UI_Active

parseAC :: Char -> CVSS40_AC
parseAC 'L' = AC_Low
parseAC 'H' = AC_High
parseAC _ = AC_High

parseAT :: Char -> CVSS40_AT
parseAT 'N' = AT_Absent
parseAT 'P' = AT_Present
parseAT _ = AT_Present

parseImpactValue :: Char -> CVSS40_ImpactValue
parseImpactValue 'H' = Impact_High
parseImpactValue 'L' = Impact_Low
parseImpactValue 'N' = Impact_None
parseImpactValue _ = Impact_None

parseSubsequentImpactValue :: Char -> CVSS40_SubsequentImpactValue
parseSubsequentImpactValue 'S' = SI_Safety
parseSubsequentImpactValue 'H' = SI_High
parseSubsequentImpactValue 'L' = SI_Low
parseSubsequentImpactValue 'N' = SI_None
parseSubsequentImpactValue _ = SI_None

parseSecurityReqValue :: Char -> CVSS40_SecurityReqValue
parseSecurityReqValue 'H' = SR_High
parseSecurityReqValue 'M' = SR_Medium
parseSecurityReqValue 'L' = SR_Low
parseSecurityReqValue _ = SR_High

parseExploitMaturity :: Char -> CVSS40_ExploitMaturity
parseExploitMaturity 'A' = EM_Attacked
parseExploitMaturity 'P' = EM_PoC
parseExploitMaturity 'U' = EM_Unreported
parseExploitMaturity _ = EM_Attacked

avSeverity :: CVSS40_AV -> Severity
avSeverity AV_Network = Severity 0.0
avSeverity AV_Adjacent = Severity 0.1
avSeverity AV_Local = Severity 0.2
avSeverity AV_Physical = Severity 0.3

prSeverity :: CVSS40_PR -> Severity
prSeverity PR_None = Severity 0.0
prSeverity PR_Low = Severity 0.1
prSeverity PR_High = Severity 0.2

uiSeverity :: CVSS40_UI -> Severity
uiSeverity UI_None = Severity 0.0
uiSeverity UI_Passive = Severity 0.1
uiSeverity UI_Active = Severity 0.2

acSeverity :: CVSS40_AC -> Severity
acSeverity AC_Low = Severity 0.0
acSeverity AC_High = Severity 0.1

atSeverity :: CVSS40_AT -> Severity
atSeverity AT_Absent = Severity 0.0
atSeverity AT_Present = Severity 0.1

vcSeverity :: CVSS40_ImpactValue -> Severity
vcSeverity Impact_High = Severity 0.0
vcSeverity Impact_Low = Severity 0.1
vcSeverity Impact_None = Severity 0.2

viSeverity :: CVSS40_ImpactValue -> Severity
viSeverity Impact_High = Severity 0.0
viSeverity Impact_Low = Severity 0.1
viSeverity Impact_None = Severity 0.2

vaSeverity :: CVSS40_ImpactValue -> Severity
vaSeverity Impact_High = Severity 0.0
vaSeverity Impact_Low = Severity 0.1
vaSeverity Impact_None = Severity 0.2

scSeverity :: CVSS40_ImpactValue -> Severity
scSeverity Impact_High = Severity 0.1
scSeverity Impact_Low = Severity 0.2
scSeverity Impact_None = Severity 0.3

siSeverity :: CVSS40_SubsequentImpactValue -> Severity
siSeverity SI_Safety = Severity 0.0
siSeverity SI_High = Severity 0.1
siSeverity SI_Low = Severity 0.2
siSeverity SI_None = Severity 0.3

saSeverity :: CVSS40_SubsequentImpactValue -> Severity
saSeverity SI_Safety = Severity 0.0
saSeverity SI_High = Severity 0.1
saSeverity SI_Low = Severity 0.2
saSeverity SI_None = Severity 0.3

crSeverity :: CVSS40_SecurityReqValue -> Severity
crSeverity SR_High = Severity 0.0
crSeverity SR_Medium = Severity 0.1
crSeverity SR_Low = Severity 0.2

irSeverity :: CVSS40_SecurityReqValue -> Severity
irSeverity SR_High = Severity 0.0
irSeverity SR_Medium = Severity 0.1
irSeverity SR_Low = Severity 0.2

arSeverity :: CVSS40_SecurityReqValue -> Severity
arSeverity SR_High = Severity 0.0
arSeverity SR_Medium = Severity 0.1
arSeverity SR_Low = Severity 0.2

eSeverity :: CVSS40_ExploitMaturity -> Severity
eSeverity EM_Attacked = Severity 0.0
eSeverity EM_PoC = Severity 1.0
eSeverity EM_Unreported = Severity 2.0

getModifiedChar40 :: [Metric] -> Text -> Text -> Char
getModifiedChar40 metrics modifiedName baseName =
  let modifiedChar = getChar40 metrics modifiedName
   in if modifiedChar == 'X' then getChar40 metrics baseName else modifiedChar

getSecurityReqChar40 :: [Metric] -> Text -> Char
getSecurityReqChar40 metrics name =
  let raw = getChar40 metrics name
   in if raw == 'X' then 'H' else raw

maxComposedEQ1 :: EQLevel -> [(Severity, Severity, Severity)]
maxComposedEQ1 EQ0 = [(Severity 0.0, Severity 0.0, Severity 0.0)]
maxComposedEQ1 EQ1 = [(Severity 0.1, Severity 0.0, Severity 0.0), (Severity 0.0, Severity 0.1, Severity 0.0), (Severity 0.0, Severity 0.0, Severity 0.1)]
maxComposedEQ1 EQ2 = [(Severity 0.3, Severity 0.0, Severity 0.0), (Severity 0.1, Severity 0.1, Severity 0.1)]

maxComposedEQ2 :: EQLevel -> [(Severity, Severity, Severity)]
maxComposedEQ2 EQ0 = [(Severity 0.0, Severity 0.0, Severity 0.0)]
maxComposedEQ2 EQ1 = [(Severity 0.1, Severity 0.0, Severity 0.0), (Severity 0.0, Severity 0.1, Severity 0.0)]
maxComposedEQ2 _ = []

maxComposedEQ3EQ6 :: EQLevel -> EQLevel -> [(Severity, Severity, Severity, Severity, Severity, Severity)]
maxComposedEQ3EQ6 EQ0 EQ0 = [(Severity 0.0, Severity 0.0, Severity 0.0, Severity 0.0, Severity 0.0, Severity 0.0)]
maxComposedEQ3EQ6 EQ0 EQ1 = [(Severity 0.0, Severity 0.0, Severity 0.1, Severity 0.1, Severity 0.1, Severity 0.0), (Severity 0.0, Severity 0.0, Severity 0.0, Severity 0.1, Severity 0.1, Severity 0.1)]
maxComposedEQ3EQ6 EQ1 EQ0 = [(Severity 0.1, Severity 0.0, Severity 0.0, Severity 0.0, Severity 0.0, Severity 0.0), (Severity 0.0, Severity 0.1, Severity 0.0, Severity 0.0, Severity 0.0, Severity 0.0)]
maxComposedEQ3EQ6 EQ1 EQ1 =
  [ (Severity 0.1, Severity 0.0, Severity 0.1, Severity 0.0, Severity 0.1, Severity 0.0),
    (Severity 0.1, Severity 0.0, Severity 0.0, Severity 0.0, Severity 0.1, Severity 0.1),
    (Severity 0.0, Severity 0.1, Severity 0.0, Severity 0.1, Severity 0.0, Severity 0.1),
    (Severity 0.0, Severity 0.1, Severity 0.1, Severity 0.1, Severity 0.0, Severity 0.0),
    (Severity 0.1, Severity 0.1, Severity 0.0, Severity 0.0, Severity 0.0, Severity 0.1)
  ]
maxComposedEQ3EQ6 EQ2 EQ1 = [(Severity 0.1, Severity 0.1, Severity 0.1, Severity 0.0, Severity 0.0, Severity 0.0)]
maxComposedEQ3EQ6 _ _ = []

maxComposedEQ4 :: EQLevel -> [(Severity, Severity, Severity)]
maxComposedEQ4 EQ0 = [(Severity 0.1, Severity 0.0, Severity 0.0)]
maxComposedEQ4 EQ1 = [(Severity 0.1, Severity 0.1, Severity 0.1)]
maxComposedEQ4 EQ2 = [(Severity 0.2, Severity 0.2, Severity 0.2)]
maxComposedEQ4 _ = []

maxDepthEQ1 :: EQLevel -> Int
maxDepthEQ1 EQ0 = 1
maxDepthEQ1 EQ1 = 4
maxDepthEQ1 EQ2 = 5

maxDepthEQ2 :: EQLevel -> Int
maxDepthEQ2 EQ0 = 1
maxDepthEQ2 EQ1 = 2
maxDepthEQ2 _ = 0

maxDepthEQ3EQ6 :: EQLevel -> EQLevel -> Int
maxDepthEQ3EQ6 EQ0 EQ0 = 7
maxDepthEQ3EQ6 EQ0 EQ1 = 6
maxDepthEQ3EQ6 EQ1 EQ0 = 8
maxDepthEQ3EQ6 EQ1 EQ1 = 8
maxDepthEQ3EQ6 EQ2 EQ1 = 10
maxDepthEQ3EQ6 _ _ = 0

maxDepthEQ4 :: EQLevel -> Int
maxDepthEQ4 EQ0 = 6
maxDepthEQ4 EQ1 = 5
maxDepthEQ4 EQ2 = 4
maxDepthEQ4 _ = 0

maxDepthEQ5 :: EQLevel -> Int
maxDepthEQ5 _ = 1

severityDistance :: [Severity] -> [Severity] -> Int
severityDistance current maxV =
  sum [round (abs (cVal - mVal) * 10) | (cVal, mVal) <- zip cVals mVals]
  where
    cVals = map (\(Severity f) -> f) current
    mVals = map (\(Severity f) -> f) maxV

minSeverityDistance :: [Severity] -> [[Severity]] -> Int
minSeverityDistance current maxVectors =
  minimum [severityDistance current maxV | maxV <- maxVectors]

minSeverityDistance6 :: [Severity] -> [(Severity, Severity, Severity, Severity, Severity, Severity)] -> Int
minSeverityDistance6 current maxVectors =
  minimum [severityDistance current [a, b, c, d, e, f] | (a, b, c, d, e, f) <- maxVectors]

incrementEQ :: EQLevel -> EQLevel
incrementEQ EQ0 = EQ1
incrementEQ EQ1 = EQ2
incrementEQ EQ2 = EQ2

clamp :: Float -> Float -> Float -> Float
clamp x lo hi = max lo (min hi x)

cvss40score :: [Metric] -> (Rating, Float)
cvss40score metrics
  | hasEnvironmentalMetrics40 metrics = cvss40EnvironmentalScore metrics
  | hasThreatMetrics40 metrics = cvss40ThreatScore metrics
  | otherwise = cvss40BaseScore metrics

filterBaseMetrics :: [Metric] -> [Metric]
filterBaseMetrics = filter isBaseMetric
  where
    isBaseMetric m =
      let n = coerce (mName m) :: Text
       in n
            `notElem` [ "E",
                        "CR",
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
                        "MSA",
                        "S",
                        "AU",
                        "R",
                        "V"
                      ]

filterThreatMetrics :: [Metric] -> [Metric]
filterThreatMetrics = filter isThreatRelevant
  where
    isThreatRelevant m =
      let n = coerce (mName m) :: Text
       in n
            `notElem` [ "CR",
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
                        "MSA",
                        "S",
                        "AU",
                        "R",
                        "V"
                      ]

cvss40ComputeScore :: [Metric] -> (Rating, Float)
cvss40ComputeScore metrics = (toRating finalScore, finalScore)
  where
    finalScore = round40 (clamp (lookupScore - meanDistance) 0.0 10.0)

    mv = macroVectorFromMetrics metrics
    lookupScore = macroVectorLookup mv

    EQ1Result {..} = computeEQ1 metrics
    EQ2Result {..} = computeEQ2 metrics
    EQ3Result {..} = computeEQ3 metrics
    EQ4Result {..} = computeEQ4 metrics
    EQ5Result {..} = computeEQ5 metrics
    EQ6Result {..} = computeEQ6 (eq3VC, eq3VI, eq3VA) metrics

    eq1MaxVectors = maxComposedEQ1 eq1Level
    eq2MaxVectors = maxComposedEQ2 eq2Level
    eq3eq6MaxVectors = maxComposedEQ3EQ6 eq3Level eq6Level
    eq4MaxVectors = maxComposedEQ4 eq4Level

    eq1SeverityDist = if null eq1MaxVectors then 0 else minSeverityDistance [eq1AV, eq1PR, eq1UI] (map (\(a, b, c) -> [a, b, c]) eq1MaxVectors)
    eq2SeverityDist = if null eq2MaxVectors then 0 else minSeverityDistance [eq2AC, eq2AT, Severity 0] (map (\(a, b, c) -> [a, b, c]) eq2MaxVectors)
    eq3eq6SeverityDist = if null eq3eq6MaxVectors then 0 else minSeverityDistance6 [eq3VC, eq3VI, eq3VA, eq6CR, eq6IR, eq6AR] eq3eq6MaxVectors
    eq4SeverityDist = if null eq4MaxVectors then 0 else minSeverityDistance [eq4SC, eq4SI, eq4SA] (map (\(a, b, c) -> [a, b, c]) eq4MaxVectors)

    eq1Depth = maxDepthEQ1 eq1Level
    eq2Depth = maxDepthEQ2 eq2Level
    eq3eq6Depth = maxDepthEQ3EQ6 eq3Level eq6Level
    eq4Depth = maxDepthEQ4 eq4Level
    eq5Depth = maxDepthEQ5 eq5Level

    eq1NextMv = mv {mvEQ1 = incrementEQ (mvEQ1 mv)}
    eq2NextMv = mv {mvEQ2 = incrementEQ (mvEQ2 mv)}
    eq3NextMv = mv {mvEQ3 = incrementEQ (mvEQ3 mv)}
    eq4NextMv = mv {mvEQ4 = incrementEQ (mvEQ4 mv)}
    eq5NextMv = mv {mvEQ5 = incrementEQ (mvEQ5 mv)}
    eq6NextMv = mv {mvEQ6 = incrementEQ (mvEQ6 mv)}

    eq1Available = positiveAvailable eq1NextMv
    eq2Available = positiveAvailable eq2NextMv
    eq3Available = positiveAvailable eq3NextMv
    eq4Available = positiveAvailable eq4NextMv
    eq5Available = positiveAvailable eq5NextMv
    eq6Available = positiveAvailable eq6NextMv

    positiveAvailable nextMv = case Map.lookup nextMv cvss40LookupTable of
      Just next
        | lookupScore - next > 0 -> Just (lookupScore - next)
        | otherwise -> Nothing
      Nothing -> Nothing

    eq3eq6Available = case (eq3Available, eq6Available) of
      (Just a, Just b) -> Just (max a b)
      (Just a, Nothing) -> Just a
      (Nothing, Just b) -> Just b
      (Nothing, Nothing) -> Nothing

    eq1Reduction = (\avail -> avail * fromIntegral eq1SeverityDist / fromIntegral eq1Depth) <$> eq1Available
    eq2Reduction = (\avail -> avail * fromIntegral eq2SeverityDist / fromIntegral eq2Depth) <$> eq2Available
    eq3eq6Reduction = (\avail -> avail * fromIntegral eq3eq6SeverityDist / fromIntegral eq3eq6Depth) <$> eq3eq6Available
    eq4Reduction = (\avail -> avail * fromIntegral eq4SeverityDist / fromIntegral eq4Depth) <$> eq4Available
    eq5Reduction = (\avail -> avail * 0 / fromIntegral eq5Depth) <$> eq5Available

    allReductions = [eq1Reduction, eq2Reduction, eq3eq6Reduction, eq4Reduction, eq5Reduction]
    validReductions = [r | Just r <- allReductions]
    count = length validReductions
    meanDistance = if count > 0 then sum validReductions / fromIntegral count else 0.0

    round40 :: Float -> Float
    round40 x = fromIntegral @Int (round (x * 10 + 0.0001)) / 10

cvss40BaseScore :: [Metric] -> (Rating, Float)
cvss40BaseScore = cvss40ComputeScore . filterBaseMetrics

cvss40ThreatScore :: [Metric] -> (Rating, Float)
cvss40ThreatScore = cvss40ComputeScore . filterThreatMetrics

cvss40EnvironmentalScore :: [Metric] -> (Rating, Float)
cvss40EnvironmentalScore metrics = (toRating finalScore, finalScore)
  where
    finalScore = round40 (clamp (lookupScore - meanDistance) 0.0 10.0)

    mv = macroVectorFromMetricsEnv metrics
    lookupScore = macroVectorLookup mv

    EQ1Result {..} = computeEQ1Env metrics
    EQ2Result {..} = computeEQ2Env metrics
    EQ3Result {..} = computeEQ3Env metrics
    EQ4Result {..} = computeEQ4Env metrics
    EQ5Result {..} = computeEQ5 metrics
    EQ6Result {..} = computeEQ6 (eq3VC, eq3VI, eq3VA) metrics

    eq1MaxVectors = maxComposedEQ1 eq1Level
    eq2MaxVectors = maxComposedEQ2 eq2Level
    eq3eq6MaxVectors = maxComposedEQ3EQ6 eq3Level eq6Level
    eq4MaxVectors = maxComposedEQ4 eq4Level

    eq1SeverityDist = if null eq1MaxVectors then 0 else minSeverityDistance [eq1AV, eq1PR, eq1UI] (map (\(a, b, c) -> [a, b, c]) eq1MaxVectors)
    eq2SeverityDist = if null eq2MaxVectors then 0 else minSeverityDistance [eq2AC, eq2AT, Severity 0] (map (\(a, b, c) -> [a, b, c]) eq2MaxVectors)
    eq3eq6SeverityDist = if null eq3eq6MaxVectors then 0 else minSeverityDistance6 [eq3VC, eq3VI, eq3VA, eq6CR, eq6IR, eq6AR] eq3eq6MaxVectors
    eq4SeverityDist = if null eq4MaxVectors then 0 else minSeverityDistance [eq4SC, eq4SI, eq4SA] (map (\(a, b, c) -> [a, b, c]) eq4MaxVectors)

    eq1Depth = maxDepthEQ1 eq1Level
    eq2Depth = maxDepthEQ2 eq2Level
    eq3eq6Depth = maxDepthEQ3EQ6 eq3Level eq6Level
    eq4Depth = maxDepthEQ4 eq4Level
    eq5Depth = maxDepthEQ5 eq5Level

    eq1NextMv = mv {mvEQ1 = incrementEQ (mvEQ1 mv)}
    eq2NextMv = mv {mvEQ2 = incrementEQ (mvEQ2 mv)}
    eq3NextMv = mv {mvEQ3 = incrementEQ (mvEQ3 mv)}
    eq4NextMv = mv {mvEQ4 = incrementEQ (mvEQ4 mv)}
    eq5NextMv = mv {mvEQ5 = incrementEQ (mvEQ5 mv)}
    eq6NextMv = mv {mvEQ6 = incrementEQ (mvEQ6 mv)}

    eq1Available = positiveAvailable eq1NextMv
    eq2Available = positiveAvailable eq2NextMv
    eq3Available = positiveAvailable eq3NextMv
    eq4Available = positiveAvailable eq4NextMv
    eq5Available = positiveAvailable eq5NextMv
    eq6Available = positiveAvailable eq6NextMv

    positiveAvailable nextMv = case Map.lookup nextMv cvss40LookupTable of
      Just next
        | lookupScore - next > 0 -> Just (lookupScore - next)
        | otherwise -> Nothing
      Nothing -> Nothing

    eq3eq6Available = case (eq3Available, eq6Available) of
      (Just a, Just b) -> Just (max a b)
      (Just a, Nothing) -> Just a
      (Nothing, Just b) -> Just b
      (Nothing, Nothing) -> Nothing

    eq1Reduction = (\avail -> avail * fromIntegral eq1SeverityDist / fromIntegral eq1Depth) <$> eq1Available
    eq2Reduction = (\avail -> avail * fromIntegral eq2SeverityDist / fromIntegral eq2Depth) <$> eq2Available
    eq3eq6Reduction = (\avail -> avail * fromIntegral eq3eq6SeverityDist / fromIntegral eq3eq6Depth) <$> eq3eq6Available
    eq4Reduction = (\avail -> avail * fromIntegral eq4SeverityDist / fromIntegral eq4Depth) <$> eq4Available
    eq5Reduction = (\avail -> avail * 0 / fromIntegral eq5Depth) <$> eq5Available

    allReductions = [eq1Reduction, eq2Reduction, eq3eq6Reduction, eq4Reduction, eq5Reduction]
    validReductions = [r | Just r <- allReductions]
    count = length validReductions
    meanDistance = if count > 0 then sum validReductions / fromIntegral count else 0.0

    round40 :: Float -> Float
    round40 x = fromIntegral @Int (round (x * 10 + 0.0001)) / 10

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

macroVectorFromMetricsEnv :: [Metric] -> MacroVector
macroVectorFromMetricsEnv metrics =
  MacroVector
    { mvEQ1 = eq1Level (computeEQ1Env metrics),
      mvEQ2 = eq2Level (computeEQ2Env metrics),
      mvEQ3 = eq3Level (computeEQ3Env metrics),
      mvEQ4 = eq4Level (computeEQ4Env metrics),
      mvEQ5 = eq5Level (computeEQ5 metrics),
      mvEQ6 = eq6Level (computeEQ6 (vcLevel, viLevel, vaLevel) metrics)
    }
  where
    EQ3Result {eq3VC = vcLevel, eq3VI = viLevel, eq3VA = vaLevel} = computeEQ3Env metrics

macroVectorLookup :: MacroVector -> Float
macroVectorLookup mv = case Map.lookup mv cvss40LookupTable of
  Nothing -> error $ "CVSS 4.0: invalid MacroVector: " <> show mv
  Just s -> s

textToMacroVector :: Text -> MacroVector
textToMacroVector txt = MacroVector (charToEQ (Text.index txt 0)) (charToEQ (Text.index txt 1)) (charToEQ (Text.index txt 2)) (charToEQ (Text.index txt 3)) (charToEQ (Text.index txt 4)) (charToEQ (Text.index txt 5))
  where
    charToEQ '0' = EQ0
    charToEQ '1' = EQ1
    charToEQ '2' = EQ2
    charToEQ _ = EQ0

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

    avLevel = avSeverity (parseAV avChar)
    prLevel = prSeverity (parsePR prChar)
    uiLevel = uiSeverity (parseUI uiChar)

    eq1
      | avChar == 'N' && prChar == 'N' && uiChar == 'N' = EQ0
      | (avChar == 'N' || prChar == 'N' || uiChar == 'N') && not (avChar == 'N' && prChar == 'N' && uiChar == 'N') && avChar /= 'P' = EQ1
      | avChar == 'P' || not (avChar == 'N' || prChar == 'N' || uiChar == 'N') = EQ2
      | otherwise = EQ1

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

    acLevel = acSeverity (parseAC acChar)
    atLevel = atSeverity (parseAT atChar)

    eq2
      | acChar == 'L' && atChar == 'N' = EQ0
      | otherwise = EQ1

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

    vcLevel = vcSeverity (parseImpactValue vcChar)
    viLevel = viSeverity (parseImpactValue viChar)
    vaLevel = vaSeverity (parseImpactValue vaChar)

    eq3
      | vcChar == 'H' && viChar == 'H' = EQ0
      | not (vcChar == 'H' && viChar == 'H') && (vcChar == 'H' || viChar == 'H' || vaChar == 'H') = EQ1
      | not (vcChar == 'H' || viChar == 'H' || vaChar == 'H') = EQ2
      | otherwise = EQ1

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

    scLevel = scSeverity (parseImpactValue scChar)
    siLevel = siSeverity (parseSubsequentImpactValue siChar)
    saLevel = saSeverity (parseSubsequentImpactValue saChar)

    eq4
      | siChar == 'S' || saChar == 'S' = EQ0
      | not (siChar == 'S' || saChar == 'S') && (scChar == 'H' || siChar == 'H' || saChar == 'H') = EQ1
      | not (siChar == 'S' || saChar == 'S') && not (scChar == 'H' || siChar == 'H' || saChar == 'H') = EQ2
      | otherwise = EQ1

computeEQ5 :: [Metric] -> EQ5Result
computeEQ5 metrics =
  EQ5Result
    { eq5Level = eq5,
      eq5E = eLevel
    }
  where
    eChar = getChar40 metrics "E"
    eLevel = eSeverity (parseExploitMaturity eChar)

    eq5
      | eChar == 'A' = EQ0
      | eChar == 'P' = EQ1
      | eChar == 'U' = EQ2
      | otherwise = EQ0

computeEQ6 :: (Severity, Severity, Severity) -> [Metric] -> EQ6Result
computeEQ6 (Severity vcLevel, Severity viLevel, Severity vaLevel) metrics =
  EQ6Result
    { eq6Level = eq6,
      eq6CR = crLevel,
      eq6IR = irLevel,
      eq6AR = arLevel
    }
  where
    crChar = getSecurityReqChar40 metrics "CR"
    irChar = getSecurityReqChar40 metrics "IR"
    arChar = getSecurityReqChar40 metrics "AR"

    crLevel = crSeverity (parseSecurityReqValue crChar)
    irLevel = irSeverity (parseSecurityReqValue irChar)
    arLevel = arSeverity (parseSecurityReqValue arChar)

    eq6
      | (crChar == 'H' && vcLevel == 0.0) || (irChar == 'H' && viLevel == 0.0) || (arChar == 'H' && vaLevel == 0.0) = EQ0
      | otherwise = EQ1

computeEQ1Env :: [Metric] -> EQ1Result
computeEQ1Env metrics =
  EQ1Result
    { eq1Level = eq1,
      eq1AV = avLevel,
      eq1PR = prLevel,
      eq1UI = uiLevel
    }
  where
    avChar = getModifiedChar40 metrics "MAV" "AV"
    prChar = getModifiedChar40 metrics "MPR" "PR"
    uiChar = getModifiedChar40 metrics "MUI" "UI"

    avLevel = avSeverity (parseAV avChar)
    prLevel = prSeverity (parsePR prChar)
    uiLevel = uiSeverity (parseUI uiChar)

    eq1
      | avChar == 'N' && prChar == 'N' && uiChar == 'N' = EQ0
      | (avChar == 'N' || prChar == 'N' || uiChar == 'N') && not (avChar == 'N' && prChar == 'N' && uiChar == 'N') && avChar /= 'P' = EQ1
      | avChar == 'P' || not (avChar == 'N' || prChar == 'N' || uiChar == 'N') = EQ2
      | otherwise = EQ1

computeEQ2Env :: [Metric] -> EQ2Result
computeEQ2Env metrics =
  EQ2Result
    { eq2Level = eq2,
      eq2AC = acLevel,
      eq2AT = atLevel
    }
  where
    acChar = getModifiedChar40 metrics "MAC" "AC"
    atChar = getModifiedChar40 metrics "MAT" "AT"

    acLevel = acSeverity (parseAC acChar)
    atLevel = atSeverity (parseAT atChar)

    eq2
      | acChar == 'L' && atChar == 'N' = EQ0
      | otherwise = EQ1

computeEQ3Env :: [Metric] -> EQ3Result
computeEQ3Env metrics =
  EQ3Result
    { eq3Level = eq3,
      eq3VC = vcLevel,
      eq3VI = viLevel,
      eq3VA = vaLevel
    }
  where
    vcChar = getModifiedChar40 metrics "MVC" "VC"
    viChar = getModifiedChar40 metrics "MVI" "VI"
    vaChar = getModifiedChar40 metrics "MVA" "VA"

    vcLevel = vcSeverity (parseImpactValue vcChar)
    viLevel = viSeverity (parseImpactValue viChar)
    vaLevel = vaSeverity (parseImpactValue vaChar)

    eq3
      | vcChar == 'H' && viChar == 'H' = EQ0
      | not (vcChar == 'H' && viChar == 'H') && (vcChar == 'H' || viChar == 'H' || vaChar == 'H') = EQ1
      | not (vcChar == 'H' || viChar == 'H' || vaChar == 'H') = EQ2
      | otherwise = EQ1

computeEQ4Env :: [Metric] -> EQ4Result
computeEQ4Env metrics =
  EQ4Result
    { eq4Level = eq4,
      eq4SC = scLevel,
      eq4SI = siLevel,
      eq4SA = saLevel
    }
  where
    scChar = getModifiedChar40 metrics "MSC" "SC"
    siChar = getModifiedChar40 metrics "MSI" "SI"
    saChar = getModifiedChar40 metrics "MSA" "SA"

    scLevel = scSeverity (parseImpactValue scChar)
    siLevel = siSeverity (parseSubsequentImpactValue siChar)
    saLevel = saSeverity (parseSubsequentImpactValue saChar)

    eq4
      | siChar == 'S' || saChar == 'S' = EQ0
      | not (siChar == 'S' || saChar == 'S') && (scChar == 'H' || siChar == 'H' || saChar == 'H') = EQ1
      | not (siChar == 'S' || saChar == 'S') && not (scChar == 'H' || siChar == 'H' || saChar == 'H') = EQ2
      | otherwise = EQ1

cvss40LookupTable :: Map.Map MacroVector Float
cvss40LookupTable = Map.fromList [(textToMacroVector k, v) | (k, v) <- textTable]
  where
    textTable =
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
