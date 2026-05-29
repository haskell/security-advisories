{-# LANGUAGE OverloadedStrings #-}

module Security.CVSS.V31
  ( cvss31DB,
    validateCvss31,
    cvss31score,
    cvss31BaseScore,
    cvss31TemporalScore,
    cvss31EnvironmentalScore,
  )
where

import Data.Foldable (traverse_)
import Data.Text (Text)
import GHC.Float (powerFloat)
import Security.CVSS.Internal
import Security.CVSS.Types

cvss31DB :: CVSSDB
cvss31DB =
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
      [ MetricValue "Network" (MetricValueChar "N") 0.85 Nothing "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet.",
        MetricValue "Adjacent" (MetricValueChar "A") 0.62 Nothing "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.",
        MetricValue "Local" (MetricValueChar "L") 0.55 Nothing "The vulnerable component is not bound to the network stack and the attacker's path is via read/write/execute capabilities.",
        MetricValue "Physical" (MetricValueChar "P") 0.2 Nothing "The attack requires the attacker to physically touch or manipulate the vulnerable component."
      ]
    acValues =
      [ MetricValue "Low" (MetricValueChar "L") 0.77 Nothing "Specialized access conditions or extenuating circumstances do not exist.",
        MetricValue "High" (MetricValueChar "H") 0.44 Nothing "A successful attack depends on conditions beyond the attacker's control."
      ]
    prValues =
      [ MetricValue "None" (MetricValueChar "N") 0.85 Nothing "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.",
        MetricValue "Low" (MetricValueChar "L") 0.62 (Just 0.68) "The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user.",
        MetricValue "High" (MetricValueChar "H") 0.27 (Just 0.5) "The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
      ]
    uiValues =
      [ MetricValue "None" (MetricValueChar "N") 0.85 Nothing "The vulnerable system can be exploited without interaction from any user.",
        MetricValue "Required" (MetricValueChar "R") 0.62 Nothing "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited."
      ]
    sValues =
      [ MetricValue "Unchanged" (MetricValueChar "U") unchanged Nothing "An exploited vulnerability can only affect resources managed by the same security authority.",
        MetricValue "Changed" (MetricValueChar "C") changed Nothing "An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component."
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
    mkHigh = MetricValue "High" (MetricValueChar "H") 0.56 Nothing
    mkLow = MetricValue "Low" (MetricValueChar "L") 0.22 Nothing
    mkNone = MetricValue "None" (MetricValueChar "N") 0 Nothing
    temporalMetrics =
      [ MetricInfo
          "Exploit Code Maturity"
          "E"
          False
          [ mkTemporalUndef "High",
            MetricValue "High" (MetricValueChar "H") 1 Nothing "Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available. Exploit code works in every situation, or is actively being delivered via an autonomous agent (such as a worm or virus). Network-connected systems are likely to encounter scanning or exploitation attempts. Exploit development has reached the level of reliable, widely available, easy-to-use automated tools.",
            MetricValue "Functional" (MetricValueChar "F") 0.97 Nothing "Functional exploit code is available. The code works in most situations where the vulnerability exists.",
            MetricValue "Proof of Concept" (MetricValueChar "P") 0.94 Nothing "Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.",
            MetricValue "Unproven" (MetricValueChar "U") 0.91 Nothing "No exploit code is available, or an exploit is theoretical."
          ],
        MetricInfo
          "Remediation Level"
          "RL"
          False
          [ mkTemporalUndef "Unavailable",
            MetricValue "Unavailable" (MetricValueChar "U") 1 Nothing "There is either no solution available or it is impossible to apply.",
            MetricValue "Workaround" (MetricValueChar "W") 0.97 Nothing "There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.",
            MetricValue "Temporary Fix" (MetricValueChar "T") 0.96 Nothing "There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.",
            MetricValue "Official Fix" (MetricValueChar "O") 0.95 Nothing "A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available."
          ],
        MetricInfo
          "Report Confidence"
          "RC"
          False
          [ mkTemporalUndef "Confirmed",
            MetricValue "Confirmed" (MetricValueChar "C") 1 Nothing "Detailed reports exist, or functional reproduction is possible (functional exploits may provide this). Source code is available to independently verify the assertions of the research, or the author or vendor of the affected code has confirmed the presence of the vulnerability.",
            MetricValue "Reasonable" (MetricValueChar "R") 0.96 Nothing "Significant details are published, but researchers either do not have full confidence in the root cause, or do not have access to source code to fully confirm all of the interactions that may lead to the result. Reasonable confidence exists, however, that the bug is reproducible and at least one impact is able to be verified (proof-of-concept exploits may provide this). An example is a detailed write-up of research into a vulnerability with an explanation (possibly obfuscated or \"left as an exercise to the reader\") that gives assurances on how to reproduce the results.",
            MetricValue "Unknown" (MetricValueChar "U") 0.92 Nothing "There are reports of impacts that indicate a vulnerability is present. The reports indicate that the cause of the vulnerability is unknown, or reports may differ on the cause or impacts of the vulnerability. Reporters are uncertain of the true nature of the vulnerability, and there is little confidence in the validity of the reports or whether a static Base Score can be applied given the differences described. An example is a bug report which notes that an intermittent but non-reproducible crash occurs, with evidence of memory corruption suggesting that denial of service, or possible more serious impacts, may result."
          ]
      ]
    mkTemporalUndef m = MetricValue "Not Defined" (MetricValueChar "X") 1 Nothing $ mkTemporalUndefMsg m
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
    mkEnvUndef = MetricValue "Not Defined" (MetricValueChar "X") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium."
    mkEnvHighMsg m = "Loss of " <> m <> " is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
    mkEnvHigh m = MetricValue "High" (MetricValueChar "H") 1.5 Nothing $ mkEnvHighMsg m
    mkEnvMediumMsg m = "Loss of " <> m <> " is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
    mkEnvMedium m = MetricValue "Medium" (MetricValueChar "M") 1 Nothing $ mkEnvMediumMsg m
    mkEnvLowMsg m = "Loss of " <> m <> " is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers)."
    mkEnvLow m = MetricValue "Low" (MetricValueChar "L") 0.5 Nothing $ mkEnvLowMsg m
    mkModifiedUndef = MetricValue "Not Defined" (MetricValueChar "X") 1 Nothing "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Score" -- Not Defined (X): mvNum is ignored in scoring; getModifiedMetricValue substitutes the base metric value

validateCvss31 :: [Metric] -> Either CVSSError ()
validateCvss31 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss31DB, validateRequired cvss31DB]

cvss31score :: [Metric] -> (Rating, Float)
cvss31score metrics
  | hasEnvironmentalMetrics metrics = cvss31EnvironmentalScore metrics
  | hasTemporalMetrics metrics = cvss31TemporalScore metrics
  | otherwise = cvss31BaseScore metrics

cvss31BaseScore :: [Metric] -> (Rating, Float)
cvss31BaseScore metrics = (toRating score, score)
  where
    iss = 1 - (1 - gm "Confidentiality Impact") * (1 - gm "Integrity Impact") * (1 - gm "Availability Impact")
    impact
      | scope == unchanged = scope * iss
      | otherwise = 7.52 * (iss - 0.029) - 3.25 * powerFloat (iss - 0.02) 15
    exploitability = 8.22 * gm "Attack Vector" * gm "Attack Complexity" * gm "Privileges Required" * gm "User Interaction"
    score
      | impact <= 0 = 0
      | scope == unchanged = roundup (min (impact + exploitability) 10)
      | otherwise = roundup (min (1.08 * (impact + exploitability)) 10)
    scope = gm "Scope"

    gm :: Text -> Float
    gm = getMetricValue cvss31DB metrics scope

cvss31TemporalScore :: [Metric] -> (Rating, Float)
cvss31TemporalScore metrics = (toRating score, score)
  where
    (_, baseScore) = cvss31BaseScore metrics
    exploitCodeMaturity = optionalMetric metrics 1.0 "Exploit Code Maturity"
    remediationLevel = optionalMetric metrics 1.0 "Remediation Level"
    reportConfidence = optionalMetric metrics 1.0 "Report Confidence"
    score = roundup (baseScore * exploitCodeMaturity * remediationLevel * reportConfidence)

optionalMetric :: [Metric] -> Float -> Text -> Float
optionalMetric metrics defaultValue =
  getMetricValueOr cvss31DB metrics defaultValue unchanged

isMetricND :: [Metric] -> Text -> Bool
isMetricND metrics name =
  case lookupMetricValueChar cvss31DB metrics name of
    Nothing -> True
    Just (MetricValueChar "X") -> True
    _ -> False

allEnvMetricsND :: [Metric] -> Bool
allEnvMetricsND metrics =
  all (isMetricND metrics) envMetricNames
  where
    envMetricNames =
      [ "Confidentiality Requirement",
        "Integrity Requirement",
        "Availability Requirement",
        "Modified Attack Vector",
        "Modified Attack Complexity",
        "Modified Privileges Required",
        "Modified User Interaction",
        "Modified Scope",
        "Modified Confidentiality",
        "Modified Integrity",
        "Modified Availability"
      ]

cvss31EnvironmentalScore :: [Metric] -> (Rating, Float)
cvss31EnvironmentalScore metrics
  | allEnvMetricsND metrics = cvss31TemporalScore metrics
  | otherwise = (toRating score, score)
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
    If ModifiedScope is unchanged 6.42 × MISS
    If ModifiedScope is changed   7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)^13
    -}
    modifiedImpact
      | modifiedScope == unchanged = 6.42 * miss
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
      | modifiedScope == unchanged =
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
    modifiedAttackVector = getModifiedMetricValue cvss31DB metrics "Modified Attack Vector" "Attack Vector" modifiedScope
    modifiedAttackComplexity = getModifiedMetricValue cvss31DB metrics "Modified Attack Complexity" "Attack Complexity" modifiedScope
    modifiedPrivilegesRequired = getModifiedMetricValue cvss31DB metrics "Modified Privileges Required" "Privileges Required" modifiedScope
    modifiedUserInteraction = getModifiedMetricValue cvss31DB metrics "Modified User Interaction" "User Interaction" modifiedScope
    modifiedScope = getModifiedMetricValue cvss31DB metrics "Modified Scope" "Scope" unchanged
    modifiedConfidentiality = getModifiedMetricValue cvss31DB metrics "Modified Confidentiality" "Confidentiality Impact" modifiedScope
    modifiedIntegrity = getModifiedMetricValue cvss31DB metrics "Modified Integrity" "Integrity Impact" modifiedScope
    modifiedAvailability = getModifiedMetricValue cvss31DB metrics "Modified Availability" "Availability Impact" modifiedScope
