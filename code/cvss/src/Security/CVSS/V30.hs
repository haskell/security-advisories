{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module Security.CVSS.V30
  ( cvss30DB,
    validateCvss30,
    cvss30score,
    cvss30BaseScore,
    cvss30TemporalScore,
    cvss30EnvironmentalScore,
  )
where

import Data.Foldable (traverse_)
import Data.Text (Text)
import GHC.Float (powerFloat)

import Security.CVSS.Internal
import Security.CVSS.Types

pattern C :: Text -> MetricValueChar
pattern C c = MetricValueChar c

{-# COMPLETE C #-}

-- Constants used in place of unchanged/changed pattern synonyms
unchanged :: Float
unchanged = 6.42

changed :: Float
changed = 7.52

cvss30DB :: CVSSDB
cvss30DB =
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
      [ MetricValue "unchanged" (C "U") unchanged Nothing "An exploited vulnerability can only affect resources managed by the same authority.",
        MetricValue "changed" (C "C") changed Nothing "An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable component."
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

validateCvss30 :: [Metric] -> Either CVSSError [Metric]
validateCvss30 metrics = do
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss30DB, validateRequired cvss30DB]
  pure metrics

cvss30BaseScore :: [Metric] -> (Rating, Float)
cvss30BaseScore metrics = (toRating score, score)
  where
    score
      | impact <= 0 = 0
      | scope == unchanged = roundup (min (impact + exploitability) 10)
      | otherwise = roundup (min (1.08 * (impact + exploitability)) 10)
    impact
      | scope == unchanged = scope * iscBase
      | otherwise = scope * (iscBase - 0.029) - 3.25 * powerFloat (iscBase - 0.02) 15
    iscBase = 1 - (1 - gm "Confidentiality Impact") * (1 - gm "Integrity Impact") * (1 - gm "Availability Impact")
    scope = gm "Scope"

    exploitability = 8.22 * gm "Attack Vector" * gm "Attack Complexity" * gm "Privileges Required" * gm "User Interaction"
    gm = getMetricValue cvss30DB metrics scope

cvss30score :: [Metric] -> (Rating, Float)
cvss30score metrics
  | hasEnvironmentalMetrics metrics = cvss30EnvironmentalScore metrics
  | hasTemporalMetrics metrics = cvss30TemporalScore metrics
  | otherwise = cvss30BaseScore metrics

cvss30TemporalScore :: [Metric] -> (Rating, Float)
cvss30TemporalScore metrics = (toRating score, score)
  where
    (_, baseScore) = cvss30BaseScore metrics
    exploitCodeMaturity = getMetricValueOr cvss30DB metrics 1.0 unchanged "Exploit Code Maturity"
    remediationLevel = getMetricValueOr cvss30DB metrics 1.0 unchanged "Remediation Level"
    reportConfidence = getMetricValueOr cvss30DB metrics 1.0 unchanged "Report Confidence"
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
      | modifiedScope == unchanged = 6.42 * miss
      | otherwise = 7.52 * (miss - 0.029) - 3.25 * powerFloat (miss - 0.02) 15

    modifiedExploitability =
      8.22
        * modifiedAttackVector
        * modifiedAttackComplexity
        * modifiedPrivilegesRequired
        * modifiedUserInteraction

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

    exploitCodeMaturity = getMetricValueOr cvss30DB metrics 1.0 unchanged "Exploit Code Maturity"
    remediationLevel = getMetricValueOr cvss30DB metrics 1.0 unchanged "Remediation Level"
    reportConfidence = getMetricValueOr cvss30DB metrics 1.0 unchanged "Report Confidence"
    confidentialityRequirement = getMetricValueOr cvss30DB metrics 1.0 unchanged "Confidentiality Requirement"
    integrityRequirement = getMetricValueOr cvss30DB metrics 1.0 unchanged "Integrity Requirement"
    availabilityRequirement = getMetricValueOr cvss30DB metrics 1.0 unchanged "Availability Requirement"
    modifiedAttackVector = getModifiedMetricValue cvss30DB metrics "Modified Attack Vector" "Attack Vector" modifiedScope
    modifiedAttackComplexity = getModifiedMetricValue cvss30DB metrics "Modified Attack Complexity" "Attack Complexity" modifiedScope
    modifiedPrivilegesRequired = getModifiedMetricValue cvss30DB metrics "Modified Privileges Required" "Privileges Required" modifiedScope
    modifiedUserInteraction = getModifiedMetricValue cvss30DB metrics "Modified User Interaction" "User Interaction" modifiedScope
    modifiedScope = getModifiedMetricValue cvss30DB metrics "Modified Scope" "Scope" unchanged
    modifiedConfidentiality = getModifiedMetricValue cvss30DB metrics "Modified Confidentiality" "Confidentiality Impact" modifiedScope
    modifiedIntegrity = getModifiedMetricValue cvss30DB metrics "Modified Integrity" "Integrity Impact" modifiedScope
    modifiedAvailability = getModifiedMetricValue cvss30DB metrics "Modified Availability" "Availability Impact" modifiedScope