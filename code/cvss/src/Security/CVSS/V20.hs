{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}

module Security.CVSS.V20
  ( cvss20DB,
    validateCvss20,
    cvss20score,
    cvss20BaseScore,
    cvss20TemporalScore,
    cvss20EnvironmentalScore,
  )
where

import Data.Foldable (traverse_)
import Data.Text (Text)
import Data.Text qualified as Text

import Security.CVSS.Internal
import Security.CVSS.Types

pattern C :: Text -> MetricValueChar
pattern C c = MetricValueChar c

{-# COMPLETE C #-}

cvss20DB :: CVSSDB
cvss20DB =
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
  traverse_ (\t -> t metrics) [validateUnique, validateKnown cvss20DB, validateRequired cvss20DB]
  pure metrics

hasEnvironmentalMetrics20 :: [Metric] -> Bool
hasEnvironmentalMetrics20 = any (\metric -> mName metric `elem` ["CDP", "TD", "CR", "IR", "AR"])

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
    gm = getMetricValue cvss20DB metrics 0

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
  getMetricValueOr cvss20DB metrics defaultValue 0

cvss20EnvironmentalScore :: [Metric] -> (Rating, Float)
cvss20EnvironmentalScore metrics = (toRating20 score, score)
  where
    securityRequirement = getMetricValueOr cvss20DB metrics 1 0
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
    gm = getMetricValue cvss20DB metrics 0

    round_to_1_decimal :: Float -> Float
    round_to_1_decimal x = fromIntegral @Int (round (x * 10)) / 10