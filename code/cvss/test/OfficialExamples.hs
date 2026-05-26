{-# LANGUAGE OverloadedStrings #-}

module OfficialExamples
  ( OfficialExample (..),
    cvss20OfficialExamples,
    cvss30OfficialExamples,
    cvss31OfficialExamples,
    cvss40OfficialExamples,
  )
where

import Data.Text (Text)
import Security.CVSS (Rating (..))

data OfficialExample = OfficialExample
  { oeVector :: Text,
    oeBaseScore :: Float,
    oeBaseRating :: Rating,
    oeTemporalScore :: Maybe (Float, Rating),
    oeThreatScore :: Maybe (Float, Rating),
    oeEnvironmentalScore :: Maybe (Float, Rating),
    oeDescription :: Text
  }

cvss20OfficialExamples :: [OfficialExample]
cvss20OfficialExamples =
  [ OfficialExample
      "AV:N/AC:L/Au:N/C:N/I:N/A:C"
      7.8
      High
      (Just (6.4, High))
      Nothing
      Nothing
      "CVE-2002-0392 Apache Chunked-Encoding Memory Corruption - Base",
    OfficialExample
      "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C"
      7.8
      High
      (Just (6.4, High))
      Nothing
      Nothing
      "CVE-2002-0392 Apache Chunked-Encoding Memory Corruption - Temporal",
    OfficialExample
      "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:H/CR:H/IR:H/AR:H"
      7.8
      High
      Nothing
      Nothing
      (Just (9.2, High))
      "CVE-2002-0392 Apache Chunked-Encoding Memory Corruption - Environmental (High AR)",
    OfficialExample
      "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:H/CR:L/IR:L/AR:L"
      7.8
      High
      Nothing
      Nothing
      (Just (4.6, High))
      "CVE-2002-0392 Apache Chunked-Encoding Memory Corruption - Environmental (Low AR)",
    OfficialExample
      "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:N"
      7.8
      High
      Nothing
      Nothing
      (Just (0.0, None))
      "CVE-2002-0392 Apache Chunked-Encoding Memory Corruption - Environmental (TD:N)",
    OfficialExample
      "AV:N/AC:L/Au:N/C:C/I:C/A:C"
      10.0
      High
      (Just (8.3, High))
      Nothing
      Nothing
      "CVE-2003-0818 Windows ASN.1 Library Integer Handling - Base",
    OfficialExample
      "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C"
      10.0
      High
      (Just (8.3, High))
      Nothing
      Nothing
      "CVE-2003-0818 Windows ASN.1 Library Integer Handling - Temporal",
    OfficialExample
      "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:H/CR:H/IR:H/AR:H"
      10.0
      High
      Nothing
      Nothing
      (Just (9.0, High))
      "CVE-2003-0818 Windows ASN.1 Library Integer Handling - Environmental (High AR)",
    OfficialExample
      "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:H/CR:L/IR:L/AR:L"
      10.0
      High
      Nothing
      Nothing
      (Just (6.4, High))
      "CVE-2003-0818 Windows ASN.1 Library Integer Handling - Environmental (Low AR)",
    OfficialExample
      "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:N"
      10.0
      High
      Nothing
      Nothing
      (Just (0.0, None))
      "CVE-2003-0818 Windows ASN.1 Library Integer Handling - Environmental (TD:N)",
    OfficialExample
      "AV:L/AC:H/Au:N/C:C/I:C/A:C"
      6.2
      High
      (Just (4.9, High))
      Nothing
      Nothing
      "CVE-2003-0062 NOD32 Antivirus Buffer Overflow - Base",
    OfficialExample
      "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C"
      6.2
      High
      (Just (4.9, High))
      Nothing
      Nothing
      "CVE-2003-0062 NOD32 Antivirus Buffer Overflow - Temporal",
    OfficialExample
      "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:H/CR:M/IR:M/AR:M"
      6.2
      High
      Nothing
      Nothing
      (Just (7.5, High))
      "CVE-2003-0062 NOD32 Antivirus Buffer Overflow - Environmental (Medium AR)",
    OfficialExample
      "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:H/CR:L/IR:L/AR:L"
      6.2
      High
      Nothing
      Nothing
      (Just (5.6, High))
      "CVE-2003-0062 NOD32 Antivirus Buffer Overflow - Environmental (Low AR)",
    OfficialExample
      "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:N/TD:N"
      6.2
      High
      Nothing
      Nothing
      (Just (0.0, None))
      "CVE-2003-0062 NOD32 Antivirus Buffer Overflow - Environmental (TD:N)"
  ]

cvss30OfficialExamples :: [OfficialExample]
cvss30OfficialExamples =
  [ OfficialExample
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
      6.1
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2013-1937 phpMyAdmin XSS",
    OfficialExample
      "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
      6.4
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2013-0375 MySQL Stored SQL Injection",
    OfficialExample
      "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
      3.1
      Low
      Nothing
      Nothing
      Nothing
      "CVE-2014-3566 SSLv3 POODLE",
    OfficialExample
      "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
      9.9
      Critical
      Nothing
      Nothing
      Nothing
      "CVE-2012-1516 VMware Guest to Host Escape",
    OfficialExample
      "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L"
      4.2
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2009-0783 Apache Tomcat XML Parser",
    OfficialExample
      "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
      8.8
      High
      Nothing
      Nothing
      Nothing
      "CVE-2012-0384 Cisco IOS Cmd Execution (v3.0 PR:L)",
    OfficialExample
      "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
      7.8
      High
      Nothing
      Nothing
      Nothing
      "CVE-2015-1098 Apple iWork DoS",
    OfficialExample
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
      7.5
      High
      Nothing
      Nothing
      Nothing
      "CVE-2014-0160 OpenSSL Heartbleed",
    OfficialExample
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      9.8
      Critical
      Nothing
      Nothing
      Nothing
      "CVE-2014-6271 Shellshock",
    OfficialExample
      "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N"
      6.8
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2008-1447 DNS Kaminsky",
    OfficialExample
      "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      6.8
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2014-2005 Sophos Login Bypass",
    OfficialExample
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N"
      5.8
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2010-0467 Joomla Directory Traversal",
    OfficialExample
      "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N"
      5.8
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2012-1342 Cisco ACL Bypass",
    OfficialExample
      "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H"
      9.3
      Critical
      Nothing
      Nothing
      Nothing
      "CVE-2013-6014 Juniper Proxy ARP DoS",
    OfficialExample
      "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
      5.4
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2014-9253 DokuWiki XSS",
    OfficialExample
      "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
      7.8
      High
      Nothing
      Nothing
      Nothing
      "CVE-2009-0658 Adobe Acrobat Overflow",
    OfficialExample
      "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      8.8
      High
      Nothing
      Nothing
      Nothing
      "CVE-2011-1265 Windows Bluetooth RCE",
    OfficialExample
      "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
      4.6
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2014-2019 Apple iOS Control Bypass"
  ]

cvss31OfficialExamples :: [OfficialExample]
cvss31OfficialExamples =
  [ OfficialExample
      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
      6.4
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2013-0375 MySQL Stored SQL Injection",
    OfficialExample
      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
      3.1
      Low
      Nothing
      Nothing
      Nothing
      "CVE-2014-3566 SSLv3 POODLE",
    OfficialExample
      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
      9.9
      Critical
      Nothing
      Nothing
      Nothing
      "CVE-2012-1516 VMware Guest to Host Escape",
    OfficialExample
      "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L"
      4.2
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2009-0783 Apache Tomcat XML Parser",
    OfficialExample
      "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
      7.2
      High
      Nothing
      Nothing
      Nothing
      "CVE-2012-0384 Cisco IOS Cmd Execution (v3.1 PR:H)",
    OfficialExample
      "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
      7.8
      High
      Nothing
      Nothing
      Nothing
      "CVE-2015-1098 Apple iWork DoS",
    OfficialExample
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
      7.5
      High
      Nothing
      Nothing
      Nothing
      "CVE-2014-0160 OpenSSL Heartbleed",
    OfficialExample
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      9.8
      Critical
      Nothing
      Nothing
      Nothing
      "CVE-2014-6271 Shellshock",
    OfficialExample
      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N"
      6.8
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2008-1447 DNS Kaminsky",
    OfficialExample
      "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      6.8
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2014-2005 Sophos Login Bypass",
    OfficialExample
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N"
      5.8
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2010-0467 Joomla Directory Traversal",
    OfficialExample
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N"
      5.8
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2012-1342 Cisco ACL Bypass",
    OfficialExample
      "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H"
      9.3
      Critical
      Nothing
      Nothing
      Nothing
      "CVE-2013-6014 Juniper Proxy ARP DoS",
    OfficialExample
      "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H"
      9.0
      High
      Nothing
      Nothing
      Nothing
      "CVE-2019-7551 Cantemo Portal XSS",
    OfficialExample
      "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
      7.8
      High
      Nothing
      Nothing
      Nothing
      "CVE-2009-0658 Adobe Acrobat Overflow",
    OfficialExample
      "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      8.8
      High
      Nothing
      Nothing
      Nothing
      "CVE-2011-1265 Windows Bluetooth RCE",
    OfficialExample
      "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
      4.6
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2014-2019 Apple iOS Control Bypass",
    OfficialExample
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
      8.8
      High
      Nothing
      Nothing
      Nothing
      "CVE-2015-0970 SearchBlox CSRF"
  ]

cvss40OfficialExamples :: [OfficialExample]
cvss40OfficialExamples =
  [ OfficialExample
      "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      7.3
      High
      Nothing
      Nothing
      Nothing
      "CVE-2022-41741 New Metric -- Attack Requirements",
    OfficialExample
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      7.7
      High
      Nothing
      Nothing
      Nothing
      "CVE-2020-3549 New Metric -- Attack Requirements (Base)",
    OfficialExample
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U"
      7.7
      High
      Nothing
      (Just (5.2, High))
      Nothing
      "CVE-2020-3549 New Metric -- Attack Requirements (Threat)",
    OfficialExample
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"
      8.3
      High
      Nothing
      Nothing
      Nothing
      "CVE-2023-3089 New Metric -- Attack Requirements (High score)",
    OfficialExample
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L"
      8.3
      High
      Nothing
      Nothing
      (Just (8.1, High))
      "CVE-2023-3089 New Metric -- Attack Requirements (Environmental)",
    OfficialExample
      "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
      4.6
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2021-44714 Revised Metric -- User Interaction",
    OfficialExample
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"
      5.1
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2022-21830 Revised Metric -- User Interaction",
    OfficialExample
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"
      6.9
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2022-22186 Subsequent Confidentiality/Integrity/Availability",
    OfficialExample
      "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N"
      5.9
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2023-21989 Subsequent Confidentiality/Integrity/Availability",
    OfficialExample
      "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
      9.4
      Critical
      Nothing
      Nothing
      Nothing
      "CVE-2020-3947 Subsequent Confidentiality/Integrity/Availability",
    OfficialExample
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H"
      9.3
      Critical
      Nothing
      Nothing
      Nothing
      "CVE-2023-48228 Subsequent Confidentiality/Integrity/Availability",
    OfficialExample
      "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D"
      8.3
      High
      Nothing
      Nothing
      Nothing
      "CVE-2023-30560 Safety Metric",
    OfficialExample
      "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A"
      7.3
      High
      Nothing
      (Just (6.8, High))
      Nothing
      "CVE-2026-20805 CISA KEV Examples",
    OfficialExample
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A"
      7.5
      High
      Nothing
      (Just (8.7, High))
      Nothing
      "CVE-2014-0160 Heartbleed Classic Example (Threat)",
    OfficialExample
      "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      8.2
      High
      Nothing
      Nothing
      Nothing
      "CVE-2021-44228 log4shell (immutable containers)",
    OfficialExample
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
      9.3
      Critical
      Nothing
      (Just (9.3, Critical))
      Nothing
      "CVE-2021-44228 log4shell Classic Example (Threat)",
    OfficialExample
      "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L"
      8.2
      High
      Nothing
      (Just (5.5, High))
      Nothing
      "CVE-2021-44228 log4shell Classic Example (Environmental)",
    OfficialExample
      "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H"
      6.4
      Medium
      Nothing
      Nothing
      Nothing
      "CVE-2013-6014 Juniper Proxy ARP Classic Example",
    OfficialExample
      "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I"
      8.4
      High
      Nothing
      (Just (8.4, High))
      Nothing
      "CVE-2016-5729 Lenovo ThinkPwn Classic Example"
  ]
