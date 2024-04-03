{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}

module Spec.FormatSpec (spec) where

import Data.Fixed (Fixed (MkFixed))
import Data.Function (on)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time
import Distribution.Types.Version
import Distribution.Types.VersionRange
import qualified Hedgehog as Gen
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import qualified Prettyprinter as Pretty
import qualified Prettyprinter.Render.Text as Pretty
import Security.Advisories.Core.Advisory
import Security.Advisories.Core.HsecId
import Security.Advisories.Format
import Security.CVSS
import Security.OSV (Reference (..), ReferenceType (..))
import Test.Tasty
import Test.Tasty.Hedgehog
import qualified Toml

spec :: TestTree
spec =
  testGroup
    "Format"
    [ testGroup
        "FrontMatter"
        [ testProperty "parse . render == id" $
            Gen.property $ do
              fm <- Gen.forAll genFrontMatter
              let rendered =
                    Pretty.renderStrict $ Pretty.layoutPretty Pretty.defaultLayoutOptions $ Toml.encode fm
              Gen.footnote $ T.unpack rendered
              Toml.decode rendered Gen.=== Toml.Success mempty (FrontMatterEq fm)
        ]
    ]

newtype FrontMatterEq = FrontMatterEq {unFrontMatter :: FrontMatter}
  deriving newtype (Show, FromValue)

instance Eq FrontMatterEq where
  (==) = (==) `on` show . unFrontMatter

genFrontMatter :: Gen.Gen FrontMatter
genFrontMatter =
  FrontMatter
    <$> genAdvisoryMetadata
    <*> Gen.list (Range.linear 0 10) genReference
    <*> Gen.list (Range.linear 0 10) genAffected

genAdvisoryMetadata :: Gen.Gen AdvisoryMetadata
genAdvisoryMetadata =
  AdvisoryMetadata
    <$> genHsecId
    <*> Gen.maybe genUTCTime
    <*> Gen.maybe genUTCTime
    <*> Gen.list (Range.linear 0 5) genCAPEC
    <*> Gen.list (Range.linear 0 5) genCWE
    <*> Gen.list (Range.linear 0 5) genKeyword
    <*> Gen.list (Range.linear 0 5) genText
    <*> Gen.list (Range.linear 0 5) genText

genAffected :: Gen.Gen Affected
genAffected =
  Affected
    <$> genText
    <*> genCVSS
    <*> Gen.list (Range.linear 0 5) genAffectedVersionRange
    <*> Gen.maybe (Gen.list (Range.linear 0 5) genArchitecture)
    <*> Gen.maybe (Gen.list (Range.linear 0 5) genOS)
    <*> (Map.toList . Map.fromList <$> Gen.list (Range.linear 0 5) ((,) <$> genText <*> genVersionRange))

genCVSS :: Gen.Gen CVSS
genCVSS =
  Gen.choice $
    map
      (\x -> either (\e -> error $ "Cannot parse CVSS " <> show x <> " " <> show e) return $ parseCVSS x)
      [ "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "CVSS:2.0/AV:L/AC:H/Au:N/C:C/I:C/A:C"
      ]

genCAPEC :: Gen.Gen CAPEC
genCAPEC = CAPEC <$> Gen.integral (Range.linear 100 999)

genCWE :: Gen.Gen CWE
genCWE = CWE <$> Gen.integral (Range.linear 100 999)

genHsecId :: Gen.Gen HsecId
genHsecId = flip nextHsecId placeholder <$> Gen.integral (Range.linear 2024 2032)

genUTCTime :: Gen.Gen UTCTime
genUTCTime =
  UTCTime
    <$> genDay
    <*> fmap secondsToDiffTime (Gen.integral $ Range.constant 0 86401)

genDay :: Gen.Gen Day
genDay = do
  y <- toInteger <$> Gen.int (Range.constant 1968 2019)
  m <- Gen.int (Range.constant 1 12)
  d <- Gen.int (Range.constant 1 28)
  pure $ fromGregorian y m d

genVersionRange :: Gen.Gen VersionRange
genVersionRange =
  Gen.recursive
    Gen.choice
    [ pure anyVersion,
      pure noVersion,
      thisVersion <$> genVersion,
      notThisVersion <$> genVersion,
      laterVersion <$> genVersion,
      earlierVersion <$> genVersion,
      orLaterVersion <$> genVersion,
      orEarlierVersion <$> genVersion,
      withinVersion <$> genVersion,
      majorBoundVersion <$> genVersion
    ]
    [ Gen.subterm2 genVersionRange genVersionRange unionVersionRanges,
      Gen.subterm2 genVersionRange genVersionRange intersectVersionRanges
    ]

genText :: Gen.Gen Text
genText = Gen.text (Range.linear 1 20) Gen.alphaNum

genAffectedVersionRange :: Gen.Gen AffectedVersionRange
genAffectedVersionRange = AffectedVersionRange <$> genVersion <*> Gen.maybe genVersion

genVersion :: Gen.Gen Version
genVersion = mkVersion <$> Gen.list (Range.linear 1 5) (Gen.integral (Range.linear 0 999))

genArchitecture :: Gen.Gen Architecture
genArchitecture = Gen.enumBounded

genOS :: Gen.Gen OS
genOS = Gen.enumBounded

genKeyword :: Gen.Gen Keyword
genKeyword = Keyword <$> genText

genReference :: Gen.Gen Reference
genReference = Reference <$> genReferenceType <*> genText

genReferenceType :: Gen.Gen ReferenceType
genReferenceType = Gen.enumBounded
