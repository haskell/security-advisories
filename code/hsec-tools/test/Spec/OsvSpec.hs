{-# LANGUAGE OverloadedStrings #-}

module Spec.OsvSpec (spec) where

import Data.Aeson (decode, encode)
import Data.ByteString.Lazy (toStrict)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Security.Advisories.Convert.OSV
import Security.Advisories.Core.Advisory
import Test.Tasty
import Test.Tasty.Hedgehog
import qualified Hedgehog as Gen
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

spec :: TestTree
spec =
  testGroup
    "OSV"
    [ testGroup
        "AffectedApi"
        [ testProperty "JSON roundtrip" $
            Gen.property $ do
              api <- Gen.forAll genAffectedApi
              let encoded = encode api
                  decoded = decode encoded
              Just api Gen.=== decoded
        ]
    , testGroup
        "HsecEcosystemSpecific"
        [ testProperty "JSON roundtrip" $
            Gen.property $ do
              ecs <- Gen.forAll genHsecEcosystemSpecific
              let encoded = encode ecs
                  decoded = decode encoded
              Just ecs Gen.=== decoded
        , testProperty "encodes affected_api key" $
            Gen.property $ do
              apis <- Gen.forAll (Gen.list (Range.linear 1 5) genAffectedApi)
              let ecs = HsecEcosystemSpecific apis
                  jsonBytes = encode ecs
                  jsonText = TE.decodeUtf8 (toStrict jsonBytes)
              Gen.assert $ "affected_api" `T.isInfixOf` jsonText
        , testProperty "Nothing when empty" $
            Gen.property $ do
              let ecs = HsecEcosystemSpecific []
                  jsonBytes = encode ecs
                  jsonText = TE.decodeUtf8 (toStrict jsonBytes)
              Gen.assert $ "affected_api" `T.isInfixOf` jsonText
        ]
    ]

genAffectedApi :: Gen.Gen AffectedApi
genAffectedApi = AffectedApi <$> genText <*> genText

genHsecEcosystemSpecific :: Gen.Gen HsecEcosystemSpecific
genHsecEcosystemSpecific = HsecEcosystemSpecific <$> Gen.list (Range.linear 0 5) genAffectedApi

genText :: Gen.Gen T.Text
genText = Gen.text (Range.linear 1 20) Gen.alphaNum
