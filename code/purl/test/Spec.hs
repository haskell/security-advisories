{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import Data.Bifunctor (Bifunctor (bimap))
import Data.Map.Strict qualified as M
import Data.Purl
import Data.Text (Text)
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain $
    testCase "Data.Purl" $ do
        forM_ examples $ \(purlString, expectedPurl) -> do
            case parsePurl purlString of
                Left e -> assertFailure (show e)
                Right purl -> do
                    purl @?= expectedPurl
                    purlText purl @?= purlString

examples :: [(Text, Purl)]
examples =
    [
        ( "pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c"
        , (newPurlOther "bitbucket" (PurlName "pygments-main"))
            { purlNamespace = Just $ PurlNamespace ["birkenfeld"]
            , purlVersion = Just $ PurlVersion "244fd47e07d1014f0aed9c"
            }
        )
    ,
        ( "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie"
        , (newPurlOther "deb" (PurlName "curl"))
            { purlNamespace = Just $ PurlNamespace ["debian"]
            , purlVersion = Just $ PurlVersion "7.50.3-1"
            , purlQualifiers = mkQualifiers [("arch", "i386"), ("distro", "jessie")]
            }
        )
    ,
        ( "pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c"
        , (newPurlOther "docker" (PurlName "cassandra"))
            { purlVersion = Just $ PurlVersion "sha256:244fd47e07d1004f0aed9c"
            }
        )
    ,
        ( "pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io"
        , (newPurlOther "docker" (PurlName "dockerimage"))
            { purlNamespace = Just $ PurlNamespace ["customer"]
            , purlVersion = Just $ PurlVersion "sha256:244fd47e07d1004f0aed9c"
            , purlQualifiers = mkQualifiers [("repository_url", "gcr.io")]
            }
        )
    ,
        ( "pkg:gem/jruby-launcher@1.1.2?platform=java"
        , (newPurlOther "gem" (PurlName "jruby-launcher"))
            { purlVersion = Just $ PurlVersion "1.1.2"
            , purlQualifiers = mkQualifiers [("platform", "java")]
            }
        )
    ,
        ( "pkg:gem/ruby-advisory-db-check@0.12.4"
        , (newPurlOther "gem" (PurlName "ruby-advisory-db-check"))
            { purlVersion = Just $ PurlVersion "0.12.4"
            }
        )
    ,
        ( "pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c"
        , (newPurlOther "github" (PurlName "purl-spec"))
            { purlNamespace = Just $ PurlNamespace ["package-url"]
            , purlVersion = Just $ PurlVersion "244fd47e07d1004f0aed9c"
            }
        )
    ,
        ( "pkg:golang/google.golang.org/genproto#googleapis/api/annotations"
        , (newPurlOther "golang" (PurlName "genproto"))
            { purlNamespace = Just $ PurlNamespace ["google.golang.org"]
            , purlSubPath = Just $ PurlSubPath ["googleapis", "api", "annotations"]
            }
        )
    ,
        ( "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources"
        , (newPurlOther "maven" (PurlName "batik-anim"))
            { purlNamespace = Just $ PurlNamespace ["org.apache.xmlgraphics"]
            , purlVersion = Just $ PurlVersion "1.9.1"
            , purlQualifiers = mkQualifiers [("packaging", "sources")]
            }
        )
    ,
        ( "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?repository_url=repo.spring.io/release"
        , (newPurlOther "maven" (PurlName "batik-anim"))
            { purlNamespace = Just $ PurlNamespace ["org.apache.xmlgraphics"]
            , purlVersion = Just $ PurlVersion "1.9.1"
            , purlQualifiers = mkQualifiers [("repository_url", "repo.spring.io/release")]
            }
        )
    ,
        ( "pkg:golang/google.golang.org/genproto#googleapis/api/annotations"
        , (newPurlOther "golang" (PurlName "genproto"))
            { purlNamespace = Just $ PurlNamespace ["google.golang.org"]
            , purlSubPath = Just $ PurlSubPath ["googleapis", "api", "annotations"]
            }
        )
    ,
        ( "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources"
        , (newPurlOther "maven" (PurlName "batik-anim"))
            { purlNamespace = Just $ PurlNamespace ["org.apache.xmlgraphics"]
            , purlVersion = Just $ PurlVersion "1.9.1"
            , purlQualifiers = mkQualifiers [("packaging", "sources")]
            }
        )
    ,
        ( "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?repository_url=repo.spring.io/release"
        , (newPurlOther "maven" (PurlName "batik-anim"))
            { purlNamespace = Just $ PurlNamespace ["org.apache.xmlgraphics"]
            , purlVersion = Just $ PurlVersion "1.9.1"
            , purlQualifiers = mkQualifiers [("repository_url", "repo.spring.io/release")]
            }
        )
    ,
        ( "pkg:npm/%40angular/animation@12.3.1"
        , (newPurlOther "npm" (PurlName "animation"))
            { purlNamespace = Just $ PurlNamespace ["%40angular"]
            , purlVersion = Just $ PurlVersion "12.3.1"
            }
        )
    ,
        ( "pkg:npm/foobar@12.3.1"
        , (newPurlOther "npm" (PurlName "foobar"))
            { purlVersion = Just $ PurlVersion "12.3.1"
            }
        )
    ,
        ( "pkg:nuget/EnterpriseLibrary.Common@6.0.1304"
        , (newPurlOther "nuget" (PurlName "EnterpriseLibrary.Common"))
            { purlVersion = Just $ PurlVersion "6.0.1304"
            }
        )
    ,
        ( "pkg:pypi/django@1.11.1"
        , (newPurlOther "pypi" (PurlName "django"))
            { purlVersion = Just $ PurlVersion "1.11.1"
            }
        )
    ,
        ( "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        , (newPurlOther "rpm" (PurlName "curl"))
            { purlNamespace = Just $ PurlNamespace ["fedora"]
            , purlVersion = Just $ PurlVersion "7.50.3-1.fc25"
            , purlQualifiers = mkQualifiers [("arch", "i386"), ("distro", "fedora-25")]
            }
        )
    ,
        ( "pkg:rpm/opensuse/curl@7.56.1-1.1.?arch=i386&distro=opensuse-tumbleweed"
        , (newPurlOther "rpm" (PurlName "curl"))
            { purlNamespace = Just $ PurlNamespace ["opensuse"]
            , purlVersion = Just $ PurlVersion "7.56.1-1.1."
            , purlQualifiers = mkQualifiers [("arch", "i386"), ("distro", "opensuse-tumbleweed")]
            }
        )
    ]
  where
    mkQualifiers = M.fromList . map (bimap PurlQualifierKey PurlQualifierValue)
