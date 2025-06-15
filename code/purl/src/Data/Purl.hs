{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | This module provides support for the purl specification: <https://github.com/package-url/purl-spec>
module Data.Purl (
    -- * Types
    Purl (..),
    PurlScheme (..),
    PurlType (..),
    PurlNamespace (..),
    PurlName (..),
    PurlVersion (..),
    PurlQualifierKey (..),
    PurlQualifierValue (..),
    PurlSubPath (..),

    -- * Helpers
    newPurl,
    newPurlHackage,
    newPurlGhc,
    newPurlOther,
    addPurlQuantifier,
    addPurlQuantifiers,
    findPurlQuantifiers,

    -- * Parsers
    parsePurl,
    purlP,
    purlSchemeP,
    purlTypeP,
    purlNamespaceP,
    purlNameP,
    purlVersionP,
    purlQualifiersP,
    purlSubPathP,

    -- * Renderers
    purlText,

    -- * instances
    FromJSON (..),
    ToJSON (..),
)
where

import Control.Monad (guard)
import Data.Aeson
import Data.CaseInsensitive (CI, mk, original)
import Data.Char
import Data.List (nub)
import Data.Map.Strict qualified as M
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import GHC.Generics
import Network.HTTP.Types (urlDecode)
import Text.Parsec

-- * Types

{- | Purl representation
scheme:type/namespace/name@version?qualifiers#subpath
-}
data Purl = Purl
    { purlScheme :: PurlScheme
    , purlType :: PurlType
    , purlNamespace :: Maybe PurlNamespace
    , purlName :: PurlName
    , purlVersion :: Maybe PurlVersion
    , purlQualifiers :: M.Map PurlQualifierKey PurlQualifierValue
    , purlSubPath :: Maybe PurlSubPath
    }
    deriving stock (Eq, Show, Generic)

-- | scheme: this is the URL scheme with the constant value of "pkg".
data PurlScheme
    = Pkg
    deriving stock (Eq, Show, Generic)

-- | type: the package "type" or package "protocol" such as maven, npm, nuget, gem, pypi, etc.
data PurlType
    = Hackage
    | Ghc
    | OtherType (CI Text)
    deriving stock (Eq, Show, Generic)

-- | namespace: some name prefix such as a Maven groupid, a Docker image owner, a GitHub user or organization.
newtype PurlNamespace = PurlNamespace {unPurlNamespace :: [Text]}
    deriving newtype (Eq)

instance Show PurlNamespace where
    showsPrec n = showsPrec n . T.intercalate "/" . unPurlNamespace

-- | name: the name of the package.
newtype PurlName = PurlName {unPurlName :: Text}
    deriving newtype (Eq, Show)

-- | version: the version of the package.
newtype PurlVersion = PurlVersion {unPurlVersion :: Text}
    deriving newtype (Eq, Show)

-- | qualifier: extra qualifying data for a package such as an OS, architecture, a distro, etc.
newtype PurlQualifierKey = PurlQualifierKey {unPurlQualifierKey :: Text}
    deriving newtype (Eq, Ord, Show)

-- | qualifier: extra qualifying data for a package such as an OS, architecture, a distro, etc.
newtype PurlQualifierValue = PurlQualifierValue {unPurlQualifierValue :: Text}
    deriving newtype (Eq, Ord, Show)

-- | subpath: extra subpath within a package, relative to the package root.
newtype PurlSubPath = PurlSubPath {unPurlSubPath :: [Text]}
    deriving newtype (Eq)

instance Show PurlSubPath where
    showsPrec n = showsPrec n . T.intercalate "/" . unPurlSubPath

-- * Helpers

-- | Create a minimal 'Purl'
newPurl :: PurlType -> PurlName -> Purl
newPurl pType pName =
    Purl
        { purlScheme = Pkg
        , purlType = pType
        , purlNamespace = Nothing
        , purlName = pName
        , purlVersion = Nothing
        , purlQualifiers = mempty
        , purlSubPath = Nothing
        }

-- | Create a minimal 'Purl' of type 'Hackage'
newPurlHackage :: PurlName -> Purl
newPurlHackage = newPurl Hackage

-- | Create a minimal 'Purl' of type 'GHC'
newPurlGhc :: PurlName -> Purl
newPurlGhc = newPurl Ghc

-- | Create a minimal 'Purl' of type 'Other'
newPurlOther :: Text -> PurlName -> Purl
newPurlOther other = newPurl (OtherType $ mk other)

-- | Prepend a qualifiers
addPurlQuantifier :: PurlQualifierKey -> PurlQualifierValue -> Purl -> Purl
addPurlQuantifier k v = addPurlQuantifiers [(k, v)]

-- | Prepend a list of qualifiers
addPurlQuantifiers :: [(PurlQualifierKey, PurlQualifierValue)] -> Purl -> Purl
addPurlQuantifiers xs p = p{purlQualifiers = M.fromList xs <> purlQualifiers p}

-- | Find all the 'PurlQualifierValue' associated to a 'PurlQualifierKey'
findPurlQuantifiers :: PurlQualifierKey -> Purl -> Maybe PurlQualifierValue
findPurlQuantifiers k = M.lookup k . purlQualifiers

-- * Parsers

parsePurl :: Text -> Either ParseError Purl
parsePurl = runParser purlP () "parsePurl"

{- | Parses the whole 'Purl'
scheme:type/namespace/name@version?qualifiers#subpath
-}
purlP :: Parsec Text u Purl
purlP =
    Purl
        <$> purlSchemeP
        <*> purlTypeP
        <*> optionMaybe purlNamespaceP
        <*> purlNameP
        <*> optionMaybe purlVersionP
        <*> purlQualifiersP
        <*> purlSubPathP

-- | Parses the constant scheme "pkg:"
purlSchemeP :: Parsec Text u PurlScheme
purlSchemeP = Pkg <$ (string "pkg:" *> many (char '/'))

-- | Parses the package type
purlTypeP :: Parsec Text u PurlType
purlTypeP = toType <$> purlTypeStr <* char '/'
  where
    purlTypeStr = do
        first <- satisfy isAsciiLetter
        rest <- takeWhileP isTypeChar
        return $ T.toLower (first `T.cons` rest)

    isAsciiLetter c = isAscii c && isLetter c
    isTypeChar c = isAscii c && (isAlphaNum c || c `elem` (".+-" :: String))

    toType =
        \case
            "hackage" -> Hackage
            "ghc" -> Ghc
            other -> OtherType $ mk other

-- | Parses the optional namespace, stripping leading/trailing slashes and decoding segments
purlNamespaceP :: Parsec Text u PurlNamespace
purlNamespaceP = do
    raw <- many $ try $ takeWhile1P (`notElem` ("/@?#" :: String)) <* char '/'
    let decoded = mapMaybe decodeSegment raw
    guard $ not $ null decoded
    return . PurlNamespace $ decoded
  where
    decodeSegment seg
        | T.null seg = Nothing
        | '/' `elem` T.unpack (unescapeURL seg) = Nothing
        | otherwise = Just seg

-- | Parses the package name (percent-decoded)
purlNameP :: Parsec Text u PurlName
purlNameP = PurlName <$> takeWhile1P notTerminator
  where
    notTerminator c = c /= '@' && c /= '?' && c /= '#'

-- | Parses the optional version (percent-decoded), prefixed by '@'
purlVersionP :: Parsec Text u PurlVersion
purlVersionP = char '@' *> (PurlVersion <$> takeWhile1P notTerminator)
  where
    notTerminator c = c /= '?' && c /= '#'

-- | Parses the optional list of qualifiers prefixed by '?'
purlQualifiersP :: Parsec Text u (M.Map PurlQualifierKey PurlQualifierValue)
purlQualifiersP = option mempty $ char '?' *> qualifiers
  where
    qualifiers = do
        qualifierPairs <- sepBy1 qualifier (char '&')
        let keys = map fst qualifierPairs
        guard (length keys == length (nub keys))
        return $ M.fromList qualifierPairs

    qualifier = do
        key <- takeWhile1P isKeyChar
        guard (not (T.null key) && isAsciiLetter (T.head key))
        _ <- char '='
        val <- takeWhile1P (/= '&')
        guard (not (T.null val))
        return (PurlQualifierKey key, PurlQualifierValue val)

    isAsciiLetter c = isAscii c && isLetter c
    isKeyChar c = isAscii c && (isAlphaNum c || c `elem` (".-_" :: String))

-- | Parses the optional subpath (percent-decoded and normalized), prefixed by '#'
purlSubPathP :: Parsec Text u (Maybe PurlSubPath)
purlSubPathP = optionMaybe $ char '#' *> (PurlSubPath <$> segments)
  where
    segments = do
        rawSegs <- takeWhileP (/= '/') `sepBy` char '/'
        let decoded = mapMaybe decodeSegment rawSegs
        guard (not (null decoded))
        return decoded

    decodeSegment seg =
        let s = unescapeURL seg
         in if T.null s || s == "." || s == ".." || "/" `T.isInfixOf` s
                then Nothing
                else Just s

-- * Parsing helpers

takeWhileP :: (Char -> Bool) -> Parsec Text u Text
takeWhileP f = T.pack <$> many (satisfy f)

takeWhile1P :: (Char -> Bool) -> Parsec Text u Text
takeWhile1P f = T.pack <$> many1 (satisfy f)

unescapeURL :: Text -> Text
unescapeURL = TE.decodeUtf8 . urlDecode True . TE.encodeUtf8

-- * Renderers
purlText :: Purl -> Text
purlText purl =
    T.concat
        [ renderedPackage
        , renderedType
        , renderedNamespace
        , renderedName
        , renderedVersion
        , renderedQuelifiers
        , renderedSubPath
        ]
  where
    renderedPackage = "pkg:"
    renderedType =
        case purlType purl of
            Hackage -> "hackage"
            Ghc -> "ghc"
            OtherType x -> T.toCaseFold $ original x
    renderedNamespace =
        maybe "" (("/" <>) . T.intercalate "/" . unPurlNamespace) $ purlNamespace purl
    renderedName =
        "/" <> unPurlName (purlName purl)
    renderedVersion = maybe "" (("@" <>) . unPurlVersion) $ purlVersion purl
    renderedQuelifiers =
        if M.null (purlQualifiers purl)
            then ""
            else
                "?"
                    <> T.intercalate
                        "&"
                        ( map (\(PurlQualifierKey k, PurlQualifierValue v) -> k <> "=" <> v) $
                            M.toList (purlQualifiers purl)
                        )
    renderedSubPath = maybe "" (("#" <>) . T.intercalate "/" . unPurlSubPath) $ purlSubPath purl

-- * instances

instance ToJSON Purl where
    toJSON = toJSON . purlText
    toEncoding = toEncoding . purlText

instance FromJSON Purl where
    parseJSON =
        withText "Purl" $ either (fail . show) return . parsePurl
