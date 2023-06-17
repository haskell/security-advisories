{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Eta reduce" #-}

module Security.Advisories
  ( Advisory (..),
    parseAdvisory,
    ParseAdvisoryError (..),
    -- * Supporting types
    CWE (..),
    Architecture (..),
    OS (..),
    Date (..),
    Keyword (..),
  )
where

import Control.Monad (forM, (>=>))
import Control.Monad.Except
  ( ExceptT (ExceptT),
    MonadError,
    throwError,
  )
import Data.Bifunctor
import Data.Functor ((<&>))
import Data.Functor.Identity (Identity (Identity))
import Data.List.NonEmpty (NonEmpty (..))
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Sequence (Seq((:<|)))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Lazy as T (toStrict)
import Data.Time.Calendar
import Data.Tuple (swap)
import Distribution.Parsec (eitherParsec)
import Distribution.Types.VersionRange (VersionRange)
import GHC.Exts (IsList (..))
import GHC.Generics (Generic)

import Commonmark.Html (Html, renderHtml)
import qualified Commonmark.Parser as Commonmark
import Commonmark.Pandoc (Cm(unCm))
import qualified TOML
import Text.Pandoc.Builder (Blocks, Many(..))
import Text.Pandoc.Definition (Block(..), Inline(..), Pandoc(..))
import Text.Pandoc.Walk (query)

import Security.OSV (Reference(..), referenceTypes)

data ParseAdvisoryError
  = MarkdownError Commonmark.ParseError T.Text
  | MarkdownFormatError T.Text
  | TomlError TOML.TOMLError T.Text
  | AdvisoryError TableParseErr T.Text
  deriving stock (Eq, Show, Generic)

parseAdvisory :: Text -> Either ParseAdvisoryError Advisory
parseAdvisory raw = do
  markdown <-
    unCm
    <$> firstPretty MarkdownError (T.pack . show)
          (Commonmark.commonmark "input" raw :: Either Commonmark.ParseError (Cm () Blocks))
  (frontMatter, rest) <- first MarkdownFormatError $ advisoryDoc markdown
  let doc = Pandoc mempty rest
  !summary <- first MarkdownFormatError $ parseAdvisorySummary doc
  table <- firstPretty TomlError TOML.renderTOMLError $ TOML.decode frontMatter

  -- Re-parse input as HTML.  This will probably go away; we now store the
  -- Pandoc doc and can render that instead, where needed.
  html <-
    T.toStrict . renderHtml
    <$> firstPretty MarkdownError (T.pack . show)
          (Commonmark.commonmark "input" raw :: Either Commonmark.ParseError (Html ()))

  first (mkPretty AdvisoryError (T.pack . show)) $
    parseAdvisoryTable table doc summary html

  where firstPretty
          :: (e -> T.Text -> ParseAdvisoryError)
          -> (e -> T.Text)
          -> Either e a
          -> Either ParseAdvisoryError a
        firstPretty ctr pretty = first $ mkPretty ctr pretty 
        mkPretty
          :: (e -> T.Text -> ParseAdvisoryError)
          -> (e -> T.Text)
          -> e
          -> ParseAdvisoryError
        mkPretty ctr pretty x = ctr x $ pretty x

newtype CWE = CWE {unCWE :: Integer}
  deriving stock (Show)

data Architecture
  = AArch64
  | Alpha
  | Arm
  | HPPA
  | HPPA1_1
  | I386
  | IA64
  | M68K
  | MIPS
  | MIPSEB
  | MIPSEL
  | NIOS2
  | PowerPC
  | PowerPC64
  | PowerPC64LE
  | RISCV32
  | RISCV64
  | RS6000
  | S390
  | S390X
  | SH4
  | SPARC
  | SPARC64
  | VAX
  | X86_64
  deriving stock (Show)

data OS
  = Windows
  | MacOS
  | Linux
  | FreeBSD
  | Android
  | NetBSD
  | OpenBSD
  deriving stock (Show)

data Date = Date {dateYear :: Integer, dateMonth :: Int, dateDay :: Int}
  deriving stock (Show)

newtype Keyword = Keyword Text
  deriving stock (Eq, Ord)
  deriving (Show) via Text

data Advisory = Advisory
  { advisoryId :: Text,
    advisoryPackage :: Text,
    advisoryDate :: Date,
    advisoryCWEs :: [CWE],
    advisoryKeywords :: [Keyword],
    advisoryAliases :: [Text],
    advisoryCVSS :: Text,
    advisoryVersions :: [AffectedVersionRange],
    advisoryArchitectures :: Maybe [Architecture],
    advisoryOS :: Maybe [OS],
    advisoryNames :: [(Text, VersionRange)],
    advisoryReferences :: [Reference],
    advisoryPandoc :: Pandoc,  -- ^ Parsed document, without TOML front matter
    advisoryHtml :: Text,
    advisorySummary :: Text
  }
  deriving stock (Show)

data AffectedVersionRange = AffectedVersionRange
  { affectedVersionRangeIntroduced :: Text,
    affectedVersionRangeFixed :: Maybe Text
  }
  deriving stock (Show)

parseAdvisoryTable
  :: TOML.Table
  -> Pandoc -- ^ parsed document (without frontmatter)
  -> Text -- ^ summary
  -> Text -- ^ rendered HTML
  -> Either TableParseErr Advisory
parseAdvisoryTable table doc summary html = runTableParser $ do
  hasNoKeysBut ["advisory", "affected", "versions", "references"] table
  advisory <- mandatory table "advisory" isTable

  identifier <- mandatory advisory "id" isString
  package <- mandatory advisory "package" isString
  date <- mandatory advisory "date" isDate <&> uncurry3 Date . toGregorian
  cats <-
    fromMaybe []
      <$> optional advisory "cwe" (isArrayOf (fmap CWE . isInt))
  kwds <-
    fromMaybe []
      <$> optional advisory "keywords" (isArrayOf (fmap Keyword . isString))
  aliases <-
    fromMaybe []
      <$> optional advisory "aliases" (isArrayOf isString)
  cvss <- mandatory advisory "cvss" isString -- TODO validate CVSS format

  (os, arch, decls) <-
    optional table "affected" isTable >>= \case
      Nothing -> pure (Nothing, Nothing, [])
      Just tbl -> do
        os <-
          optional tbl "os" $
            isArrayOf (isString >=> operatingSystem)
        arch <-
          optional tbl "arch" $
            isArrayOf (isString >=> architecture)
        decls <-
          maybe [] Map.toList
            <$> optional tbl "declarations" (isTableOf versionRange)
        pure (os, arch, decls)

  versions <- mandatory table "versions" isArray
  affectedVersionsRange <- forM versions $ \version -> do
    versionTable <- isTable version
    introduced <- mandatory versionTable "introduced" isString
    fixed <- optional versionTable "fixed" isString
    pure $ AffectedVersionRange introduced fixed

  references <- mandatory table "references" (isArrayOf parseReference)

  pure $ Advisory
      { advisoryId = identifier,
        advisoryPackage = package,
        advisoryDate = date,
        advisoryCWEs = cats,
        advisoryKeywords = kwds,
        advisoryAliases = aliases,
        advisoryCVSS = cvss,
        advisoryVersions = affectedVersionsRange,
        advisoryArchitectures = arch,
        advisoryOS = os,
        advisoryNames = decls,
        advisoryReferences = references,
        advisoryPandoc = doc,
        advisoryHtml = html,
        advisorySummary = summary
      }

parseReference :: TOML.Value -> TableParser Reference
parseReference v = do
  tbl <- isTable v
  refTypeStr <- mandatory tbl "type" isString
  refType <- case lookup refTypeStr (fmap swap referenceTypes) of
    Just a -> pure a
    Nothing -> throwError $ InvalidFormat "reference.type" refTypeStr
  url <- mandatory tbl "url" isString
  pure $ Reference refType url

uncurry3 :: (a -> b -> c -> d) -> (a, b, c) -> d
uncurry3 f (x, y, z) = f x y z

operatingSystem :: Text -> TableParser OS
operatingSystem "darwin" = pure MacOS
operatingSystem "freebsd" = pure FreeBSD
operatingSystem "linux" = pure Linux
operatingSystem "linux-android" = pure Android
operatingSystem "mingw32" = pure Windows
operatingSystem "netbsd" = pure NetBSD
operatingSystem "openbsd" = pure OpenBSD
operatingSystem other = throwError $ InvalidOS other

architecture :: Text -> TableParser Architecture
architecture "aarch64" = pure AArch64
architecture "alpha" = pure Alpha
architecture "arm" = pure Arm
architecture "hppa" = pure HPPA
architecture "hppa1_1" = pure HPPA1_1
architecture "i386" = pure I386
architecture "ia64" = pure IA64
architecture "m68k" = pure M68K
architecture "mips" = pure MIPS
architecture "mipseb" = pure MIPSEB
architecture "mipsel" = pure MIPSEL
architecture "nios2" = pure NIOS2
architecture "powerpc" = pure PowerPC
architecture "powerpc64" = pure PowerPC64
architecture "powerpc64le" = pure PowerPC64LE
architecture "riscv32" = pure RISCV32
architecture "riscv64" = pure RISCV64
architecture "rs6000" = pure RS6000
architecture "s390" = pure S390
architecture "s390x" = pure S390X
architecture "sh4" = pure SH4
architecture "sparc" = pure SPARC
architecture "sparc64" = pure SPARC64
architecture "vax" = pure VAX
architecture "x86_64" = pure X86_64
architecture other = throwError $ InvalidArchitecture other

versionRange :: TOML.Value -> TableParser VersionRange
versionRange =
  isString >=> \v ->
    case eitherParsec (T.unpack v) of
      Left err -> throwError $ UnderlyingParserError (T.pack err)
      Right affected -> pure affected

data TableParseErr
  = UnexpectedKeys (NonEmpty Text)
  | MissingKey Text
  | InvalidFormat Text Text
  | InvalidOS Text
  | InvalidArchitecture Text
  | UnderlyingParserError Text
  deriving stock (Eq, Show)

newtype TableParser a = TableParser {runTableParser :: Either TableParseErr a}
  deriving stock (Show)
  deriving
    ( Functor,
      Applicative,
      Monad,
      MonadError TableParseErr
    )
    via ExceptT TableParseErr Identity

hasNoKeysBut :: [Text] -> TOML.Table -> TableParser ()
hasNoKeysBut keys tbl =
  let keySet = Set.fromList keys
      tblKeySet = Set.fromList (Map.keys tbl)
      extra = Set.toList $ Set.difference tblKeySet keySet
   in case extra of
        [] -> pure ()
        k : ks -> throwError (UnexpectedKeys $ k :| ks)

optional ::
  TOML.Table ->
  Text ->
  (TOML.Value -> TableParser a) ->
  TableParser (Maybe a)
optional tbl k act =
  onKey tbl k (pure Nothing) (fmap Just . act)

mandatory ::
  TOML.Table ->
  Text ->
  (TOML.Value -> TableParser a) ->
  TableParser a
mandatory tbl k act =
  onKey tbl k (throwError $ MissingKey k) act

onKey ::
  TOML.Table ->
  Text ->
  TableParser a ->
  (TOML.Value -> TableParser a) ->
  TableParser a
onKey tbl k absent present =
  maybe absent present $ Map.lookup k tbl

isInt :: TOML.Value -> TableParser Integer
isInt (TOML.Integer i) = pure i
isInt other = throwError $ InvalidFormat "Integer" (describeValue other)

isString :: TOML.Value -> TableParser Text
isString (TOML.String txt) = pure txt
isString other = throwError $ InvalidFormat "String" (describeValue other)

isTable :: TOML.Value -> TableParser TOML.Table
isTable (TOML.Table table) = pure table
isTable other = throwError $ InvalidFormat "Table" (describeValue other)

isTableOf ::
  (TOML.Value -> TableParser a) ->
  TOML.Value ->
  TableParser (Map Text a)
isTableOf elt (TOML.Table table) =
  traverse elt table
isTableOf _ other =
  throwError $ InvalidFormat "Table" (describeValue other)

isDate :: TOML.Value -> TableParser Day
isDate (TOML.LocalDate time) = pure time
isDate other = throwError $ InvalidFormat "Date/time" (describeValue other)

isArray :: TOML.Value -> TableParser [TOML.Value]
isArray (TOML.Array arr) = pure arr
isArray other = throwError $ InvalidFormat "Array" (describeValue other)

isArrayOf ::
  (TOML.Value -> TableParser a) ->
  TOML.Value ->
  TableParser [a]
isArrayOf elt v =
  isArray v >>= traverse elt . toList

describeValue :: TOML.Value -> Text
describeValue TOML.String {} = "string"
describeValue TOML.Table {} = "table"
describeValue TOML.Integer {} = "integer"
describeValue TOML.Float {} = "float"
describeValue TOML.Boolean {} = "boolean"
describeValue TOML.Array {} = "array"
describeValue TOML.OffsetDateTime {} = "date/time with offset"
describeValue TOML.LocalDateTime {} = "local date/time"
describeValue TOML.LocalDate {} = "local date"
describeValue TOML.LocalTime {} = "local time"

advisoryDoc :: Blocks -> Either Text (Text, [Block])
advisoryDoc (Many blocks) = case blocks of
  CodeBlock (_, classes, _) frontMatter :<| t
    | "toml" `elem` classes
    -> pure (frontMatter, toList t)
  _
    -> Left "Does not have toml code block as first element"

parseAdvisorySummary :: Pandoc -> Either Text Text
parseAdvisorySummary = fmap inlineText . firstHeading

firstHeading :: Pandoc -> Either Text [Inline]
firstHeading (Pandoc _ xs) = go xs
  where
  go [] = Left "Does not have summary heading"
  go (Header _ _ ys : _) = Right ys
  go (_ : t) = go t

-- yield "plain" terminal inline content; discard formatting
inlineText :: [Inline] -> Text
inlineText = query f
  where
  f inl = case inl of
    Str s -> s
    Code _ s -> s
    Space -> " "
    SoftBreak -> " "
    LineBreak -> "\n"
    Math _ s -> s
    RawInline _ s -> s
    _ -> ""
