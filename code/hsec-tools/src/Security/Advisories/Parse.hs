{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}

module Security.Advisories.Parse
  ( parseAdvisory
  , ParseAdvisoryError(..)
  , TableParseError(..)
  )
  where

import Control.Monad ((>=>))
import Data.Bifunctor (first)
import Data.Foldable (toList)
import Data.Functor ((<&>))
import Data.Functor.Identity (Identity(Identity))
import Data.List.NonEmpty (NonEmpty(..))
import Data.Maybe (fromMaybe)
import Data.Traversable (for)
import Data.Tuple (swap)
import GHC.Generics (Generic)

import Control.Monad.Except
  ( ExceptT (ExceptT)
  , MonadError
  , throwError
  )
import qualified Data.Map as Map
import Data.Sequence (Seq((:<|)))
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Lazy as T (toStrict)
import Data.Time.Calendar
import Distribution.Parsec (eitherParsec)
import Distribution.Types.VersionRange (VersionRange)

import Commonmark.Html (Html, renderHtml)
import qualified Commonmark.Parser as Commonmark
import Commonmark.Pandoc (Cm(unCm))
import qualified TOML
import Text.Pandoc.Builder (Blocks, Many(..))
import Text.Pandoc.Definition (Block(..), Inline(..), Pandoc(..))
import Text.Pandoc.Walk (query)

import Security.Advisories.Definition
import Security.OSV (Reference(..), referenceTypes)

data ParseAdvisoryError
  = MarkdownError Commonmark.ParseError T.Text
  | MarkdownFormatError T.Text
  | TomlError TOML.TOMLError T.Text
  | AdvisoryError TableParseError T.Text
  deriving stock (Eq, Show, Generic)

parseAdvisory :: T.Text -> Either ParseAdvisoryError Advisory
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

  where
    firstPretty
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

parseAdvisoryTable
  :: TOML.Table
  -> Pandoc -- ^ parsed document (without frontmatter)
  -> T.Text -- ^ summary
  -> T.Text -- ^ rendered HTML
  -> Either TableParseError Advisory
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
  affectedVersionsRange <- for versions $ \version -> do
    versionTable <- isTable version
    introduced <- mandatory versionTable "introduced" isString
    fixed <- optional versionTable "fixed" isString
    pure $ AffectedVersionRange introduced fixed

  references <- mandatory table "references" (isArrayOf parseReference)

  pure $ Advisory
    { advisoryId = identifier
    , advisoryPackage = package
    , advisoryDate = date
    , advisoryCWEs = cats
    , advisoryKeywords = kwds
    , advisoryAliases = aliases
    , advisoryCVSS = cvss
    , advisoryVersions = affectedVersionsRange
    , advisoryArchitectures = arch
    , advisoryOS = os
    , advisoryNames = decls
    , advisoryReferences = references
    , advisoryPandoc = doc
    , advisoryHtml = html
    , advisorySummary = summary
    }

advisoryDoc :: Blocks -> Either T.Text (T.Text, [Block])
advisoryDoc (Many blocks) = case blocks of
  CodeBlock (_, classes, _) frontMatter :<| t
    | "toml" `elem` classes
    -> pure (frontMatter, toList t)
  _
    -> Left "Does not have toml code block as first element"

parseAdvisorySummary :: Pandoc -> Either T.Text T.Text
parseAdvisorySummary = fmap inlineText . firstHeading

firstHeading :: Pandoc -> Either T.Text [Inline]
firstHeading (Pandoc _ xs) = go xs
  where
  go [] = Left "Does not have summary heading"
  go (Header _ _ ys : _) = Right ys
  go (_ : t) = go t

-- yield "plain" terminal inline content; discard formatting
inlineText :: [Inline] -> T.Text
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

operatingSystem :: T.Text -> TableParser OS
operatingSystem = \case
  "darwin" -> pure MacOS
  "freebsd" -> pure FreeBSD
  "linux" -> pure Linux
  "linux-android" -> pure Android
  "mingw32" -> pure Windows
  "netbsd" -> pure NetBSD
  "openbsd" -> pure OpenBSD
  other -> throwError $ InvalidOS other

architecture :: T.Text -> TableParser Architecture
architecture = \case
  "aarch64" -> pure AArch64
  "alpha" -> pure Alpha
  "arm" -> pure Arm
  "hppa" -> pure HPPA
  "hppa1_1" -> pure HPPA1_1
  "i386" -> pure I386
  "ia64" -> pure IA64
  "m68k" -> pure M68K
  "mips" -> pure MIPS
  "mipseb" -> pure MIPSEB
  "mipsel" -> pure MIPSEL
  "nios2" -> pure NIOS2
  "powerpc" -> pure PowerPC
  "powerpc64" -> pure PowerPC64
  "powerpc64le" -> pure PowerPC64LE
  "riscv32" -> pure RISCV32
  "riscv64" -> pure RISCV64
  "rs6000" -> pure RS6000
  "s390" -> pure S390
  "s390x" -> pure S390X
  "sh4" -> pure SH4
  "sparc" -> pure SPARC
  "sparc64" -> pure SPARC64
  "vax" -> pure VAX
  "x86_64" -> pure X86_64
  other -> throwError $ InvalidArchitecture other

versionRange :: TOML.Value -> TableParser VersionRange
versionRange =
  isString >=> \v ->
    case eitherParsec (T.unpack v) of
      Left err -> throwError $ UnderlyingParserError (T.pack err)
      Right affected -> pure affected

data TableParseError
  = UnexpectedKeys (NonEmpty T.Text)
  | MissingKey T.Text
  | InvalidFormat T.Text T.Text
  | InvalidOS T.Text
  | InvalidArchitecture T.Text
  | UnderlyingParserError T.Text
  deriving stock (Eq, Show)

newtype TableParser a = TableParser {runTableParser :: Either TableParseError a}
  deriving stock (Show)
  deriving
    ( Functor,
      Applicative,
      Monad,
      MonadError TableParseError
    )
    via ExceptT TableParseError Identity

hasNoKeysBut :: [T.Text] -> TOML.Table -> TableParser ()
hasNoKeysBut keys tbl =
  let keySet = Set.fromList keys
      tblKeySet = Set.fromList (Map.keys tbl)
      extra = Set.toList $ Set.difference tblKeySet keySet
   in case extra of
        [] -> pure ()
        k : ks -> throwError (UnexpectedKeys $ k :| ks)

optional ::
  TOML.Table ->
  T.Text ->
  (TOML.Value -> TableParser a) ->
  TableParser (Maybe a)
optional tbl k act =
  onKey tbl k (pure Nothing) (fmap Just . act)

mandatory ::
  TOML.Table ->
  T.Text ->
  (TOML.Value -> TableParser a) ->
  TableParser a
mandatory tbl k =
  onKey tbl k (throwError $ MissingKey k)

onKey ::
  TOML.Table ->
  T.Text ->
  TableParser a ->
  (TOML.Value -> TableParser a) ->
  TableParser a
onKey tbl k absent present =
  maybe absent present $ Map.lookup k tbl

isInt :: TOML.Value -> TableParser Integer
isInt (TOML.Integer i) = pure i
isInt other = throwError $ InvalidFormat "Integer" (describeValue other)

isString :: TOML.Value -> TableParser T.Text
isString (TOML.String txt) = pure txt
isString other = throwError $ InvalidFormat "String" (describeValue other)

isTable :: TOML.Value -> TableParser TOML.Table
isTable (TOML.Table table) = pure table
isTable other = throwError $ InvalidFormat "Table" (describeValue other)

isTableOf ::
  (TOML.Value -> TableParser a) ->
  TOML.Value ->
  TableParser (Map.Map T.Text a)
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

describeValue :: TOML.Value -> T.Text
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
