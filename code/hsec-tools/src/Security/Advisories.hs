{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Eta reduce" #-}

module Security.Advisories
  ( Advisory (..),
    parseAdvisory,
    ParseAdvisoryError (..),
    renderAdvisoryHtml,
    -- * Supporting types
    CWE (..),
    Architecture (..),
    OS (..),
    Date (..),
    Keyword (..),
  )
where

import Commonmark.Html (Html, renderHtml)
import qualified Commonmark.Parser as Commonmark
import Commonmark.Types
  ( Attributes,
    Format,
    HasAttributes (..),
    IsBlock (..),
    IsInline (..),
    ListSpacing,
    ListType,
    Rangeable (..),
    SourceRange,
  )
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
import Data.Monoid
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Lazy as T (toStrict)
import Data.Time.Calendar
import Data.Tuple (swap)
import Distribution.Parsec (eitherParsec)
import Distribution.Types.VersionRange (VersionRange)
import GHC.Exts (IsList (..))
import GHC.Generics (Generic)
import qualified TOML

import Security.OSV (Reference(..), referenceTypes)

data ParseAdvisoryError
  = MarkdownError Commonmark.ParseError T.Text
  | MarkdownFormatError T.Text
  | TomlError TOML.TOMLError T.Text
  | AdvisoryError TableParseErr T.Text
  deriving stock (Eq, Show, Generic)

parseAdvisory :: Text -> Either ParseAdvisoryError Advisory
parseAdvisory raw = do
  markdown <- firstPretty MarkdownError (T.pack . show) $ Commonmark.commonmark "input" raw
  (frontMatter, text) <- first MarkdownFormatError $ advisoryDoc markdown
  !summary <- first MarkdownFormatError $ parseAdvisorySummary text
  table <- firstPretty TomlError TOML.renderTOMLError $ TOML.decode frontMatter
  bimap (mkPretty AdvisoryError (T.pack . show)) ($ T.toStrict $ renderHtml (fromBlock text :: Html ())) $
    parseAdvisoryTable table summary
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
    advisoryHtml :: Text,
    advisorySummary :: Text
  }
  deriving stock (Show)

data AffectedVersionRange = AffectedVersionRange
  { affectedVersionRangeIntroduced :: Text,
    affectedVersionRangeFixed :: Maybe Text
  }
  deriving stock (Show)

renderAdvisoryHtml :: Advisory -> Text
renderAdvisoryHtml adv =
  T.unlines
    [ "<table>",
      T.unlines $
        map
          tr
          [ row "ID" advisoryId,
            row "Package" advisoryPackage,
            row "Date" (date . advisoryDate),
            row "CWEs" (T.intercalate ", " . map (T.pack . show . unCWE) . advisoryCWEs),
            row "Keywords" (T.intercalate ", " . map (T.pack . show) . advisoryKeywords),
            row "Aliases" (T.intercalate ", " . advisoryAliases),
            row "CVSS" advisoryCVSS,
            row "Versions" (T.pack . show . advisoryVersions),
            row
              "Architectures"
              ( maybe
                  "All"
                  ( T.intercalate ", "
                      . map (T.pack . show)
                  )
                  . advisoryArchitectures
              ),
            row "OS" (maybe "All" (T.intercalate ", " . map (T.pack . show)) . advisoryOS),
            row
              "Affected exports"
              ( T.intercalate ", "
                  . map (\(name, version) -> name <> " in " <> T.pack (show version))
                  . advisoryNames
              )
          ]
          <> fmap refRow (advisoryReferences adv)
          ,
      "</table>",
      advisoryHtml adv
    ]
  where
    tr x = "<tr>" <> x <> "</tr>"
    td x = "<td>" <> x <> "</td>"
    row name f = td name <> td (f adv)
    refRow (Reference refType url) =
      tr $
        td "Reference"
        <> td (fromMaybe "URL" (lookup refType referenceTypes) <> ": " <> url)
    date (Date y m d) = T.intercalate "-" $ T.pack <$> [show y, show m, show d]

parseAdvisoryTable :: TOML.Table -> Text -> Either TableParseErr (Text -> Advisory)
parseAdvisoryTable table summary = runTableParser $ do
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

  pure $ \html ->
    Advisory
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

advisoryDoc :: Block -> Either Text (Text, Block)
advisoryDoc (BSeq bseq) =
  case bseq of
    [] -> Left "Does not have toml code block as first element"
    b : bs -> advisoryDoc b >>= \(toml, acode) -> pure (toml, BSeq (acode : bs))
advisoryDoc (BRanged _ b) = advisoryDoc b
advisoryDoc (CodeBlock (T.unpack -> "toml") frontMatter) = pure (frontMatter, mempty)
advisoryDoc _ = Left "Does not have toml code block as first element"

parseAdvisorySummary :: Block -> Either Text Text
parseAdvisorySummary = fmap inlineText . firstHeading

firstHeading :: Block -> Either Text Inline
firstHeading = maybe (Left "Does not have summary heading") Right . go where
  go (Heading _ h) = Just h
  go (AddAttributes _ b) = go b
  go (BSeq bs) = getFirst . foldMap (First . go) $ bs
  go (BRanged  _ b) = go b
  go _ = Nothing

inlineText :: Inline -> Text
inlineText LineBreak = "\n"
inlineText SoftBreak = ""
inlineText (Str s) = s
inlineText (Entity s) = s
inlineText (Sequence l) = T.concat $ map inlineText l
inlineText (Escaped c) = T.singleton c
inlineText (Emph i) = inlineText i
inlineText (Strong i) = inlineText i
inlineText (Link _ _ i) = inlineText i
inlineText (Image _ _ i) = inlineText i
inlineText (Code s) = s
inlineText (RawInline _ s) = s
inlineText (WithAttrs _ i) = inlineText i
inlineText (Ranged _ i) = inlineText i

data Block
  = Para Inline
  | Plain Inline
  | ThematicBreak
  | BlockQuote Block
  | CodeBlock Text Text
  | Heading Int Inline
  | Raw Format Text
  | RefLinkDef Text (Text, Text)
  | List ListType ListSpacing [Block]
  | AddAttributes Attributes Block
  | BSeq [Block]
  | BRanged SourceRange Block
  deriving stock (Show)

fromBlock :: IsBlock il html => Block -> html
fromBlock (Para il) = paragraph (fromInline il)
fromBlock (Plain il) = plain (fromInline il)
fromBlock ThematicBreak = thematicBreak
fromBlock (BlockQuote b) = blockQuote (fromBlock b)
fromBlock (CodeBlock x y) = codeBlock x y
fromBlock (Heading i il) = heading i (fromInline il)
fromBlock (Raw fmt txt) = rawBlock fmt txt
fromBlock (RefLinkDef a b) = referenceLinkDefinition a b
fromBlock (List ty sp elts) = list ty sp (map fromBlock elts)
fromBlock (AddAttributes attrs b) = addAttributes attrs (fromBlock b)
fromBlock (BSeq bs) = foldMap fromBlock bs
fromBlock (BRanged rng b) = ranged rng (fromBlock b)

instance HasAttributes Block where
  addAttributes = AddAttributes

instance Semigroup Block where
  BSeq xs <> BSeq ys = BSeq (xs <> ys)
  BSeq xs <> x = BSeq (xs ++ [x])
  x <> BSeq xs = BSeq (x : xs)
  x <> y = BSeq [x, y]

instance Monoid Block where
  mempty = BSeq []

instance Rangeable Block where
  ranged = BRanged

instance IsBlock Inline Block where
  paragraph = Para
  plain = Plain
  thematicBreak = ThematicBreak
  blockQuote = BlockQuote
  codeBlock = CodeBlock
  heading = Heading
  rawBlock = Raw
  referenceLinkDefinition = RefLinkDef
  list = List

data Inline
  = LineBreak
  | SoftBreak
  | Str Text
  | Entity Text
  | Escaped Char
  | Emph Inline
  | Strong Inline
  | Link Text Text Inline
  | Image Text Text Inline
  | Code Text
  | RawInline Format Text
  | WithAttrs [(Text, Text)] Inline
  | Ranged SourceRange Inline
  | Sequence [Inline]
  deriving stock (Show)

fromInline :: IsInline il => Inline -> il
fromInline LineBreak = lineBreak
fromInline SoftBreak = softBreak
fromInline (Str txt) = str txt
fromInline (Entity ent) = entity ent
fromInline (Escaped ch) = escapedChar ch
fromInline (Emph il) = emph (fromInline il)
fromInline (Strong il) = strong (fromInline il)
fromInline (Link a b il) = link a b (fromInline il)
fromInline (Image a b il) = image a b (fromInline il)
fromInline (Code txt) = code txt
fromInline (RawInline fmt txt) = rawInline fmt txt
fromInline (WithAttrs attrs il) = addAttributes attrs (fromInline il)
fromInline (Ranged rng il) = ranged rng (fromInline il)
fromInline (Sequence ils) = foldMap fromInline ils

instance HasAttributes Inline where
  addAttributes = WithAttrs

instance Rangeable Inline where
  ranged = Ranged

instance Semigroup Inline where
  Sequence xs <> Sequence ys = Sequence (xs <> ys)
  Sequence xs <> other = Sequence xs <> Sequence [other]
  other <> Sequence ys = Sequence (other : ys)
  in1 <> in2 = Sequence [in1, in2]

instance Monoid Inline where
  mempty = Sequence []

instance IsInline Inline where
  lineBreak = LineBreak
  softBreak = SoftBreak
  str = Str
  entity = Entity
  escapedChar = Escaped
  emph = Emph
  strong = Strong
  link = Link
  image = Image
  code = Code
  rawInline = RawInline
