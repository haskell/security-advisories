{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Security.Advisories.Parse (
    parseAdvisory,
    OutOfBandAttributes (..),
    emptyOutOfBandAttributes,
    AttributeOverridePolicy (..),
    ParseAdvisoryError (..),
)
where

import Data.Bifunctor (first)
import Data.Foldable (toList)
import Data.Maybe (fromMaybe)
import Data.Monoid (First(..))
import GHC.Generics (Generic)

import Data.Sequence (Seq((:<|)))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Lazy as T (toStrict)
import Data.Time (ZonedTime)

import Commonmark.Html (Html, renderHtml)
import qualified Commonmark.Parser as Commonmark
import Commonmark.Types (HasAttributes(..), IsBlock(..), IsInline(..), Rangeable(..), SourceRange(..))
import Commonmark.Pandoc (Cm(unCm))
import qualified Toml
import qualified Toml.Syntax as Toml (startPos)
import qualified Toml.Schema as Toml
import Text.Pandoc.Builder (Blocks, Many(..))
import Text.Pandoc.Definition (Block(..), Inline(..), Pandoc(..))
import Text.Pandoc.Walk (query)
import Text.Parsec.Pos (sourceLine)

import Security.Advisories.Core.Advisory
import Security.Advisories.Format (FrontMatter(..), AdvisoryMetadata(..))

-- | A source of attributes supplied out of band from the advisory
-- content.  Values provided out of band are treated according to
-- the 'AttributeOverridePolicy'.
--
-- The convenient way to construct a value of this type is to start
-- with 'emptyOutOfBandAttributes', then use the record accessors to
-- set particular fields.
--
data OutOfBandAttributes = OutOfBandAttributes
  { oobModified :: Maybe ZonedTime
  , oobPublished :: Maybe ZonedTime
  }
  deriving (Show)

emptyOutOfBandAttributes :: OutOfBandAttributes
emptyOutOfBandAttributes = OutOfBandAttributes
  { oobModified = Nothing
  , oobPublished = Nothing
  }

data AttributeOverridePolicy
  = PreferInBand
  | PreferOutOfBand
  | NoOverrides -- ^ Parse error if attribute occurs both in-band and out-of-band
  deriving (Show, Eq)

data ParseAdvisoryError
    = MarkdownError Commonmark.ParseError Text
    | MarkdownFormatError Text
    | TomlError String Text
    | AdvisoryError [Toml.MatchMessage Toml.Position] T.Text
    deriving stock (Eq, Show, Generic)

parseAdvisory
  :: AttributeOverridePolicy
  -> OutOfBandAttributes
  -> T.Text -- ^ input (CommonMark with TOML header)
  -> Either ParseAdvisoryError Advisory
parseAdvisory policy attrs raw = do
  markdown <-
    unCm
    <$> firstPretty MarkdownError (T.pack . show)
          (Commonmark.commonmark "input" raw :: Either Commonmark.ParseError (Cm () Blocks))
  (frontMatter, rest) <- first MarkdownFormatError $ advisoryDoc markdown
  let doc = Pandoc mempty rest
  !summary <- first MarkdownFormatError $ parseAdvisorySummary doc
  table <- case Toml.parse frontMatter of
    Left e -> Left (TomlError e (T.pack e))
    Right t -> Right t

  -- Re-parse as FirstSourceRange to find the source range of
  -- the TOML header.
  FirstSourceRange (First mRange) <-
    firstPretty MarkdownError (T.pack . show) (Commonmark.commonmark "input" raw)
  let
    details = case mRange of
      Just (SourceRange ((_,end):_)) ->
        T.unlines
        . dropWhile T.null
        . fmap snd
        . dropWhile ((< sourceLine end) . fst)
        . zip [1..]
        $ T.lines raw
      _ ->
        -- no block elements?  empty range list?
        -- these shouldn't happen, but better be total
        raw
  -- Re-parse input as HTML.  This will probably go away; we now store the
  -- Pandoc doc and can render that instead, where needed.
  html <-
    T.toStrict . renderHtml
    <$> firstPretty MarkdownError (T.pack . show)
          (Commonmark.commonmark "input" raw :: Either Commonmark.ParseError (Html ()))

  case parseAdvisoryTable attrs policy doc summary details html table of
    Left es -> Left (AdvisoryError es (T.pack (unlines (map Toml.prettyMatchMessage es))))
    Right adv -> pure adv

  where
    firstPretty
      :: (e -> Text -> ParseAdvisoryError)
      -> (e -> Text)
      -> Either e a
      -> Either ParseAdvisoryError a
    firstPretty ctr pretty = first $ mkPretty ctr pretty

    mkPretty
      :: (e -> Text -> ParseAdvisoryError)
      -> (e -> Text)
      -> e
      -> ParseAdvisoryError
    mkPretty ctr pretty x = ctr x $ pretty x

parseAdvisoryTable
  :: OutOfBandAttributes
  -> AttributeOverridePolicy
  -> Pandoc -- ^ parsed document (without frontmatter)
  -> Text -- ^ summary
  -> Text -- ^ details
  -> Text -- ^ rendered HTML
  -> Toml.Table' Toml.Position
  -> Either [Toml.MatchMessage Toml.Position] Advisory
parseAdvisoryTable oob policy doc summary details html tab =
  Toml.runMatcherFatalWarn $
   do fm <- Toml.fromValue (Toml.Table' Toml.startPos tab)
      published <-
        mergeOobMandatory policy
          (oobPublished oob)
          "advisory.date"
          (amdPublished (frontMatterAdvisory fm))
      modified <-
        fromMaybe published <$>
          mergeOobOptional policy
            (oobPublished oob)
            "advisory.modified"
            (amdModified (frontMatterAdvisory fm))
      pure Advisory
        { advisoryId = amdId (frontMatterAdvisory fm)
        , advisoryPublished = published
        , advisoryModified = modified
        , advisoryCAPECs = amdCAPECs (frontMatterAdvisory fm)
        , advisoryCWEs = amdCWEs (frontMatterAdvisory fm)
        , advisoryKeywords = amdKeywords (frontMatterAdvisory fm)
        , advisoryAliases = amdAliases (frontMatterAdvisory fm)
        , advisoryRelated = amdRelated (frontMatterAdvisory fm)
        , advisoryAffected = frontMatterAffected fm
        , advisoryReferences = frontMatterReferences fm
        , advisoryPandoc = doc
        , advisoryHtml = html
        , advisorySummary = summary
        , advisoryDetails = details
        }

advisoryDoc :: Blocks -> Either Text (Text, [Block])
advisoryDoc (Many blocks) = case blocks of
    CodeBlock (_, classes, _) frontMatter :<| t
        | "toml" `elem` classes ->
            pure (frontMatter, toList t)
    _ ->
        Left "Does not have toml code block as first element"

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

mergeOob
  :: MonadFail m
  => AttributeOverridePolicy
  -> Maybe a  -- ^ out-of-band value
  -> String  -- ^ key
  -> Maybe a -- ^ in-band-value
  -> m b  -- ^ when key and out-of-band value absent
  -> (a -> m b) -- ^ when value present
  -> m b
mergeOob policy oob k ib absent present = do
  case (oob, ib) of
    (Just l, Just r) -> case policy of
      NoOverrides -> fail ("illegal out of band override: " ++ k)
      PreferOutOfBand -> present l
      PreferInBand -> present r
    (Just a, Nothing) -> present a
    (Nothing, Just a) -> present a
    (Nothing, Nothing) -> absent

mergeOobOptional
  :: MonadFail m
  => AttributeOverridePolicy
  -> Maybe a  -- ^ out-of-band value
  -> String -- ^ key
  -> Maybe a -- ^ in-band-value
  -> m (Maybe a)
mergeOobOptional policy oob k ib =
  mergeOob policy oob k ib (pure Nothing) (pure . Just)

mergeOobMandatory
  :: MonadFail m
  => AttributeOverridePolicy
  -> Maybe a  -- ^ out-of-band value
  -> String  -- ^ key
  -> Maybe a -- ^ in-band value
  -> m a
mergeOobMandatory policy oob k ib =
  mergeOob policy oob k ib (fail ("missing mandatory key: " ++ k)) pure

{- | A solution to an awkward problem: how to delete the TOML
 block.  We parse into this type to get the source range of
 the first block element.  We can use it to delete the lines
 from the input.
-}
newtype FirstSourceRange = FirstSourceRange (First SourceRange)
    deriving (Show, Semigroup, Monoid)

instance Rangeable FirstSourceRange where
    ranged range = (FirstSourceRange (First (Just range)) <>)

instance HasAttributes FirstSourceRange where
    addAttributes _ = id

instance IsBlock FirstSourceRange FirstSourceRange where
    paragraph _ = mempty
    plain _ = mempty
    thematicBreak = mempty
    blockQuote _ = mempty
    codeBlock _ = mempty
    heading _ = mempty
    rawBlock _ = mempty
    referenceLinkDefinition _ = mempty
    list _ = mempty

instance IsInline FirstSourceRange where
    lineBreak = mempty
    softBreak = mempty
    str _ = mempty
    entity _ = mempty
    escapedChar _ = mempty
    emph = id
    strong = id
    link _ _ _ = mempty
    image _ _ _ = mempty
    code _ = mempty
    rawInline _ _ = mempty
