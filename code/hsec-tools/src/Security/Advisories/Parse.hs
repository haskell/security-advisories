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

import Commonmark.Html (Html, renderHtml)
import Commonmark.Pandoc (Cm (unCm))
import qualified Commonmark.Parser as Commonmark
import Commonmark.Types (HasAttributes (..), IsBlock (..), IsInline (..), Rangeable (..), SourceRange (..))
import Data.Bifunctor (first)
import Data.Foldable (toList)
import Data.Monoid (First (..))
import Data.Sequence (Seq ((:<|)))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Lazy as T (toStrict)
import GHC.Generics (Generic)
import Security.Advisories.Core.Advisory
import Security.Advisories.Format (
    AttributeOverridePolicy (..),
    OutOfBandAttributes (..),
    codecFrontMatter,
    emptyOutOfBandAttributes,
    toAdvisory,
 )
import Text.Pandoc.Builder (Blocks, Many (..))
import Text.Pandoc.Definition (Block (..), Inline (..), Pandoc (..))
import Text.Pandoc.Walk (query)
import Text.Parsec.Pos (sourceLine)
import qualified Toml

data ParseAdvisoryError
    = MarkdownError Commonmark.ParseError Text
    | MarkdownFormatError Text
    | TomlError String Text
    | AdvisoryError [Toml.TomlDecodeError]
    deriving stock (Eq, Show, Generic)

{- | The main parsing function.  'OutOfBandAttributes' are handled
 according to the 'AttributeOverridePolicy'.
-}
parseAdvisory ::
    AttributeOverridePolicy ->
    OutOfBandAttributes ->
    -- | input (CommonMark with TOML header)
    Text ->
    Either ParseAdvisoryError Advisory
parseAdvisory policy attrs raw = do
    markdown <-
        unCm
            <$> firstPretty
                MarkdownError
                (T.pack . show)
                (Commonmark.commonmark "input" raw :: Either Commonmark.ParseError (Cm () Blocks))
    (frontMatter, rest) <- first MarkdownFormatError $ advisoryDoc markdown
    let doc = Pandoc mempty rest
    !summary <- first MarkdownFormatError $ parseAdvisorySummary doc

    -- Re-parse as FirstSourceRange to find the source range of
    -- the TOML header.
    FirstSourceRange (First mRange) <-
        firstPretty MarkdownError (T.pack . show) (Commonmark.commonmark "input" raw)
    let details = case mRange of
            Just (SourceRange ((_, end) : _)) ->
                T.unlines
                    . dropWhile T.null
                    . fmap snd
                    . dropWhile ((< sourceLine end) . fst)
                    . zip [1 ..]
                    $ T.lines raw
            _ ->
                -- no block elements?  empty range list?
                -- these shouldn't happen, but better be total
                raw

    -- Re-parse input as HTML.  This will probably go away; we now store the
    -- Pandoc doc and can render that instead, where needed.
    html <-
        T.toStrict . renderHtml
            <$> firstPretty
                MarkdownError
                (T.pack . show)
                (Commonmark.commonmark "input" raw :: Either Commonmark.ParseError (Html ()))

    first AdvisoryError $ do
        fm <- Toml.decode codecFrontMatter frontMatter
        toAdvisory attrs policy doc summary details html fm
  where
    firstPretty ::
        (e -> Text -> ParseAdvisoryError) ->
        (e -> Text) ->
        Either e a ->
        Either ParseAdvisoryError a
    firstPretty ctr f = first $ mkPretty ctr f

    mkPretty ::
        (e -> Text -> ParseAdvisoryError) ->
        (e -> Text) ->
        e ->
        ParseAdvisoryError
    mkPretty ctr f x = ctr x $ f x

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
