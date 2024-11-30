{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Security.Advisories.Generate.HTML
  ( renderAdvisoriesIndex,
  )
where

import Control.Monad (forM_)
import qualified Data.ByteString.Char8 as BS8
import Data.List (sortOn)
import Data.List.Extra (groupSort)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Ord (Down (..))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import qualified Data.Text.Lazy as TL
import Data.Time (UTCTime, formatTime, defaultTimeLocale)
import Data.Time.Format.ISO8601
import System.Directory (createDirectoryIfMissing)
import System.Exit (exitFailure)
import System.FilePath ((</>), takeDirectory)
import System.IO (hPrint, hPutStrLn, stderr)
import System.IO.Unsafe (unsafePerformIO)

import Data.Default (def)
import Distribution.Pretty (prettyShow)
import Distribution.Types.VersionRange (earlierVersion, intersectVersionRanges, orLaterVersion)
import Lucid
import Safe (maximumMay)
import qualified Text.Atom.Feed as Feed
import qualified Text.Atom.Feed.Export as FeedExport
import Text.Pandoc (runIOorExplode)
import Text.Pandoc.Writers (writeHtml5String)
import Validation (Validation (..))

import qualified Security.Advisories as Advisories
import Security.Advisories.Filesystem (listAdvisories)
import Security.Advisories.Generate.TH (readDirFilesTH)
import Security.Advisories.Core.Advisory (ComponentIdentifier (..), ghcComponentToText)
import qualified Security.OSV as OSV

-- * Actions

renderAdvisoriesIndex :: FilePath -> FilePath -> IO ()
renderAdvisoriesIndex src dst = do
  advisories <-
    listAdvisories src >>= \case
      Failure errors -> do
        T.hPutStrLn stderr "Cannot parse some advisories"
        forM_ errors $
          hPrint stderr
        exitFailure
      Success advisories ->
        return advisories

  let renderHTMLToFile path content = do
        hPutStrLn stderr $ "Rendering " <> path
        renderToFile path content

  createDirectoryIfMissing False dst
  let indexAdvisories = map toAdvisoryR advisories
  renderHTMLToFile (dst </> "by-dates.html") $ listByDates indexAdvisories
  renderHTMLToFile (dst </> "by-packages.html") $ listByPackages indexAdvisories

  let advisoriesDir = dst </> "advisory"
  createDirectoryIfMissing False advisoriesDir
  forM_ advisories $ \advisory -> do
    let advisoryPath = advisoriesDir </> advisoryHtmlFilename (Advisories.advisoryId advisory)
    hPutStrLn stderr $ "Rendering " <> advisoryPath
    renderHTMLToFile advisoryPath $
      inPage (T.pack $ Advisories.printHsecId $ Advisories.advisoryId advisory) PageAdvisory $
        renderAdvisory advisory

  hPutStrLn stderr $ "Rendering " <> (dst </> "atom.xml")
  writeFile (dst </> "atom.xml") $ T.unpack $ renderFeed advisories

  putStrLn "Copying assets"
  let assetsDir = dst </> "assets"
  forM_ $(readDirFilesTH "assets") $ \(path, content) -> do
    createDirectoryIfMissing True $ assetsDir </> takeDirectory path
    putStrLn $ "Copying " <> (assetsDir </> path)
    BS8.writeFile (assetsDir </> path) content

-- * Rendering types

data AdvisoryR = AdvisoryR
  { advisoryId :: Advisories.HsecId,
    advisorySummary :: Text,
    advisoryAffected :: [AffectedPackageR],
    advisoryModified :: UTCTime
  }
  deriving stock (Show)

data AffectedPackageR = AffectedPackageR
  { ecosystem :: ComponentIdentifier,
    introduced :: Text,
    fixed :: Maybe Text
  }
  deriving stock (Eq, Show)

-- * Pages

listByDates :: [AdvisoryR] -> Html ()
listByDates advisories =
  inPage "Advisories list" PageListByDates $ do
    indexDescription
    div_ [class_ "advisories"] $ do
      table_ [class_ "pure-table pure-table-horizontal"] $ do
        thead_ $ do
          tr_ $ do
            th_ "#"
            th_ "Package(s)"
            th_ "Summary"

        tbody_ $ do
          let sortedAdvisories =
                zip
                  (sortOn (Down . advisoryId) advisories)
                  (cycle [[], [class_ "pure-table-odd"]])
          forM_ sortedAdvisories $ \(advisory, trClasses) ->
            tr_ trClasses $ do
              td_ [class_ "advisory-id"] $ a_ [href_ $ advisoryLink (advisoryId advisory)] $ toHtml (Advisories.printHsecId (advisoryId advisory))
              td_ [class_ "advisory-packages"] $ toHtml $ T.intercalate "," $ packageName <$> advisoryAffected advisory
              td_ [class_ "advisory-summary"] $ toHtml $ advisorySummary advisory

packageName :: AffectedPackageR -> Text
packageName af = case ecosystem af of
  Hackage n -> n
  GHC c -> "ghc:" <> ghcComponentToText c

listByPackages :: [AdvisoryR] -> Html ()
listByPackages advisories =
  inPage "Advisories list" PageListByPackages $ do
    indexDescription

    let byPackage :: Map.Map Text [(AdvisoryR, AffectedPackageR)]
        byPackage =
          Map.fromList $
            groupSort
              [ (packageName package, (advisory, package))
                | advisory <- advisories,
                  package <- advisoryAffected advisory
              ]

    forM_ (Map.toList byPackage) $ \(currentPackageName, perPackageAdvisory) -> do
      h2_ $ toHtml currentPackageName
      div_ [class_ "advisories"] $ do
        table_ [] $ do
          thead_ $ do
            tr_ $ do
              th_ "#"
              th_ "Introduced"
              th_ "Fixed"
              th_ "Summary"

          tbody_ $ do
            let sortedAdvisories =
                    sortOn (Down . advisoryId . fst) perPackageAdvisory
            forM_ sortedAdvisories $ \(advisory, package) -> do
              tr_ $ do
                td_ [class_ "advisory-id"] $
                  a_ [href_ $ advisoryLink $ advisoryId advisory] $
                    toHtml (Advisories.printHsecId $ advisoryId advisory)
                td_ [class_ "advisory-introduced"] $ toHtml $ introduced package
                td_ [class_ "advisory-fixed"] $ maybe (return ()) toHtml $ fixed package
                td_ [class_ "advisory-summary"] $ toHtml $ advisorySummary advisory

indexDescription :: Html ()
indexDescription =
  div_ [class_ "description"] $ do
    p_ "The Haskell Security Advisory Database is a repository of security advisories filed against packages published via Hackage."
    p_  $ do
      "It is generated from "
      a_ [href_ "https://github.com/haskell/security-advisories/", target_ "_blank", rel_ "noopener noreferrer"] "Haskell Security Advisory Database"
      ". "
      "Feel free to "
      a_ [href_ "https://github.com/haskell/security-advisories/blob/main/PROCESS.md", target_ "_blank", rel_ "noopener noreferrer"] "report new or historic security issues"
      "."

renderAdvisory :: Advisories.Advisory -> Html ()
renderAdvisory advisory =
  div_ [id_ "advisory"] $ do
    let renderedDescription = unsafePerformIO $ runIOorExplode $ writeHtml5String def $ Advisories.advisoryPandoc advisory
    toHtmlRaw renderedDescription

    let placeholderWhenEmptyOr :: [a] -> ([a] -> Html ()) -> Html ()
        placeholderWhenEmptyOr xs f = if null xs then dd_ [] $ i_ "< none >" else f xs

    h3_ [] "Info"
    dl_ [] $ do
      dt_ "Published"
      dd_ [] $ toHtml $ formatTime defaultTimeLocale "%B %d, %Y" $ Advisories.advisoryPublished advisory
      dt_ "Modified"
      dd_ [] $ toHtml $ formatTime defaultTimeLocale "%B %d, %Y" $ Advisories.advisoryModified advisory
      dt_ "CAPECs"
      placeholderWhenEmptyOr (Advisories.advisoryCAPECs advisory) $ \capecs ->
        forM_ capecs $ \(Advisories.CAPEC capec) ->
            dd_ [] $ a_ [href_ $ "https://capec.mitre.org/data/definitions/" <> T.pack (show capec) <> ".html"] $ toHtml $ show capec
      dt_ "CWEs"
      placeholderWhenEmptyOr (Advisories.advisoryCWEs advisory) $ \cwes ->
        forM_ cwes $ \(Advisories.CWE cwe) ->
          dd_ [] $ a_ [href_ $ "https://cwe.mitre.org/data/definitions/" <> T.pack (show cwe) <> ".html"] $ toHtml $ show cwe
      dt_ "Keywords"
      placeholderWhenEmptyOr (Advisories.advisoryKeywords advisory) $ dd_ [] . toHtml . T.intercalate ", " . map Advisories.unKeyword
      dt_ "Aliases"
      placeholderWhenEmptyOr (Advisories.advisoryAliases advisory) $ dd_ [] . toHtml . T.intercalate ", "
      dt_ "Related"
      placeholderWhenEmptyOr (Advisories.advisoryRelated advisory) $ dd_ [] . toHtml . T.intercalate ", "
      dt_ "References"
      placeholderWhenEmptyOr (Advisories.advisoryReferences advisory) $ \references ->
        forM_ references $ \reference ->
          dd_ [] $ a_ [href_ $ OSV.referencesUrl reference] $ toHtml $ "[" <> fromMaybe "WEB" (lookup (OSV.referencesType reference) OSV.referenceTypes) <> "] " <> OSV.referencesUrl reference

    h4_ [] "Affected"
    forM_ (Advisories.advisoryAffected advisory) $ \affected -> do
      h5_ [] $
        case Advisories.affectedComponentIdentifier affected of
          Hackage package -> a_ [href_ $ "https://hackage.haskell.org/package/" <> package] $ code_ [] $ toHtml package
          GHC component -> code_ [] $ toHtml $ Advisories.ghcComponentToText component

      dl_ [] $ do
        dt_ "CVSS"
        dd_ [] $ toHtml $ T.pack $ show $ Advisories.affectedCVSS affected
        dt_ "Versions"
        forM_ (Advisories.affectedVersions affected) $ \affectedVersionRange ->
          dd_ [] $
            code_ [] $
              toHtml $
                T.pack $
                  prettyShow $
                    let introducedVersionRange = orLaterVersion $ Advisories.affectedVersionRangeIntroduced affectedVersionRange
                    in case Advisories.affectedVersionRangeFixed affectedVersionRange of
                      Nothing -> introducedVersionRange
                      Just fixedVersion -> introducedVersionRange `intersectVersionRanges` earlierVersion fixedVersion
        forM_ (Advisories.affectedArchitectures affected) $ \architectures -> do
          dt_ "Architectures"
          dd_ [] $ toHtml $ T.intercalate ", " $ T.toLower . T.pack . show <$> architectures
        forM_ (Advisories.affectedOS affected) $ \oses -> do
          dt_ "OSes"
          dd_ [] $ toHtml $ T.intercalate ", " $ T.toLower . T.pack . show <$> oses
        dt_ "Declarations"
        placeholderWhenEmptyOr (Advisories.affectedDeclarations affected) $ \declarations ->
          forM_ declarations $ \(declaration, versionRange) ->
            dd_ [] $ do
              code_ [] $ toHtml declaration
              ": "
              code_ [] $ toHtml $ T.pack $ prettyShow versionRange

-- * Utils

data NavigationPage
  = PageListByDates
  | PageListByPackages
  | PageAdvisory
  deriving stock (Eq, Show)

baseUrlForPage :: NavigationPage -> Text
baseUrlForPage = \case
  PageListByDates -> "."
  PageListByPackages -> "."
  PageAdvisory -> ".."

inPage :: Text -> NavigationPage -> Html () -> Html ()
inPage title page content =
  doctypehtml_ $
    html_ [lang_ "en"] $ do
      head_ $ do
        meta_ [charset_ "UTF-8"]
        base_ [href_ $ baseUrlForPage page]
        link_ [rel_ "alternate", type_ "application/atom+xml", href_ atomFeedUrl]
        link_ [rel_ "stylesheet", href_ "assets/css/default.css"]
        meta_ [name_ "viewport", content_ "width=device-width, initial-scale=1"]
        meta_ [name_ "description", content_ "Haskell Security advisories"]
        title_ "Haskell Security advisories"
      body_ $ do
        div_ [class_ "nav-bar"] $ do
          let selectedOn p =
                if page == p
                  then "selected"
                  else ""
          ul_ [class_ "items"] $ do
            li_ [class_ $ selectedOn PageListByDates] $
              a_ [href_ "by-dates.html"] "by date"
            li_ [class_ $ selectedOn PageListByPackages] $
              a_ [href_ "by-packages.html"] "by package"
        h1_ [] $ toHtml title
        div_ [class_ "content"] content
        footer_ [] $ do
          div_ [class_ "HF"] $ do
            "This site is a project of "
            a_ [href_ "https://haskell.foundation", target_ "_blank", rel_ "noopener noreferrer"] "The Haskell Foundation"
            "."

advisoryHtmlFilename :: Advisories.HsecId -> FilePath
advisoryHtmlFilename advisoryId' = Advisories.printHsecId advisoryId' <> ".html"

advisoryLink :: Advisories.HsecId -> Text
advisoryLink advisoryId' = "advisory/" <> T.pack (advisoryHtmlFilename advisoryId')

toAdvisoryR :: Advisories.Advisory -> AdvisoryR
toAdvisoryR x =
  AdvisoryR
    { advisoryId = Advisories.advisoryId x,
      advisorySummary = Advisories.advisorySummary x,
      advisoryAffected = concatMap toAffectedPackageR $ Advisories.advisoryAffected x,
      advisoryModified = Advisories.advisoryModified x
    }
  where
    toAffectedPackageR :: Advisories.Affected -> [AffectedPackageR]
    toAffectedPackageR p =
      flip map (Advisories.affectedVersions p) $ \versionRange ->
        AffectedPackageR
          { ecosystem = Advisories.affectedComponentIdentifier p,
            introduced = T.pack $ prettyShow $ Advisories.affectedVersionRangeIntroduced versionRange,
            fixed = T.pack . prettyShow <$> Advisories.affectedVersionRangeFixed versionRange
          }

-- * Atom/RSS feed

feed :: [Advisories.Advisory] -> Feed.Feed
feed advisories =
  ( Feed.nullFeed
      atomFeedUrl
      (Feed.TextString "Haskell Security Advisory DB") -- Title
      (maybe "" (T.pack . iso8601Show) . maximumMay . fmap Advisories.advisoryModified $ advisories)
  )
    { Feed.feedEntries = fmap toEntry advisories
    , Feed.feedLinks = [(Feed.nullLink atomFeedUrl) { Feed.linkRel = Just (Left "self") }]
    , Feed.feedAuthors = [Feed.nullPerson { Feed.personName = "Haskell Security Response Team" }]
    }
  where
    toEntry advisory =
      ( Feed.nullEntry
        (toUrl advisory)
        (mkSummary advisory)
        (T.pack . iso8601Show $ Advisories.advisoryModified advisory)
      )
        { Feed.entryLinks = [(Feed.nullLink (toUrl advisory)) { Feed.linkRel = Just (Left "alternate") }]
        , Feed.entryContent = Just (Feed.HTMLContent (Advisories.advisoryHtml advisory))
        }

    mkSummary advisory =
      Feed.TextString $
        T.pack (Advisories.printHsecId (Advisories.advisoryId advisory))
        <> " - "
        <> Advisories.advisorySummary advisory
    toUrl advisory = advisoriesRootUrl <> "/" <> advisoryLink (Advisories.advisoryId advisory)

renderFeed :: [Advisories.Advisory] -> Text
renderFeed =
  maybe (error "Cannot render atom feed") TL.toStrict
    . FeedExport.textFeed
    . feed

advisoriesRootUrl :: T.Text
advisoriesRootUrl = "https://haskell.github.io/security-advisories"

atomFeedUrl :: T.Text
atomFeedUrl = advisoriesRootUrl <> "/atom.xml"
