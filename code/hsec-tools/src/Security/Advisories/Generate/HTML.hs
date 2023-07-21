{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Security.Advisories.Generate.HTML
  ( renderAdvisoriesIndex,
  )
where

import Control.Monad (filterM, forM_)
import Control.Monad.Extra (mapMaybeM)
import Data.Either.Extra (eitherToMaybe)
import Data.Functor ((<&>))
import Data.List (isPrefixOf, isSuffixOf, sortOn)
import Data.List.Extra (groupSort)
import qualified Data.Map.Strict as Map
import Data.Ord (Down (..))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Lucid
import Security.Advisories (AttributeOverridePolicy (NoOverrides), OutOfBandAttributes (..), emptyOutOfBandAttributes, parseAdvisory)
import qualified Security.Advisories as Advisories
import Security.Advisories.Git
import System.Directory (createDirectoryIfMissing, pathIsSymbolicLink)
import System.Directory.Extra (listFilesRecursive)
import System.FilePath (takeFileName, (</>))

-- * Actions

renderAdvisoriesIndex :: FilePath -> FilePath -> IO ()
renderAdvisoriesIndex src dst = do
  let okToLoad path = do
        isSym <- pathIsSymbolicLink path
        let fileName = takeFileName path
        pure $
          not isSym  -- ignore symlinks (avoid duplicates entries in index)
          && "HSEC-" `isPrefixOf` fileName
          && ".md" `isSuffixOf` fileName
      readAdvisory path = do
        oob <-
          getAdvisoryGitInfo path <&> \case
            Left _ -> emptyOutOfBandAttributes
            Right gitInfo ->
              emptyOutOfBandAttributes
                { oobPublished = Just (firstAppearanceCommitDate gitInfo),
                  oobModified = Just (lastModificationCommitDate gitInfo)
                }
        fileContent <- T.readFile path
        return $ eitherToMaybe $ parseAdvisory NoOverrides oob fileContent
  advisoriesFileName <- listFilesRecursive src >>= filterM okToLoad
  advisories <- mapMaybeM readAdvisory advisoriesFileName
  let renderToFile' path content = do
        putStrLn $ "Rendering " <> path
        renderToFile path content

  createDirectoryIfMissing False dst
  let indexAdvisories = map toAdvisoryR advisories
  renderToFile' (dst </> "by-dates.html") $ listByDates indexAdvisories
  renderToFile' (dst </> "by-packages.html") $ listByPackages indexAdvisories

  let advisoriesDir = dst </> "advisory"
  createDirectoryIfMissing False advisoriesDir
  forM_ advisories $ \advisory ->
    renderToFile' (advisoriesDir </> advisoryHtmlFilename (Advisories.advisoryId advisory)) $
      inPage PageAdvisory $
        div_ [class_ "pure-u-1"] $
          toHtmlRaw (Advisories.advisoryHtml advisory)

-- * Rendering types

data AdvisoryR = AdvisoryR
  { advisoryId :: Advisories.HsecId,
    advisorySummary :: Text,
    advisoryAffected :: [AffectedPackageR]
  }
  deriving stock (Eq, Show)

data AffectedPackageR = AffectedPackageR
  { packageName :: Text,
    introduced :: Text,
    fixed :: Maybe Text
  }
  deriving stock (Eq, Show)

-- * Pages

listByDates :: [AdvisoryR] -> Html ()
listByDates advisories =
  inPage PageListByDates $
    div_ [class_ "pure-u-1"] $ do
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

listByPackages :: [AdvisoryR] -> Html ()
listByPackages advisories =
  inPage PageListByPackages $
    div_ [class_ "pure-u-1"] $ do
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
          table_ [class_ "pure-table pure-table-horizontal"] $ do
            thead_ $ do
              tr_ $ do
                th_ "#"
                th_ "Introduced"
                th_ "Fixed"
                th_ "Summary"

            tbody_ $ do
              let sortedAdvisories =
                    zip
                      (sortOn (Down . advisoryId . fst) perPackageAdvisory)
                      (cycle [[], [class_ "pure-table-odd"]])
              forM_ sortedAdvisories $ \((advisory, package), trClasses) ->
                tr_ trClasses $ do
                  td_ [class_ "advisory-id"] $ a_ [href_ $ advisoryLink $ advisoryId advisory] $ toHtml (Advisories.printHsecId $ advisoryId advisory)
                  td_ [class_ "advisory-introduced"] $ toHtml $ introduced package
                  td_ [class_ "advisory-fixed"] $ maybe (return ()) toHtml $ fixed package
                  td_ [class_ "advisory-summary"] $ toHtml $ advisorySummary advisory

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

inPage :: NavigationPage -> Html () -> Html ()
inPage page content =
  doctypehtml_ $
    html_ $ do
      head_ $ do
        meta_ [charset_ "UTF-8"]
        base_ [href_ $ baseUrlForPage page]
        link_ [rel_ "stylesheet", href_ "https://cdn.jsdelivr.net/npm/purecss@3.0.0/build/pure-min.css", integrity_ "sha384-X38yfunGUhNzHpBaEBsWLO+A0HDYOQi8ufWDkZ0k9e0eXz/tH3II7uKZ9msv++Ls", crossorigin_ "anonymous"]
        meta_ [name_ "viewport", content_ "width=device-width, initial-scale=1"]
        title_ "Haskell Security Advisories"
        style_ $
          T.intercalate
            "\n"
            [ ".advisories, .content {",
              "    margin: 1em;",
              "}",
              "a {",
              "    text-decoration: none;",
              "}",
              "a:visited {",
              "    text-decoration: none;",
              "    color: darkblue;",
              "}",
              "pre {",
              "    background: lightgrey;",
              "}"
            ]
      body_ $ do
        div_ [class_ "pure-u-1"] $ do
          div_ [class_ "pure-menu pure-menu-horizontal"] $ do
            let selectedOn p cls =
                  if page == p
                    then cls <> " pure-menu-selected"
                    else cls
            span_ [class_ "pure-menu-heading pure-menu-link"] "Advisories list"
            ul_ [class_ "pure-menu-list"] $ do
              li_ [class_ $ selectedOn PageListByDates "pure-menu-item"] $
                a_ [href_ "by-dates.html", class_ "pure-menu-link"] "by date"
              li_ [class_ $ selectedOn PageListByPackages "pure-menu-item"] $
                a_ [href_ "by-packages.html", class_ "pure-menu-link"] "by package"
        div_ [class_ "content"] content

advisoryHtmlFilename :: Advisories.HsecId -> FilePath
advisoryHtmlFilename advisoryId' = Advisories.printHsecId advisoryId' <> ".html"

advisoryLink :: Advisories.HsecId -> Text
advisoryLink advisoryId' = "advisory/" <> T.pack (advisoryHtmlFilename advisoryId')

toAdvisoryR :: Advisories.Advisory -> AdvisoryR
toAdvisoryR x =
  AdvisoryR
    { advisoryId = Advisories.advisoryId x,
      advisorySummary = Advisories.advisorySummary x,
      advisoryAffected = concatMap toAffectedPackageR $ Advisories.advisoryAffected x
    }
  where
    toAffectedPackageR :: Advisories.Affected -> [AffectedPackageR]
    toAffectedPackageR p =
      flip map (Advisories.affectedVersions p) $ \versionRange ->
        AffectedPackageR
          { packageName = Advisories.affectedPackage p,
            introduced = Advisories.affectedVersionRangeIntroduced versionRange,
            fixed = Advisories.affectedVersionRangeFixed versionRange
          }
