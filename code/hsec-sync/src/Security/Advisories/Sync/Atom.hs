module Security.Advisories.Sync.Atom
  ( UpdatesUrl (..),
    latestUpdate,
  )
where

import Control.Exception (try)
import Control.Lens
import Data.Either.Extra (maybeToEither)
import qualified Data.Text as T
import Data.Time (UTCTime, defaultTimeLocale, parseTimeM, rfc822DateFormat)
import Data.Time.Format.ISO8601 (iso8601ParseM)
import Network.HTTP.Client (HttpException (..), HttpExceptionContent (..))
import Network.Wreq
import qualified Text.Atom.Feed as FeedAtom
import qualified Text.Feed.Import as FeedImport
import qualified Text.Feed.Types as FeedTypes
import qualified Text.RSS.Syntax as FeedRSS

newtype UpdatesUrl = UpdatesUrl {getUpdatesUrl :: String}

latestUpdate :: UpdatesUrl -> IO (Either String UTCTime)
latestUpdate url = do
  resultE <- try $ get $ getUpdatesUrl url
  return $
    case resultE of
      Left e ->
        Left $
          case e of
            InvalidUrlException url' reason ->
              "Invalid URL " <> show url' <> ": " <> show reason
            HttpExceptionRequest _ content ->
              case content of
                StatusCodeException response body ->
                  "Request failed with " <> show (response ^. responseStatus) <> ": " <> show body
                _ ->
                  "Request failed: " <> show content
      Right result ->
        case FeedImport.parseFeedSource $ result ^. responseBody of
          Just (FeedTypes.AtomFeed x) ->
            maybeToEither "Invalid feed date" $
              iso8601ParseM $
                T.unpack $
                  FeedAtom.feedUpdated x
          Just (FeedTypes.RSSFeed x) ->
            maybeToEither "Invalid feed date" $
              FeedRSS.rssLastUpdate (FeedRSS.rssChannel x)
                >>= parseTimeM True defaultTimeLocale rfc822DateFormat . T.unpack
          Just (FeedTypes.RSS1Feed _) -> Left "RSS1 feed are not supported"
          Just (FeedTypes.XMLFeed _) -> Left "XML feed are not supported"
          Nothing -> Left "No feed found"
