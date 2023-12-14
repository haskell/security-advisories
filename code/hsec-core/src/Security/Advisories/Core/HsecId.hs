module Security.Advisories.Core.HsecId
  (
    HsecId
  , hsecIdYear
  , hsecIdSerial
  , mkHsecId
  , placeholder
  , isPlaceholder
  , parseHsecId
  , printHsecId
  , nextHsecId
  , getNextHsecId
  ) where

import Control.Monad (guard, join)

import Data.Time (getCurrentTime, utctDay)
import Data.Time.Calendar.OrdinalDate (toOrdinalDate)

import Safe (readMay)

data HsecId = HsecId Integer Integer
  deriving (Eq, Ord)

instance Show HsecId where
  show = printHsecId

-- | Make an 'HsecId'.  Year and serial must both be positive, or
-- else both must be zero (the 'placeholder').
mkHsecId
  :: Integer -- ^ Year
  -> Integer -- ^ Serial number within year
  -> Maybe HsecId
mkHsecId y n
  | y > 0 && n > 0 || y == 0 && n == 0 = Just $ HsecId y n
  | otherwise = Nothing

hsecIdYear :: HsecId -> Integer
hsecIdYear (HsecId y _) = y

hsecIdSerial :: HsecId -> Integer
hsecIdSerial (HsecId _ n) = n

-- | The placeholder ID: __HSEC-0000-0000__.
-- See also 'isPlaceholder'.
placeholder :: HsecId
placeholder = HsecId 0 0

-- | Test whether an ID is the 'placeholder'
isPlaceholder :: HsecId -> Bool
isPlaceholder = (==) placeholder

-- | Parse an 'HsecId'.  The 'placeholder' is accepted.
parseHsecId :: String -> Maybe HsecId
parseHsecId s = case s of
  'H':'S':'E':'C':'-':t ->
    let
      (y, t') = break (== '-') t
      n = drop 1 t'
    in do
      guard $ length y >= 4  -- year must have at least 4 digits
      guard $ length n >= 4  -- serial must have at least 4 digits
      join $ mkHsecId <$> readMay y <*> readMay n
  _ -> Nothing

printHsecId :: HsecId -> String
printHsecId (HsecId y n) = "HSEC-" <> pad (show y) <> "-" <> pad (show n)
  where
  pad s = replicate (4 - length s) '0' <> s

-- | Given a year and an HSEC ID, return a larger HSEC ID.  This
-- function, when given the current year and the greatest allocated
-- HSEC ID, returns the next HSEC ID to allocate.
--
nextHsecId
  :: Integer -- ^ Current year
  -> HsecId
  -> HsecId
nextHsecId curYear (HsecId idYear n)
  | curYear > idYear = HsecId curYear 1
  | otherwise = HsecId idYear (n + 1)

-- | Get the current time, and return an HSEC ID greater than the
-- given HSEC ID.  The year of the returned HSEC ID is the current
-- year.
--
getNextHsecId
  :: HsecId
  -> IO HsecId
getNextHsecId oldId = do
  t <- getCurrentTime
  let (year, _dayOfYear) = toOrdinalDate (utctDay t)
  pure $ nextHsecId year oldId
