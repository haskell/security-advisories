{-# LANGUAGE LambdaCase #-}
module Security.Advisories.Sync.Url
  ( mkUrl
  , ensureFile
  )
where

mkUrl :: [String] -> String
mkUrl = foldl1 (</>)

infixr 5 </>

(</>) :: String -> String -> String
"/" </> ('/' : ys) = '/' : ys
"/" </> ys = '/' : ys
"" </> ('/' : ys) = '/' : ys
"" </> ys = '/' : ys
[x] </> ('/' : ys) = x : '/' : ys
[x] </> ys = x : '/' : ys
(x0 : x1 : xs) </> ys = x0 : ((x1 : xs) </> ys)

ensureFile :: String -> String
ensureFile =
  \case
    "" -> ""
    "/" -> ""
    (x:xs) -> x : ensureFile xs
