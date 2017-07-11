module Crypto.SGP
  ( generatePassword
  , combineParts
  , getHostname
  , md5
  , sha512
  ) where

import           Control.Applicative    ((<$>))
import           Crypto.Hash            (Digest, hash)
import qualified Crypto.Hash            as CH
import           Crypto.SGP.TLD
import           Data.Byteable          (toBytes)
import           Data.ByteString        (ByteString)
import           Data.ByteString.Base64 (encode)
import           Data.ByteString.Char8  (pack, unpack)
import           Data.List              (find, foldl', intercalate, iterate)
import           Data.Maybe
import           Text.Regex

customBase64 :: ByteString -> ByteString
customBase64 = pack . map replacer . unpack . encode
  where
    replacer c =
      case c of
        '+' -> '9'
        '/' -> '8'
        '=' -> 'A'
        _   -> c

hasher :: (ByteString -> Digest a) -> ByteString -> ByteString
hasher hashFn = customBase64 . toBytes . hashFn

md5 :: ByteString -> Digest CH.MD5
md5 = hash

sha512 :: ByteString -> Digest CH.SHA512
sha512 = hash

hashRounds :: (ByteString -> Digest a) -> String -> [ByteString]
hashRounds hashFn message = iterate (hasher hashFn) $ pack message

domainRegex :: Regex
domainRegex = mkRegexWithOpts "^([a-z]+:\\/\\/)?([^/@]+@)?([^/:]+)" False False

ipRegex :: Regex
ipRegex =
  mkRegex
    "^[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}$"

removeSubdomains :: String -> String
removeSubdomains domain
  | length domainParts < 3 = domain
  | otherwise =
    intercalate "." $
    if isJust ccSuffix
      then lastN' subdomainLen domainParts
      else lastN' 2 domainParts
  where
    subdomainDelimiter = mkRegex "\\."
    domainParts = splitRegex subdomainDelimiter domain
    ccTldList' = map ('.' :) ccTldList
    ccSuffix = find (`endsWith` domain) ccTldList'
    subdomainLen = length . splitRegex subdomainDelimiter $ fromJust ccSuffix

getHostname :: Bool -> String -> Maybe String
getHostname rmSubs url = (subsRemoving . (!! 2)) <$> matchRegex domainRegex url
  where
    ipUrl dom = isJust $ matchRegex ipRegex dom
    subsRemoving dom
      | ipUrl dom = dom
      | rmSubs = removeSubdomains dom
      | otherwise = dom

endsWith :: Eq a => [a] -> [a] -> Bool
endsWith s t = lastN' (length s) t == s

lastN' :: Int -> [a] -> [a]
lastN' n xs = foldl' (const . drop 1) xs $ drop n xs

startsWithLowercaseLetter :: Regex
startsWithLowercaseLetter = mkRegex "^[a-z]"

containsUppercaseLetter :: Regex
containsUppercaseLetter = mkRegex "[A-Z]"

containsNumeral :: Regex
containsNumeral = mkRegex "[0-9]"

validatePassword :: String -> Int -> Bool
validatePassword password len =
  and $
  isJust . flip matchRegex (take len password) <$>
  [startsWithLowercaseLetter, containsUppercaseLetter, containsNumeral]

combineParts :: String -> String -> String -> String
combineParts mainPassword secretPassword domain =
  mainPassword ++ secretPassword ++ ":" ++ domain

generatePassword :: (ByteString -> Digest a) -> Int -> Int -> String -> String
generatePassword hashFn minRounds passLen seed =
  take passLen .
  unpack .
  head .
  dropWhile (not . flip validatePassword passLen . unpack) . drop minRounds $
  hashRounds hashFn seed
