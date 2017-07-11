module Main where

import           Crypto.SGP
import           Data.Maybe
import           Data.Text             (pack, toUpper, unpack)
import           System.Console.GetOpt
import           System.Environment
import           Text.Read             (readMaybe)

data HashFn
  = MD5
  | SHA512
  deriving (Eq, Show)

data Options = Options
  { optHashFn             :: HashFn
  , optMinRounds          :: Int
  , optPasswordLen        :: Int
  , optRemovingSubdomains :: Bool
  , optSecretPassword     :: String
  , optMainPassword       :: String
  , optUrl                :: String
  } deriving (Show)

defaultOptions =
  Options
  { optHashFn = MD5
  , optMinRounds = 10
  , optPasswordLen = 10
  , optRemovingSubdomains = True
  , optSecretPassword = ""
  , optMainPassword = ""
  , optUrl = ""
  }

readHashFn :: String -> Maybe HashFn
readHashFn name
  | name' == "MD5" = Just MD5
  | name' == "SHA512" = Just SHA512
  | otherwise = Nothing
  where
    name' = unpack . toUpper . pack $ name

options :: [OptDescr (Options -> Options)]
options =
  [ Option
      ['a']
      ["subdomains"]
      (NoArg (\opts -> opts {optRemovingSubdomains = False}))
      "subdomains enabled"
  , Option
      ['r']
      ["round"]
      (ReqArg
         ((\c opts -> opts {optMinRounds = c}) . fromMaybe 10 . readMaybe)
         "NUMBER")
      "the minimum count of rounds"
  , Option
      ['l']
      ["length"]
      (ReqArg
         ((\l opts -> opts {optPasswordLen = l}) . fromMaybe 10 . readMaybe)
         "NUMBER")
      "the generated password length"
  , Option
      ['h']
      ["hash"]
      (ReqArg
         ((\h opts -> opts {optHashFn = h}) . fromMaybe MD5 . readHashFn)
         "TYPE")
      "the hash function: MD5 | SHA512"
  , Option
      ['s']
      ["secret"]
      (ReqArg (\s opts -> opts {optSecretPassword = s}) "PASSWORD")
      "the secret password part"
  , Option
      ['p']
      ["password"]
      (ReqArg (\p opts -> opts {optMainPassword = p}) "PASSWORD")
      "the main password part"
  , Option ['u'] ["url"] (ReqArg (\u opts -> opts {optUrl = u}) "URL") "the url"
  ]

header :: String
header = "Usage: hsSGP [OPTION...]"

sgpOpts :: [String] -> IO (Options, [String])
sgpOpts argv =
  case getOpt Permute options argv of
    (o, n, [])   -> return (foldl (flip id) defaultOptions o, n)
    (_, _, errs) -> putStrLn (usageInfo header options) >> fail (concat errs)

main :: IO ()
main = do
  args <- getArgs
  if length args == 0
    then putStrLn $ usageInfo header options
    else do
      optsArgs <- sgpOpts args
      opts <- return . fst $ optsArgs
      hostName <-
        return $ getHostname (optRemovingSubdomains opts) (optUrl opts)
      combination <-
        if hostName == Nothing
          then putStrLn (usageInfo header options) >> fail "Bad URL"
          else return $
               combineParts
                 (optMainPassword opts)
                 (optSecretPassword opts)
                 (fromJust hostName)
      genPassWithHash <-
        return $
        case (optHashFn opts) of
          MD5    -> generatePassword md5
          SHA512 -> generatePassword sha512
      putStrLn $
        genPassWithHash (optMinRounds opts) (optPasswordLen opts) combination
