module Crypto.RNG.Utils where

import Control.Monad

import Crypto.RNG

-- | Generate random string of specified length that contains allowed
-- chars.
randomString :: CryptoRNG m => Int -> [Char] -> m String
randomString n allowed_chars =
  sequence $ replicate n $ ((!!) allowed_chars `liftM` randomR (0, len))
  where
    len = length allowed_chars - 1
