module Crypto.RNG.Utils where

import Control.Monad
import Data.Primitive.SmallArray

import Crypto.RNG

-- | Generate random string of specified length that contains allowed
-- chars.
randomString :: CryptoRNG m => Int -> [Char] -> m String
randomString n allowedList = map (indexSmallArray allowed)
  <$> replicateM n (randomR (0, sizeofSmallArray allowed - 1))
  where
    allowed = smallArrayFromList allowedList
