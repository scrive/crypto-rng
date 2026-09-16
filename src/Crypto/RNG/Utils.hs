module Crypto.RNG.Utils
  ( randomString
  ) where

import Control.Monad
import Data.Primitive.SmallArray

import Crypto.RNG

-- | Generate random string of specified length that contains allowed chars.
--
-- The list of allowed chars must not be empty.
randomString :: CryptoRNG m => Int -> [Char] -> m String
randomString n allowedList
  | size == 0 = error "randomString: the list of allowed chars is empty"
  | otherwise = map (indexSmallArray allowed)
      <$> replicateM n (randomR (0, size - 1))
  where
    allowed :: SmallArray Char
    allowed = smallArrayFromList allowedList

    size :: Int
    size = sizeofSmallArray allowed
