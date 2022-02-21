{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}
module Crypto.RNG.Class where

import Control.Monad.Trans
import Data.ByteString (ByteString)
import System.Random (Uniform, UniformRange)

-- | Monads carrying around the RNG state.
class Monad m => CryptoRNG m where
  -- | Generate a given number of cryptographically secure random bytes.
  randomBytes :: Int -> m ByteString

  -- | Generate a cryptographically secure value uniformly distributed over all
  -- possible values of that type.
  random :: Uniform a => m a

  -- | Generate a cryptographically secure value in a given, closed range.
  randomR :: UniformRange a => (a, a) -> m a

-- | Generic, overlapping instance.
instance {-# OVERLAPPABLE #-}
  ( Monad (t m)
  , MonadTrans t
  , CryptoRNG m
  ) => CryptoRNG (t m) where
    randomBytes = lift . randomBytes
    random      = lift random
    randomR     = lift . randomR
