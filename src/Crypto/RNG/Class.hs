{-# LANGUAGE CPP                     #-}
{-# LANGUAGE ConstrainedClassMethods #-}
{-# LANGUAGE FlexibleInstances       #-}
{-# LANGUAGE UndecidableInstances    #-}

#if __GLASGOW_HASKELL__ < 710
{-# LANGUAGE OverlappingInstances #-}
#endif

module Crypto.RNG.Class where

import Control.Monad.Trans
import Crypto.Random.DRBG
import Data.ByteString (ByteString)

-- | Monads carrying around the RNG state.
class Monad m => CryptoRNG m where
  -- | Generate given number of cryptographically secure random bytes.
  randomBytes :: ByteLength -- ^ number of bytes to generate
              -> m ByteString

-- | Generic, overlapping instance.

instance {-# OVERLAPPABLE #-} (
    Monad (t m)
  , MonadTrans t
  , CryptoRNG m
  ) => CryptoRNG (t m) where
    randomBytes = lift . randomBytes
