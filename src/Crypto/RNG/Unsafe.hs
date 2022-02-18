{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE UndecidableInstances #-}
-- | Support for generation of __non cryptographically secure__ random numbers
-- for testing purposes.
module Crypto.RNG.Unsafe
  ( -- * CryptoRNG class
    module Crypto.RNG.Class
    -- * Monad transformer for carrying rng state
  , RNGT
  , mapRNGT
  , runRNGT
  , withRNGState
    -- * Instantiation of the initial RNG state
  , RNGState
  , newRNGState
    -- ** Low-level utils
  , withRNG
  ) where

import Control.Applicative
import Control.Concurrent
import Control.Monad
import Control.Monad.Base
import Control.Monad.Catch
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.Trans.Control
import qualified System.Random as R

import Crypto.RNG.Class

-- | The random number generator state.
newtype RNGState = RNGState (MVar R.StdGen)

-- | Create a new 'RNGState' with a given seed.
newRNGState :: MonadIO m => Int -> m RNGState
newRNGState seed = liftIO $ do
  RNGState <$> newMVar (R.mkStdGen seed)

----------------------------------------

-- | Monad transformer with RNG state.
newtype RNGT m a = RNGT { unRNGT :: ReaderT RNGState m a }
  deriving ( Alternative, Applicative, Functor, Monad, MonadFail, MonadPlus
           , MonadError e, MonadIO, MonadBase b, MonadBaseControl b
           , MonadThrow, MonadCatch, MonadMask
           , MonadTrans, MonadTransControl
           )

mapRNGT :: (m a -> n b) -> RNGT m a -> RNGT n b
mapRNGT f m = withRNGState $ \rng -> f (runRNGT rng m)

runRNGT :: RNGState -> RNGT m a -> m a
runRNGT rng m = runReaderT (unRNGT m) rng

withRNGState :: (RNGState -> m a) -> RNGT m a
withRNGState = RNGT . ReaderT

instance MonadIO m => CryptoRNG (RNGT m) where
  randomBytes n  = RNGT ask >>= (`withRNG` \g -> R.genByteString n g)
  random         = RNGT ask >>= (`withRNG` \g -> R.uniform g)
  randomR bounds = RNGT ask >>= (`withRNG` \g -> R.uniformR bounds g)

withRNG :: MonadIO m => RNGState -> (R.StdGen -> (a, R.StdGen)) -> m a
withRNG (RNGState rng) f = liftIO . modifyMVar rng $ \g -> do
  (a, newG) <- pure $ f g
  newG `seq` pure (newG, a)
