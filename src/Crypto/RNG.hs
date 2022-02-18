{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE UndecidableInstances #-}
-- | Support for generation of cryptographically secure random numbers.
--
-- This is a convenience layer on top of "System.Entropy", which allows you to
-- pull random values by means of the class 'CryptoRNG', while keeping the state
-- of the random number generator (RNG) inside a monad. The state is protected
-- by an MVar, which means that concurrent generation of random values from
-- several threads works straight out of the box.
module Crypto.RNG
  ( -- * CryptoRNG class
    module Crypto.RNG.Class
    -- * Monad transformer for carrying rng state
  , CryptoRNGT
  , mapCryptoRNGT
  , runCryptoRNGT
  , withCryptoRNGState
    -- * Instantiation of the initial RNG state
  , CryptoRNGState
  , newCryptoRNGState
  , newCryptoRNGStateSized
    -- ** Low-level utils
  , randomBytesIO
  ) where

import Control.Applicative
import Control.Concurrent
import Control.Monad
import Control.Monad.Base
import Control.Monad.Catch
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.Trans.Control
import Data.Bits
import Data.ByteString (ByteString)
import System.Entropy
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as SBS
import qualified System.Random.Stateful as R

import Crypto.RNG.Class

-- | The random number generator state.
newtype CryptoRNGState = CryptoRNGState (MVar Buffer)

-- | A buffer of random bytes for immediate consumption.
data Buffer = Buffer
  { maxSize :: !Int
  , bytes   :: !BS.ByteString
  }

instance R.StatefulGen CryptoRNGState IO where
  uniformWord8  st = mkWord <$> randomBytesIO 1 st
  uniformWord16 st = mkWord <$> randomBytesIO 2 st
  uniformWord32 st = mkWord <$> randomBytesIO 4 st
  uniformWord64 st = mkWord <$> randomBytesIO 8 st
  uniformShortByteString n st = SBS.toShort <$> randomBytesIO n st

mkWord :: (Bits a, Integral a) => ByteString -> a
mkWord bs = BS.foldl' (\acc w -> shiftL acc 8 .|. fromIntegral w) 0 bs

----------------------------------------

-- | Create a new 'CryptoRNGState' based on system entropy with a buffer size of
-- 32KB.
newCryptoRNGState :: MonadIO m => m CryptoRNGState
newCryptoRNGState = newCryptoRNGStateSized $ 32 * 1024

-- | Create a new 'CryptoRNGState' based on system entropy with a buffer of
-- specified size.
newCryptoRNGStateSized
  :: MonadIO m
  => Int -- ^ Buffer size.
  -> m CryptoRNGState
newCryptoRNGStateSized bufferSize = liftIO $ do
  when (bufferSize <= 0) $ do
    error "Buffer size must be larger than 0"
  CryptoRNGState <$> newMVar (Buffer bufferSize BS.empty)

-- | Generate a number of cryptographically secure random bytes.
randomBytesIO :: Int -> CryptoRNGState -> IO ByteString
randomBytesIO n (CryptoRNGState rng) = modifyMVar rng $ \buf -> do
  (rs, newBuf) <- generateBytes buf n []
  pure (newBuf, BS.concat rs)

generateBytes
  :: Buffer
  -> Int
  -> [BS.ByteString]
  -> IO ([BS.ByteString], Buffer)
generateBytes buf n acc = do
  (r, newBytes) <- BS.splitAt n <$> if BS.null (bytes buf)
                                    then getEntropy (maxSize buf)
                                    else pure (bytes buf)
  let newBuf = buf { bytes = newBytes }
      k = n - BS.length r
  newBuf `seq` if k <= 0
    then pure (r : acc, newBuf)
    else generateBytes newBuf k (r : acc)

----------------------------------------

-- | Monad transformer with RNG state.
newtype CryptoRNGT m a = CryptoRNGT { unCryptoRNGT :: ReaderT CryptoRNGState m a }
  deriving ( Alternative, Applicative, Functor, Monad, MonadFail, MonadPlus
           , MonadError e, MonadIO,  MonadBase b, MonadBaseControl b
           , MonadThrow, MonadCatch, MonadMask
           , MonadTrans, MonadTransControl
           )

mapCryptoRNGT :: (m a -> n b) -> CryptoRNGT m a -> CryptoRNGT n b
mapCryptoRNGT f m = withCryptoRNGState $ \rng -> f (runCryptoRNGT rng m)

runCryptoRNGT :: CryptoRNGState -> CryptoRNGT m a -> m a
runCryptoRNGT rng m = runReaderT (unCryptoRNGT m) rng

withCryptoRNGState :: (CryptoRNGState -> m a) -> CryptoRNGT m a
withCryptoRNGState = CryptoRNGT . ReaderT

instance MonadIO m => CryptoRNG (CryptoRNGT m) where
  randomBytes n  = CryptoRNGT ask >>= liftIO . randomBytesIO n
  random         = CryptoRNGT ask >>= liftIO . R.uniformM
  randomR bounds = CryptoRNGT ask >>= liftIO . R.uniformRM bounds
