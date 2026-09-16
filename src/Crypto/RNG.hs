{-# LANGUAGE CPP #-}
-- | Support for generation of cryptographically secure random numbers.
--
-- This is a convenience layer on top of "System.Entropy". You pull random
-- values with the class 'CryptoRNG'. A monad keeps the state of the random
-- number generator (RNG).
--
-- The state holds one buffer per capability, and an MVar protects each
-- buffer. A thread uses the buffer of the capability it runs on, so threads
-- on different capabilities do not contend.
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
import Data.ByteString qualified as BS
import Data.Primitive.SmallArray
import GHC.Stack
import System.Entropy
import System.Random.Stateful qualified as R

import Crypto.RNG.Class

#if MIN_VERSION_random(1,3,0)
import Data.ByteString.Unsafe qualified as BSU
import Data.Primitive.ByteArray
#else
import Data.ByteString.Short qualified as SBS
#endif

-- | The random number generator state.
data CryptoRNGState = CryptoRNGState !Int !(SmallArray (MVar Buffer))

-- | A buffer of random bytes for immediate consumption.
newtype Buffer = Buffer { bytes :: BS.ByteString }

-- The results are strict, because a lazy result would hold the slice of the
-- buffer and thus the whole buffer until it is evaluated.
instance R.StatefulGen CryptoRNGState IO where
  uniformWord8  st = mkWord <$!> randomBytesIO 1 st
  uniformWord16 st = mkWord <$!> randomBytesIO 2 st
  uniformWord32 st = mkWord <$!> randomBytesIO 4 st
  uniformWord64 st = mkWord <$!> randomBytesIO 8 st
#if MIN_VERSION_random(1,3,0)
  uniformByteArrayM isPinned n st = do
    bs <- randomBytesIO n st
    let len = BS.length bs
    mba <- if isPinned then newPinnedByteArray len else newByteArray len
    BSU.unsafeUseAsCStringLen bs $ \(ptr, _) ->
      copyPtrToMutableByteArray mba 0 ptr len
    unsafeFreezeByteArray mba
#else
  uniformShortByteString n st = SBS.toShort <$!> randomBytesIO n st
#endif

mkWord :: (Bits a, Integral a) => BS.ByteString -> a
mkWord bs = BS.foldl' (\acc w -> shiftL acc 8 .|. fromIntegral w) 0 bs

----------------------------------------

-- | Create a new 'CryptoRNGState' based on system entropy with a buffer size of
-- 32KB.
--
-- One buffer per capability is created.
newCryptoRNGState :: MonadIO m => m CryptoRNGState
newCryptoRNGState = newCryptoRNGStateSized $ 32 * 1024

-- | Create a new 'CryptoRNGState' based on system entropy with buffers of
-- specified size.
--
-- One buffer per capability is created.
newCryptoRNGStateSized
  :: (HasCallStack, MonadIO m)
  => Int -- ^ Buffer size.
  -> m CryptoRNGState
newCryptoRNGStateSized maxBufSize = liftIO $ do
  when (maxBufSize <= 0) $ do
    error "Buffer size must be larger than 0"
  n <- getNumCapabilities
  bufs <- replicateM n . newMVar $ Buffer BS.empty
  pure $ CryptoRNGState maxBufSize (smallArrayFromListN n bufs)

-- | Generate a number of cryptographically secure random bytes.
randomBytesIO :: Int -> CryptoRNGState -> IO BS.ByteString
randomBytesIO n (CryptoRNGState maxBufSize bufs) = do
  (cid, _) <- threadCapability =<< myThreadId
  let mbuf = bufs `indexSmallArray` (cid `rem` sizeofSmallArray bufs)
  modifyMVar mbuf $ \buf -> do
    let (r, newBytes) = BS.splitAt n (bytes buf)
        k = n - BS.length r
    if k <= 0
      then newBytes `seq` pure (Buffer newBytes, r)
      else do
        -- The buffer is drained at this point. One call to the entropy source
        -- covers the missing bytes and the new buffer, whichever is larger.
        (rest, newerBytes) <- BS.splitAt k <$> getEntropy (max maxBufSize k)
        newerBytes `seq` pure (Buffer newerBytes, r <> rest)

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
