{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}

-- | Support for generation of cryptographically secure random
-- numbers, based on the DRBG package.
--
-- This is a convenience layer on top of DRBG, which allows you to
-- pull random values by means of the method 'random', while keeping
-- the state of the random number generator (RNG) inside a monad.  The
-- state is protected by an MVar, which means that concurrent
-- generation of random values from several threads works straight out
-- of the box.
--
-- The access to the RNG state is captured by a class.  By making
-- instances of this class, client code can enjoy RNG generation from
-- their own monads.
module Crypto.RNG
  ( -- * CryptoRNG class
    module Crypto.RNG.Class
    -- * Generation of strings and numbers
  , CryptoRNGState
  , newCryptoRNGState
  , newCryptoRNGStateSized
  , unsafeCryptoRNGState
  , randomBytesIO
  , randomIO
  , randomRIO
    -- * Monad transformer for carrying rng state
  , CryptoRNGT
  , mapCryptoRNGT
  , runCryptoRNGT
  , withCryptoRNGState
  ) where

import Control.Applicative
import Control.Concurrent
import Control.Monad.Base
import Control.Monad.Catch
import Control.Monad.Cont
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.Trans.Control
import Crypto.Random
import Crypto.Random.DRBG
import Data.Bits
import Data.ByteString (ByteString)
import Data.Either
import Data.Primitive.SmallArray
import qualified Data.ByteString as BS
import qualified System.Random as R

import Crypto.RNG.Class

-- | The random number generator state.
newtype CryptoRNGState = CryptoRNGState (SmallArray (MVar RNG))

-- | The random number generator.
newtype RNG = RNG (GenBuffered (GenAutoReseed HashDRBG HashDRBG))

instance R.RandomGen RNG where
  split = error "split"
  genWord32 (RNG g) = case genBytes 4 g of
    Left err       -> error $ "genBytes failed: " ++ show err
    Right (bs, g') -> (mkWord bs, RNG g')
  genWord64 (RNG g) = case genBytes 8 g of
    Left err       -> error $ "genBytes failed: " ++ show err
    Right (bs, g') -> (mkWord bs, RNG g')

mkWord :: (Bits a, Integral a) => ByteString -> a
mkWord bs = BS.foldl' (\acc w -> shiftL acc 8 .|. fromIntegral w) 0 bs

-- | Work with one of the RNGs from the pool.
withRNG :: CryptoRNGState -> (RNG -> (a, RNG)) -> IO a
withRNG (CryptoRNGState pool) f = do
  -- Selection strategy is based on the id of a capability instead of an id of a
  -- thread as that offers much better performance in a typical scenario when
  -- the size of the pool is equal to the number of capabilities and there are
  -- more threads than capabilities.
  (cid, _) <- threadCapability =<< myThreadId
  let mrng = pool `indexSmallArray` (cid `rem` sizeofSmallArray pool)
  modifyMVar mrng $ \rng -> do
    (a, newRng) <- pure $ f rng
    newRng `seq` pure (newRng, a)

----------------------------------------

-- | Create a new 'CryptoRNGState', based on system entropy.
newCryptoRNGState :: MonadIO m => m CryptoRNGState
newCryptoRNGState = newCryptoRNGStateSized =<< liftIO getNumCapabilities

-- | Create a new 'CryptoRNGState', based on system entropy with the pool of a
-- specific size.
--
-- /Note:/ making the pool bigger than the number of capabilities will not
-- affect anything.
newCryptoRNGStateSized
  :: MonadIO m
  => Int -- ^ Pool size.
  -> m CryptoRNGState
newCryptoRNGStateSized n = liftIO $ do
  pool <- replicateM n $ newMVar . RNG =<< newGenIO
  pure . CryptoRNGState $ smallArrayFromListN n pool

-- | Create a new 'CryptoRNGState', based on a bytestring seed.
-- Should only be used for testing.
unsafeCryptoRNGState
  :: MonadIO m
  => [ByteString]
  -- ^ Seeds for each generator from the pool.
  -> m CryptoRNGState
unsafeCryptoRNGState ss = liftIO $ do
  case partitionEithers $ map newGen ss of
    ([], gens) -> do
      pool <- mapM (newMVar . RNG) gens
      pure . CryptoRNGState $ smallArrayFromList pool
    (errs, _)  -> error $ show errs

-- | Generate given number of cryptographically secure random bytes.
randomBytesIO :: ByteLength -- ^ number of bytes to generate
              -> CryptoRNGState
              -> IO ByteString
randomBytesIO n pool = withRNG pool $ \(RNG g) ->
  case genBytes n g of
    Left err       -> error $ "genBytes failed: " ++ show err
    Right (bs, g') -> (bs, RNG g')

randomIO :: R.Uniform a => CryptoRNGState -> IO a
randomIO pool = withRNG pool $ \g -> R.uniform g

randomRIO :: R.UniformRange a => (a, a) -> CryptoRNGState -> IO a
randomRIO bounds pool = withRNG pool $ \g -> R.uniformR bounds g

type InnerCryptoRNGT = ReaderT CryptoRNGState

-- | Monad transformer with RNG state.
newtype CryptoRNGT m a = CryptoRNGT { unCryptoRNGT :: InnerCryptoRNGT m a }
  deriving ( Alternative, Applicative, Functor, Monad
           , MonadBase b, MonadCatch, MonadError e, MonadIO, MonadMask, MonadPlus
           , MonadThrow, MonadTrans, MonadFail )

mapCryptoRNGT :: (m a -> n b) -> CryptoRNGT m a -> CryptoRNGT n b
mapCryptoRNGT f m = withCryptoRNGState $ \s -> f (runCryptoRNGT s m)

runCryptoRNGT :: CryptoRNGState -> CryptoRNGT m a -> m a
runCryptoRNGT pool m = runReaderT (unCryptoRNGT m) pool

withCryptoRNGState :: (CryptoRNGState -> m a) -> CryptoRNGT m a
withCryptoRNGState = CryptoRNGT . ReaderT

instance MonadTransControl CryptoRNGT where
  type StT CryptoRNGT a = StT InnerCryptoRNGT a
  liftWith = defaultLiftWith CryptoRNGT unCryptoRNGT
  restoreT = defaultRestoreT CryptoRNGT

instance MonadBaseControl b m => MonadBaseControl b (CryptoRNGT m) where
  type StM (CryptoRNGT m) a = ComposeSt CryptoRNGT m a
  liftBaseWith = defaultLiftBaseWith
  restoreM     = defaultRestoreM

instance {-# OVERLAPPABLE #-} MonadIO m => CryptoRNG (CryptoRNGT m) where
  randomBytes n  = CryptoRNGT ask >>= liftIO . randomBytesIO n
  random         = CryptoRNGT ask >>= liftIO . randomIO
  randomR bounds = CryptoRNGT ask >>= liftIO . randomRIO bounds
