# Revision history for crypto-rng

## 0.3.0.0  -- 2022-02-21

* Use the entropy package instead of DRBG.

## 0.2.0.1  -- 2022-02-16

* Better selection strategy for picking generators from the pool.

## 0.2.0.0  -- 2022-02-16

* Drop support for GHC < 8.8
* Fix a space leak in randomBytesIO.
* Use a buffered generator.
* Remove modulo bias from randomRIO.
* Improve performance of randomString.
* Add support for a pool of generators for less contention.

## 0.1.2.0  -- 2020-05-05

* GHC-8.8 support (MonadFail) and ghc 8.10.1 support.

## 0.1.1.0  -- 2019-10-08

* Added a 'MonadError' instance for 'CryptoRNGT'.

## 0.1.0.2  -- 2018-03-14

* Dropped support for GHC 7.8 and 7.10.

## 0.1.0.1  -- 2017-01-18

* Removed a redundant constraint that led to build failures with GHC 8.0.2.

## 0.1.0.0  -- 2016-12-06

* First version. Released on an unsuspecting world.
