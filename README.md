
# Short, fast PKP-based signature scheme

## Summary

This repository contains a Python 3 reference implementation of a
signature scheme based on Shamir's 1989 PKP-based identification
protocol.  With the q=977 parameters proposed in eprint 2018/714
version 20181201:152523 for the Category 1 security level, and some
standard optimizations, signatures at the full Category 1 security
level are at most 13750 bytes, and can easily be reduced to 13145
bytes long with moderate added computational cost.

These two size options correspond to two out of four possible
encodings of the "long" proofs, and do not affect the formats of hash
inputs; signatures can be converted between proof encodings separately
from the signing and verification routines if desired.

For use in interactive applications, where a random value can be
included in the signed message to prove "freshness" of the signature,
the security level of the signature against forgery can be reduced
without harming the long-term security of the keypair.  With the
lowest-cost encodings supported by this software, this results in
signatures at the 80-bit, 96-bit, and 112-bit preimage security levels
of 7350 (or less), 9360 (or less), and 11468 (or less) bytes,
respectively.  These choices are not fully optimized for size given
the choice of encoding format; they have some extra bytes to reduce
the number of runs of the underlying identification protocol.

FIXME               

## Authors

Authors: Robert Ransom, NTRU Prime round 2 submitters (vectenc.py only)

The encoding and decoding functions in vectenc.py are based on the functions
on pages 17 and 18 of the NTRU Prime round 2 specification.

They should be revised to demonstrate more efficient techniques, but
these near-original functions are sufficient to define the data
format for test vector generation and interoperability testing.

## License

With the possible exception of the vector coders, this software is
released to the public domain.

To the extent permitted by law, this software is provided WITHOUT ANY
WARRANTY WHATSOEVER.

## WARNINGS

This software is not intended for production use.  It makes no attempt
to protect against any form of side-channel attack, and the
verification routine will raise exceptions for malformed signatures.

## 

FIXME               

