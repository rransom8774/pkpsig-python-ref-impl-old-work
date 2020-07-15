
# Authors: Robert Ransom

# This software is released to the public domain.

PKP_Q = 997 # must be prime in this implementation
PKP_N = 61
PKP_M = 28

PKPSIG_SIGFMT_SQUISH_PERMUTATIONS = False
PKPSIG_SIGFMT_MERGE_VECTOR_ROOTS = False

# sizes determined by keypair security level
PKPSIG_BYTES_PUBPARAMSEED = 17
PKPSIG_BYTES_SECKEYSEED = 32
PKPSIG_BYTES_SALTGENSEED = 32
PKPSIG_BYTES_SECKEYCHECKSUM = 8
PKPSIG_BYTES_MSGHASHSALT = 32
PKPSIG_BYTES_BLINDINGSEED = 16

# determined by keypair security level, and not sent anywhere
PKPSIG_BYTES_MESSAGEHASH = 32
PKPSIG_BYTES_TREEHASHNODE = 32

# determined by keypair security level, and not a protocol constant
PKPSIG_BYTES_INTERNAL_BLINDINGSEEDGENSEED = 64

# sizes determined by signature security level
PKPSIG_BYTES_COMMITHASH = 32
PKPSIG_BYTES_CHALLENGESEED = 32

# non-byte sizes determined by signature security level
PKPSIG_NRUNS_SHORT = 120
PKPSIG_NRUNS_LONG = 51
PKPSIG_NRUNS_TOTAL = PKPSIG_NRUNS_SHORT + PKPSIG_NRUNS_LONG

# vector sizes and root bounds
from . import vectenc

VECTSIZE_PUBKEY_U = vectenc.size([PKP_Q]*PKP_M)
VECTSIZE_SIG_Z = vectenc.size([PKP_Q]*PKP_N)

VECTSIZE_SIG_PERM = vectenc.size([PKP_N]*PKP_N)
if PKPSIG_SIGFMT_SQUISH_PERMUTATIONS:
    VECTSIZE_SIG_PERM = vectenc.size([PKP_N-i for i in range(PKP_N-1)])
    pass

if PKPSIG_SIGFMT_MERGE_VECTOR_ROOTS:
    VECTSIZE_SIG_RUNVEC_HEADS = vectenc.size([VECTSIZE_SIG_Z[1], VECTSIZE_SIG_PERM[1]]*PKPSIG_NRUNS_LONG)
    pass

# sizes derived from the above, manually for now
BYTES_PUBLICKEY = 52
BYTES_SECRETKEY = 89
BYTES_SIGNATURE = 13710

