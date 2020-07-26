
# Authors: Robert Ransom

# This software is released to the public domain.

import struct

PKP_Q = 977 # must be prime in this implementation
PKP_N = 61
PKP_M = 28

PKPSIG_SIGFMT_SQUISH_PERMUTATIONS = True
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
PKPSIG_NRUNS_SHORT = 108
PKPSIG_NRUNS_LONG = 55
PKPSIG_NRUNS_TOTAL = PKPSIG_NRUNS_SHORT + PKPSIG_NRUNS_LONG

PKPSIG_TREEHASH_PARAM_STRING = \
    struct.pack('<BBHH',
                PKPSIG_BYTES_COMMITHASH,
                PKPSIG_BYTES_CHALLENGESEED,
                PKPSIG_NRUNS_SHORT,
                PKPSIG_NRUNS_LONG)

# vector sizes and root bounds
from . import vectenc

VECTSIZE_PUBKEY_U = vectenc.size([PKP_Q]*PKP_M)
VECTSIZE_SIG_Z = vectenc.size([PKP_Q]*PKP_N)

VECTSIZE_SIG_PERM = vectenc.size([PKP_N]*PKP_N)
if PKPSIG_SIGFMT_SQUISH_PERMUTATIONS:
    VECTSIZE_SIG_PERM = vectenc.size([PKP_N-i for i in range(PKP_N-1)])
    pass

PKPSIG_TOTAL_BULK_LEN = (PKPSIG_BYTES_COMMITHASH * PKPSIG_NRUNS_TOTAL +
                         PKPSIG_BYTES_BLINDINGSEED * PKPSIG_NRUNS_SHORT +
                         VECTSIZE_SIG_Z.lenS * PKPSIG_NRUNS_LONG +
                         VECTSIZE_SIG_PERM.lenS * PKPSIG_NRUNS_LONG)
if PKPSIG_SIGFMT_MERGE_VECTOR_ROOTS:
    VECTSIZE_SIG_RUNVEC_HEADS = vectenc.size([VECTSIZE_SIG_Z.root_bound, VECTSIZE_SIG_PERM.root_bound]*PKPSIG_NRUNS_LONG)
    PKPSIG_TOTAL_SPILLS_ENC_LEN = VECTSIZE_SIG_RUNVEC_HEADS.lenS
    PKPSIG_TOTAL_SPILLS_ROOT_BOUND = VECTSIZE_SIG_RUNVEC_HEADS.root_bound
    PKPSIG_TOTAL_SPILLS_ROOT_BYTES = VECTSIZE_SIG_RUNVEC_HEADS.root_bytes
    pass
else:
    PKPSIG_TOTAL_BULK_LEN += (VECTSIZE_SIG_Z.root_bytes * PKPSIG_NRUNS_LONG +
                              VECTSIZE_SIG_PERM.root_bytes * PKPSIG_NRUNS_LONG)
    PKPSIG_TOTAL_SPILLS_ENC_LEN = 0
    PKPSIG_TOTAL_SPILLS_ROOT_BOUND = 1
    PKPSIG_TOTAL_SPILLS_ROOT_BYTES = 0
    pass

# sizes derived from the above, manually for now
BYTES_PUBLICKEY = 52
BYTES_SECRETKEY = 89
if PKPSIG_SIGFMT_SQUISH_PERMUTATIONS:
    if PKPSIG_SIGFMT_MERGE_VECTOR_ROOTS:
        BYTES_SIGNATURE = 13119
        pass
    else:
        BYTES_SIGNATURE = 13145
        pass
    pass
else:
    if PKPSIG_SIGFMT_MERGE_VECTOR_ROOTS:
        BYTES_SIGNATURE = 13695
        pass
    else:
        BYTES_SIGNATURE = 13750
        pass
    pass

