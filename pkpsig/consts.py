
# Authors: Robert Ransom

# This software is released to the public domain.

HASHCTX_PUBPARAMS = 0
HASHCTX_SECKEYSEEDEXPAND = 1
HASHCTX_SECKEYCHECKSUM = 2
HASHCTX_MESSAGEHASH = 3
HASHCTX_EXPANDBLINDINGSEED = 4
HASHCTX_COMMITMENT = 5
HASHCTX_CHALLENGE1 = 6
HASHCTX_CHALLENGE2 = 7

HASHCTX_INTERNAL_GENMSGHASHSALT = 0x80
HASHCTX_INTERNAL_GENBLINDINGSEEDGENSEED = 0x81
HASHCTX_INTERNAL_GENBLINDINGSEED = 0x82

HASHIDX_PUBPARAMS_V = 0
# indices PKP_M through PKP_N-1 are also used for matrix columns

HASHIDX_SECKEYSEEDEXPAND_PI_INV = 0

HASHIDX_EXPANDBLINDINGSEED_RUN_INDEX_FACTOR = 256
HASHIDX_EXPANDBLINDINGSEED_COMMITMENT = 0
HASHIDX_EXPANDBLINDINGSEED_PI_SIGMA_INV = 1
HASHIDX_EXPANDBLINDINGSEED_R_SIGMA = 2

