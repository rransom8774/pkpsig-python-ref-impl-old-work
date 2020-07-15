
# Authors: Robert Ransom

# This software is released to the public domain.

from . import common, consts, params, permops, symmetric, vectenc

class PublicMatrix(object):
    """
    A simple wrapper for the non-identity part of a column-major m*n matrix
    in systematic form mod q.
    """
    __slots__ = ('cols',)
    def __init__(self):
        self.cols = [None for i in range(params.PKP_N - params.PKP_M)]
        pass
    def __getitem__(self, i):
        assert(i >= params.PKP_M)
        assert(i < params.PKP_N)
        return self.cols[i - params.PKP_M]
    def __setitem__(self, i, v):
        assert(i >= params.PKP_M)
        assert(i < params.PKP_N)
        self.cols[i - params.PKP_M] = v
        pass
    def mult_vec(A, v):
        "Computes the column vector A*v."
        assert(len(v) == params.PKP_N)
        # Multiply by the identity portion
        out = list(v[:params.PKP_M])
        # Multiply by the non-identity portion
        for i in range(params.PKP_M, params.PKP_N, 1):
            for j in range(params.PKP_M):
                out[j] += A[i][j] * v[j]
                pass
            pass
        # Reduce mod q
        for j in range(params.PKP_M):
            out[j] %= params.PKP_Q
            pass
        return out
    pass

class PublicParams(object):
    __slots__ = ('A', 'v')
    def expand_seed(self, seed):
        hobj = symmetric.hash_init(consts.HASHCTX_PUBPARAMS, seed)
        # Generate v
        # The key generator is responsible for ensuring that v has no
        # duplicate elements.
        self.v = symmetric.hash_expand_index_fqvec(hobj, consts.HASHIDX_PUBPARAMS_V, params.PKP_N)
        # Generate A'
        self.A = PublicMatrix()
        for i in range(params.PKP_M, params.PKP_N, 1):
            self.A[i] = symmetric.hash_expand_index_fqvec(hobj, i, params.PKP_M)
            pass
        return self
    pass

def validate_param_seed(seed):
    hobj = symmetric.hash_init(consts.HASHCTX_PUBPARAMS, seed)
    # Generate v
    v = symmetric.hash_expand_index_fqvec(hobj, consts.HASHIDX_PUBPARAMS_V, params.PKP_N)
    # Check v for duplicates
    v.sort()
    for i in range(len(v) - 1):
        if v[i] == v[i+1]:
            return False
        pass
    return True

class PublicKey(PublicParams):
    __slots__ = ('u',)
    def unpack(self, keyblob):
        assert(params.BYTES_PUBLICKEY == (params.PKPSIG_BYTES_PUBPARAMSEED +
                                          params.VECTSIZE_PUBKEY_U.lenS +
                                          params.VECTSIZE_PUBKEY_U.root_bytes))
        if len(keyblob) != params.BYTES_PUBLICKEY:
            raise common.DataError('Public key blob has wrong length')
        pubseed, u_enc, u_root_enc = \
            common.split_sequence_fields(keyblob, (params.PKPSIG_BYTES_PUBPARAMSEED,
                                                   params.VECTSIZE_PUBKEY_U.lenS,
                                                   params.VECTSIZE_PUBKEY_U.root_bytes))
        self.expand_seed(pubseed)
        # Decode u
        u_root = vectenc.decode_root(u_root_enc,
                                     params.VECTSIZE_PUBKEY_U.root_bound)
        self.u = vectenc.decode(u_enc,
                                [params.PKP_Q]*params.PKP_M,
                                u_root)
        return self
    def pack_u(self):
        S, root, root_bound = vectenc.encode(self.u, [params.PKP_Q]*params.PKP_M)
        S = S + vectenc.encode_root(root, root_bound)
        return bytes(S)
    pass

class SecretKey(PublicKey):
    __slots__ = ('pi_inv', 'pubseed', 'secseed', 'saltgenseed')
    def unpack(self, keyblob, validate_checksum = True):
        assert(params.BYTES_SECRETKEY == (params.PKPSIG_BYTES_PUBPARAMSEED +
                                          params.PKPSIG_BYTES_SECKEYSEED +
                                          params.PKPSIG_BYTES_SALTGENSEED +
                                          params.PKPSIG_BYTES_SECKEYCHECKSUM))
        if len(keyblob) != params.BYTES_SECRETKEY:
            raise common.DataError('Secret key blob has wrong length')
        self.pubseed, self.secseed, self.saltgenseed, cksum = \
            common.split_sequence_fields(keyblob, (params.PKPSIG_BYTES_PUBPARAMSEED,
                                                   params.PKPSIG_BYTES_SECKEYSEED,
                                                   params.PKPSIG_BYTES_SALTGENSEED,
                                                   params.PKPSIG_BYTES_SECKEYCHECKSUM))
        self.expand_seed(self.pubseed)
        hobj = symmetric.hash_init(consts.HASHCTX_SECKEYSEEDEXPAND, self.pubseed + self.secseed)
        # Expand pi_inv
        self.pi_inv = symmetric.hash_expand_index_perm(hobj, consts.HASHIDX_SECKEYSEEDEXPAND_PI_INV, params.PKP_N)
        # Derive u
        v_pi = permops.apply_inv(self.v, self.pi_inv)
        self.u = self.A.mult_vec(v_pi)
        # Check checksum
        if validate_checksum:
            hobj = symmetric.hash_init(consts.HASHCTX_SECKEYCHECKSUM, self.pubseed)
            cksum_expected = symmetric.hash_digest_suffix_fqvec(hobj, self.u, params.PKPSIG_BYTES_SECKEYCHECKSUM)
            if cksum_expected != cksum:
                raise common.DataError('Secret key blob has wrong checksum')
            pass
        return self
    pass

def generate_keypair(randombytes = common.randombytes):
    "generate_keypair([randombytes]) -> (pkblob, skblob)"
    assert(params.BYTES_SECRETKEY == (params.PKPSIG_BYTES_PUBPARAMSEED +
                                      params.PKPSIG_BYTES_SECKEYSEED +
                                      params.PKPSIG_BYTES_SALTGENSEED +
                                      params.PKPSIG_BYTES_SECKEYCHECKSUM))
    # Generate the most secret part first, as a separate RNG call
    seckeyseed = randombytes(params.PKPSIG_BYTES_SECKEYSEED)
    saltgenseed = randombytes(params.PKPSIG_BYTES_SALTGENSEED)
    # Now generate a parameter seed by rejection sampling
    paramseed = randombytes(params.PKPSIG_BYTES_PUBPARAMSEED)
    while not validate_param_seed(paramseed):
        paramseed = randombytes(params.PKPSIG_BYTES_PUBPARAMSEED)
        pass
    # Expand the key to calculate u
    skblob_tmp = paramseed + seckeyseed + saltgenseed + (b'X' * params.PKPSIG_BYTES_SECKEYCHECKSUM)
    keyobj = SecretKey().unpack(skblob_tmp, validate_checksum=False)
    # Encode the public key
    pkblob = paramseed + keyobj.pack_u()
    # Generate the secret key checksum
    hobj = symmetric.hash_init(consts.HASHCTX_SECKEYCHECKSUM, paramseed)
    cksum = symmetric.hash_digest_suffix_fqvec(hobj, keyobj.u, params.PKPSIG_BYTES_SECKEYCHECKSUM)
    # Pack the final secret key
    skblob = paramseed + seckeyseed + saltgenseed + cksum
    # Sanity check
    skeyobj = SecretKey().unpack(skblob)
    assert(keyobj.pi_inv == skeyobj.pi_inv)
    assert(keyobj.u == skeyobj.u)
    pkeyobj = PublicKey().unpack(pkblob)
    assert(keyobj.u == pkeyobj.u)
    return (pkblob, skblob)

