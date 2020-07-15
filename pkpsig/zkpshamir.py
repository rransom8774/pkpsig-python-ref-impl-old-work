
# Authors: Robert Ransom

# This software is released to the public domain.

import collections

from . import common, consts, keys, params, permops, symmetric, vectenc

BlindingValues = collections.namedtuple('BlindingValues', ('pi_sigma_inv', 'r_sigma', 'commitment'))

class VerifierContext(object):
    __slots__ = ('key', 'messagehash', 'hobj_ebs')
    def __init__(self, key, messagehash):
        self.key = key
        self.messagehash = messagehash
        self.hobj_ebs = symmetric.hash_init(consts.HASHCTX_EXPANDBLINDINGSEED, self.messagehash)
        self.hobj_com0 = symmetric.hash_init(consts.HASHCTX_COMMITMENT, self.messagehash)
        pass
    def expand_blindingseed(self, run_index, blindingseed, check_uniform = False):
        idx = run_index * consts.HASHIDX_EXPANDBLINDINGSEED_RUN_INDEX_FACTOR
        pi_sigma_inv = symmetric.hash_expand_index_seed_perm(self.hobj_ebs, idx + consts.HASHIDX_EXPANDBLINDINGSEED_PI_SIGMA_INV, blindingseed, params.PKP_N, check_uniform)
        if check_uniform and (pi_sigma_inv is None):
            return None
        r_sigma = symmetric.hash_expand_index_seed_fqvec(self.hobj_ebs, idx + consts.HASHIDX_EXPANDBLINDINGSEED_R_SIGMA, blindingseed, params.PKP_N, check_uniform)
        if check_uniform and (r_sigma is None):
            return None
        commitment = hash_expand_index_seed(self.hobj_ebs, idx + consts.HASHIDX_EXPANDBLINDINGSEED_COMMITMENT, blindingseed, params.PKPSIG_BYTES_COMMITHASH)
        return BlindingValues(pi_sigma_inv, r_sigma, commitment)
    pass

class ProverContext(VerifierContext):
    __slots__ = ('hobj_gbs',)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        hobj_gbsgs = symmetric.hash_init(consts.HASHCTX_INTERNAL_GENBLINDINGSEEDGENSEED, self.key.pubseed + self.key.secseed)
        blindingseedgenseed = symmetric.hash_digest_suffix(hobj_gbsgs, self.messagehash, params.PKPSIG_BYTES_INTERNAL_BLINDINGSEEDGENSEED)
        self.hobj_gbs = symmetric.hash_init(consts.HASHCTX_INTERNAL_GENBLINDINGSEED, blindingseedgenseed)
        pass
    def generate_blindingseed(self, run_index):
        hobj = self.hobj_gbs
        while True:
            seedbuf = symmetric.hash_expand_index(hobj, run_index,
                                                  params.PKPSIG_BYTES_INTERNAL_BLINDINGSEEDGENSEED +
                                                  params.PKPSIG_BYTES_BLINDINGSEED)
            nextbsgseed, blindingseed = \
                common.split_sequence_fields(seedbuf, (params.PKPSIG_BYTES_INTERNAL_BLINDINGSEEDGENSEED,
                                                       params.PKPSIG_BYTES_BLINDINGSEED))
            blindingvalues = self.expand_blindingseed(run_index, blindingseed, check_uniform=True)
            if blindingvalues is not None:
                return (blindingseed, blindingvalues)
            else:
                hobj = symmetric.hash_init(consts.HASHCTX_INTERNAL_GENBLINDINGSEED, nextbsgseed)
                pass
            pass
        pass
    pass

class ProverRun(object):
    __slots__ = ('ctx', 'run_index',
                 'blindingseed', 'pi_sigma_inv', 'r_sigma', 'com1',
                 'sigma_inv', 'com0',
                 'c', 'z',
                 'b')
    def __init__(self, ctx, run_index):
        self.ctx = ctx
        self.run_index = run_index
        pass
    def setup(self):
        "Generate the blinding seed and derived values."
        self.blindingseed, bvals = self.ctx.generate_blindingseed(self.run_index)
        self.pi_sigma_inv = bvals.pi_sigma_inv
        self.r_sigma = bvals.r_sigma
        # com1 serves as a commitment to (pi sigma, r_sigma)
        self.com1 = bvals.commitment
        pass
    def commit1(self):
        "Generate and return the commitment for the first ZKP pass."
        assert(hasattr(self, 'blindingseed'))
        # (pi sigma)^(-1) == sigma^(-1) pi^(-1)
        self.sigma_inv = permops.compose_inv(self.pi_sigma_inv, self.ctx.key.pi_inv)
        r = permops.apply_inv(self.r_sigma, self.sigma_inv)
        Ar = self.ctx.key.A.mult_vec(r)
        # com0 serves as a commitment to (sigma, A*r)
        self.com0 = symmetric.hash_digest_index_perm_fqvec(self.ctx.hobj_com0,
                                                           self.run_index, self.sigma_inv, Ar,
                                                           params.PKPSIG_BYTES_COMMITHASH)
        return self.com0 + self.com1
    def challenge1(self, c):
        "Set the challenge (in GF(q)) for the second ZKP pass."
        assert(hasattr(self, 'com0'))
        assert(c >= 0)
        assert(c <= params.PKP_Q)
        self.c = c
        pass
    def commit2(self):
        "Generate and return the commitment for the third ZKP pass (second commitment pass)."
        assert(hasattr(self, 'c'))
        v_pi_sigma = permops.apply_inv(self.ctx.key.v, self.pi_sigma_inv)
        # z = r_sigma + c v_(pi sigma)
        self.z = tuple((self.r_sigma[i] + self.c*v_pi_sigma[i]) % params.PKP_Q for i in range(params.PKP_N))
        return symmetric.fqvec_to_hash_input(self.z)
    def challenge2(self, one_minus_b):
        """
        Set the challenge (in {0, 1}) for the fourth ZKP pass (second challenge pass).

        Note that the challenge 1 passed as input here should result in the
        longer of the two possible answer formats, which in this optimized
        version of Shamir's protocol is b=0.
        """
        assert(hasattr(self, 'z'))
        assert(b in (0, 1))
        self.b = 1 - one_minus_b
        pass
    def encode_proof(self):
        """
        prover_run.encode_proof() -> (bytes, spills, spill_bounds)

        Return the information needed to regenerate the commitments for
        this ZKP run, given the challenges, message hash, and public key.

        The size of the proof information must depend solely on the context
        and challenges.
        """
        com_1_minus_b = (self.com1, self.com0)[self.b]
        if self.b == 0:
            sigma = permops.inverse(self.sigma_inv)
            z_enc, z_root, z_root_bound = vectenc.encode(self.z, [params.PKP_Q]*params.PKP_N)
            if params.PKPSIG_SIGFMT_SQUISH_PERMUTATIONS:
                for i in range(len(sigma)):
                    for j in range(i, len(sigma)):
                        if sigma[j] > sigma[i]:
                            sigma[j] -= 1
                            pass
                        pass
                    pass
                sigma_M = [params.PKP_N-i for i in range(params.PKP_N-1)]
                pass
            else:
                sigma_M = [params.PKP_N]*params.PKP_N
                pass
            sigma_enc, sigma_root, sigma_root_bound = vectenc.encode(sigma, sigma_M)
            if params.PKPSIG_SIGFMT_MERGE_VECTOR_ROOTS:
                return (com_1_minus_b + bytes(z_enc) + bytes(sigma_enc),
                        (z_root, sigma_root),
                        (z_root_bound, sigma_root_bound))
            else:
                z_enc.extend(vectenc.encode_root(z_root, z_root_bound))
                sigma_enc.extend(vectenc.encode_root(sigma_root, sigma_root_bound))
                return (com_1_minus_b + bytes(z_enc) + bytes(sigma_enc), (), ())
            pass
        elif self.b == 1:
            return (com_1_minus_b, (), ())
        assert(not "can't happen")
        pass
    pass

class VerifierRun(object):
    __slots__ = ('ctx', 'run_index',
                 'c', 'b',
                 'com0', 'com1', 'z')
    def __init__(self, ctx, run_index):
        self.ctx = ctx
        self.run_index = run_index
        pass
    def challenge1(self, c):
        "Set the challenge (in GF(q)) for the second ZKP pass."
        assert(not hasattr(self, 'c'))
        self.c = c
        pass
    def challenge2(self, one_minus_b):
        """
        Set the challenge (in {0, 1}) for the fourth ZKP pass (second challenge pass).

        Note that the challenge 1 passed as input here should result in the
        longer of the two possible answer formats, which in this optimized
        version of Shamir's protocol is b=0.
        """
        assert(not hasattr(self, 'b'))
        self.b = 1 - one_minus_b
        pass
    def get_proof_size(self):
        """
        verifier_run.get_proof_size() -> (nbytes, spill_bounds)

        Return the size of the data which ProverRun.encode_proof() would have
        returned given the context and challenges.
        """
        if self.b == 0:
            nbytes = (params.PKPSIG_BYTES_COMMITHASH +
                      params.VECTSIZE_SIG_Z.lenS +
                      params.VECTSIZE_SIG_PERM.lenS)
            spill_bounds = (params.VECTSIZE_SIG_Z.root_bound,
                            params.VECTSIZE_SIG_PERM.root_bound)
            if params.PKPSIG_SIGFMT_MERGE_VECTOR_ROOTS:
                return (nbytes, spill_bounds)
            else:
                return sum((vectenc.root_bound_to_bytes(m) for m in spill_bounds),
                           start=nbytes)
            pass
        elif self.b == 1:
            return (params.PKPSIG_BYTES_COMMITHASH, ())
        assert(not "can't happen")
        pass
    def decode_proof(self, bulk, spills):
        "Decode the proof information and regenerate the commitments."
        com_1_minus_b = bulk[:params.PKPSIG_BYTES_COMMITHASH]
        if self.b == 0:
            self.com1 = com_1_minus_b
            vects = bulk[params.PKPSIG_BYTES_COMMITHASH:]
            z_nbytes = params.VECTSIZE_SIG_Z.lenS
            sigma_nbytes = params.VECTSIZE_SIG_PERM.lenS
            if not params.PKPSIG_SIGFMT_MERGE_VECTOR_ROOTS:
                z_nbytes += params.VECTSIZE_SIG_Z.root_bytes
                sigma_nbytes += params.VECTSIZE_SIG_PERM.root_bytes
                pass
            z_enc, sigma_enc = \
                common.split_sequence_fields(vects, (z_nbytes, sigma_nbytes))
            if params.PKPSIG_SIGFMT_MERGE_VECTOR_ROOTS:
                z_root, sigma_root = spills
                pass
            else:
                z_root = vectenc.decode_root(z_enc[params.VECTSIZE_SIG_Z.lenS:],
                                             params.VECTSIZE_SIG_Z.root_bound)
                z_enc = z_enc[:params.VECTSIZE_SIG_Z.lenS]
                sigma_root = vectenc.decode_root(sigma_enc[params.VECTSIZE_SIG_PERM.lenS:],
                                                 params.VECTSIZE_SIG_PERM.root_bound)
                sigma_enc = sigma_enc[:params.VECTSIZE_SIG_PERM.lenS]
                pass
            self.z = vectenc.decode(z_enc, [params.PKP_Q]*params.PKP_N, z_root)
            if params.PKPSIG_SIGFMT_SQUISH_PERMUTATIONS:
                sigma = vectenc.decode(sigma_enc, [params.PKP_N-i for i in range(params.PKP_N-1)], sigma_root)
                for i in range(len(sigma)):
                    for j in range(i, len(sigma)):
                        if sigma[j] > sigma[i]:
                            sigma[j] += 1
                            pass
                        pass
                    pass
                pass
            else:
                sigma = vectenc.decode(sigma_enc, [params.PKP_N]*params.PKP_N, sigma_root)
                pass
            # z = r_sigma + c*v_(pi sigma);
            # public key is u such that u = A*v_pi;
            # need to compute and check A*r
            sigma_inv, z_sigma_inv = permops.inverse_and_apply_inv(self.z, sigma)
            # z_sigma_inv = r + c*v_pi; A*z_sigma_inv = A*r + c*u
            Ar_plus_cu = self.ctx.key.A.mult_vec(z_sigma_inv)
            Ar = tuple((Ar_plus_cu[i] + (params.PKP_Q - self.c)*self.ctx.key.u[i]) % params.PKP_Q
                       for i in range(params.PKP_N))
            self.com0 = symmetric.hash_digest_index_perm_fqvec(self.ctx.hobj_com0,
                                                               self.run_index, sigma_inv, Ar,
                                                               params.PKPSIG_BYTES_COMMITHASH)
            pass
        elif self.b == 1:
            self.com0 = com_1_minus_b
            blindingseed = bulk[params.PKPSIG_BYTES_COMMITHASH:]
            bvals = self.ctx.expand_blindingseed(self.run_index, blindingseed)
            # com1 serves as a commitment to (pi sigma, r_sigma)
            self.com1 = bvals.commitment
            # z = r_sigma + c*v_(pi sigma);
            # need to recompute z from (pi_sigma_inv, r_sigma)
            v_pi_sigma = permops.apply_inv(self.ctx.key.v, bvals.pi_sigma_inv)
            self.z = tuple((bvals.r_sigma[i] + self.c*v_pi_sigma[i]) % params.PKP_Q
                           for i in range(params.PKP_N))
            pass
        assert(not "can't happen")
        pass
    def commit1(self):
        "Generate and return the commitment for the first ZKP pass."
        return self.com0 + self.com1
    def commit2(self):
        "Generate and return the commitment for the third ZKP pass (second commitment pass)."
        return symmetric.fqvec_to_hash_input(self.z)
    pass

