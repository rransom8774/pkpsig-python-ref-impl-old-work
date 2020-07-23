
# Authors: Robert Ransom

# This software is released to the public domain.

from . import common, consts, keys, params, permops, symmetric, vectenc, zkpshamir

zkp = zkpshamir

def generate_msghash_salt(sk, message):
    hobj = symmetric.hash_init(consts.HASHCTX_INTERNAL_GENMSGHASHSALT)
    return symmetric.hash_digest_suffix(hobj,
                                        message + sk.saltgenseed,
                                        params.PKPSIG_BYTES_MSGHASHSALT)

def hash_message(salt, message):
    hobj = symmetric.hash_init(consts.HASHCTX_MESSAGEHASH, salt)
    return symmetric.hash_digest_suffix(hobj, message, params.PKPSIG_BYTES_MESSAGEHASH)

def generate_signature(sk, message):
    salt = generate_msghash_salt(sk, message)
    messagehash = hash_message(salt, message)
    ctx = zkp.ProverContext(sk, messagehash)
    runs = [zkp.ProverRun(ctx, i) for i in range(params.PKPSIG_NRUNS_TOTAL)]
    commit1s = list()
    for run in runs:
        run.setup()
        commit1s.append((run.run_index, run.commit1()))
        pass
    challenge1_seed = \
        symmetric.tree_hash_sorting(consts.HASHCTX_CHALLENGE1HASH,
                                    messagehash,
                                    params.PKPSIG_TREEHASH_PARAM_STRING,
                                    commit1s,
                                    params.PKPSIG_BYTES_TREEHASHNODE,
                                    params.PKPSIG_BYTES_CHALLENGESEED)
    hobj = symmetric.hash_init(consts.HASHCTX_CHALLENGE1EXPAND, messagehash)
    challenge1s = symmetric.hash_expand_suffix_to_fqvec(hobj, challenge1_seed, params.PKPSIG_NRUNS_TOTAL)
    commit2s = list()
    for run in runs:
        run.challenge1(challenge1s[run.run_index])
        commit2s.append((run.run_index, run.commit2()))
        pass
    challenge2_seed = \
        symmetric.tree_hash_sorting(consts.HASHCTX_CHALLENGE2HASH,
                                    messagehash,
                                    params.PKPSIG_TREEHASH_PARAM_STRING,
                                    commit2s,
                                    params.PKPSIG_BYTES_TREEHASHNODE,
                                    params.PKPSIG_BYTES_CHALLENGESEED)
    hobj = symmetric.hash_init(consts.HASHCTX_CHALLENGE2EXPAND, messagehash)
    # b=1 is the long-proof case here;
    # zkpshamir will invert b for consistency with eprint 2018/714
    challenge2s = symmetric.hash_expand_suffix_to_fwv_nonuniform(hobj, challenge2_seed,
                                                                 params.PKPSIG_NRUNS_TOTAL,
                                                                 params.PKPSIG_NRUNS_LONG)
    proofs_common, proofs_short, proofs_long = list(), list(), list()
    for i in range(len(runs)):
        run = runs[i]
        assert(run.run_index == i)
        b = challenge2s[i]
        run.challenge2(b)
        proofs_common.append(run.encode_proof_common())
        if b == 0:
            proofs_short.append(run.encode_proof_b_dep())
            pass
        elif b == 1:
            proofs_long.append(run.encode_proof_b_dep())
            pass
        else:
            assert(not "can't happen")
            pass
        pass
    bulks, spills, spill_bounds = list(), list(), list()
    # XXX should be extracted into a function or class     
    for i in range(params.PKPSIG_NRUNS_TOTAL):
        bulk, R, M = proofs_common[i]
        assert(len(R) == len(M))
        bulks.append(bulk)
        spills.extend(R)
        spill_bounds.extend(M)
        pass
    for i in range(params.PKPSIG_NRUNS_SHORT):
        bulk, R, M = proofs_short[i]
        assert(len(R) == len(M))
        bulks.append(bulk)
        spills.extend(R)
        spill_bounds.extend(M)
        pass
    for i in range(params.PKPSIG_NRUNS_LONG):
        bulk, R, M = proofs_long[i]
        assert(len(R) == len(M))
        bulks.append(bulk)
        spills.extend(R)
        spill_bounds.extend(M)
        pass
    if len(spills) != 0:
        spills_enc, spills_root, spills_root_bound = vectenc.encode(spills, spill_bounds)
        pass
    else:
        spills_enc, spills_root, spills_root_bound = b'', 0, 1
    assert(params.PKPSIG_TOTAL_BULK_LEN == sum(len(b) for b in bulks))
    assert(params.PKPSIG_TOTAL_SPILLS_ENC_LEN == len(spills_enc))
    assert(params.PKPSIG_TOTAL_SPILLS_ROOT_BOUND == spills_root_bound)
    signature = (salt +
                 challenge1_seed +
                 challenge2_seed +
                 b''.join(bulks) +
                 bytes(spills_enc) +
                 byte(vectenc.encode_root(spills_root, spills_root_bound)))
    return signature


    
    
    
    
    
    







