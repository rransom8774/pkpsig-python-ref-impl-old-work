
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

def hash_commit1s(messagehash, commit1s):
    return symmetric.tree_hash_sorting(consts.HASHCTX_CHALLENGE1HASH,
                                       messagehash,
                                       params.PKPSIG_TREEHASH_PARAM_STRING,
                                       commit1s,
                                       False,
                                       params.PKPSIG_BYTES_TREEHASHNODE,
                                       params.PKPSIG_BYTES_CHALLENGESEED)

def expand_challenge1s(messagehash, challenge1_seed):
    hobj = symmetric.hash_init(consts.HASHCTX_CHALLENGE1EXPAND, messagehash)
    return symmetric.hash_expand_suffix_to_fqvec(hobj, params.PKPSIG_TREEHASH_PARAM_STRING + challenge1_seed,
                                                 params.PKPSIG_NRUNS_TOTAL)

def hash_commit2s(messagehash, commit2s):
    return symmetric.tree_hash_sorting(consts.HASHCTX_CHALLENGE2HASH,
                                       messagehash,
                                       params.PKPSIG_TREEHASH_PARAM_STRING,
                                       commit2s,
                                       True,
                                       params.PKPSIG_BYTES_TREEHASHNODE,
                                       params.PKPSIG_BYTES_CHALLENGESEED)

def expand_challenge2s(messagehash, challenge1_seed, challenge2_seed):
    hobj = symmetric.hash_init(consts.HASHCTX_CHALLENGE2EXPAND, messagehash)
    # b=1 is the long-proof case here;
    # zkpshamir will invert b for consistency with eprint 2018/714
    return symmetric.hash_expand_suffix_to_fwv_nonuniform(hobj,
                                                          params.PKPSIG_TREEHASH_PARAM_STRING +
                                                          challenge1_seed + challenge2_seed,
                                                          params.PKPSIG_NRUNS_TOTAL,
                                                          params.PKPSIG_NRUNS_LONG)

def store_intermediate_value(ivs, name, value):
    if ivs is not None:
        ivs[name] = value
        pass
    pass

def generate_signature(sk, message, ivs = None):
    salt = generate_msghash_salt(sk, message)
    messagehash = hash_message(salt, message)
    ctx = zkp.ProverContext(sk, messagehash)
    runs = [zkp.ProverRun(ctx, i) for i in range(params.PKPSIG_NRUNS_TOTAL)]
    commit1s = list()
    for run in runs:
        run.setup()
        commit1s.extend(run.commit1())
        pass
    store_intermediate_value(ivs, 'commit1s', commit1s)
    challenge1_seed = hash_commit1s(messagehash, commit1s)
    challenge1s = expand_challenge1s(messagehash, challenge1_seed)
    commit2s = list()
    for run in runs:
        run.challenge1(challenge1s[run.run_index])
        commit2s.append((run.run_index, run.commit2()))
        pass
    store_intermediate_value(ivs, 'commit2s', commit2s)
    challenge2_seed = hash_commit2s(messagehash, commit2s)
    challenge2s = expand_challenge2s(messagehash, challenge1_seed, challenge2_seed)
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
                 bytes(vectenc.encode_root(spills_root, spills_root_bound)))
    return signature

def verify_signature(pk, signature, message, ivs = None):
    signature = bytes(signature)
    if len(signature) != params.BYTES_SIGNATURE:
        raise common.DataError('Signature has wrong length')
    salt, challenge1_seed, challenge2_seed, proofs_bulk, spills_enc, spills_root_enc = \
        common.split_sequence_fields(signature,
                                     (params.PKPSIG_BYTES_MSGHASHSALT,
                                      params.PKPSIG_BYTES_CHALLENGESEED,
                                      params.PKPSIG_BYTES_CHALLENGESEED,
                                      params.PKPSIG_TOTAL_BULK_LEN,
                                      params.PKPSIG_TOTAL_SPILLS_ENC_LEN,
                                      params.PKPSIG_TOTAL_SPILLS_ROOT_BYTES))
    messagehash = hash_message(salt, message)
    ctx = zkp.VerifierContext(pk, messagehash)
    challenge1s = expand_challenge1s(messagehash, challenge1_seed)
    challenge2s = expand_challenge2s(messagehash, challenge1_seed, challenge2_seed)
    tmp = list(zip(challenge2s, range(params.PKPSIG_NRUNS_TOTAL), challenge1s))
    tmp.sort()
    run_order = [tmp[i][1] for i in range(params.PKPSIG_NRUNS_TOTAL)]
    runs = [zkp.VerifierRun(ctx, run_order[i]) for i in range(params.PKPSIG_NRUNS_TOTAL)]
    for i in range(params.PKPSIG_NRUNS_TOTAL):
        assert(tmp[i][1] == runs[i].run_index)
        runs[i].challenge1(tmp[i][2])
        runs[i].challenge2(tmp[i][0]) # 0 if i <= params.PKPSIG_NRUNS_SHORT; 1 otherwise
        pass
    bulk_parts, spill_bounds_all, spill_bounds_parts = list(), list(), list()
    # Recover the sizes; these should be purely hard-coded in a real implementation
    nbytes, spill_bounds = ctx.get_proof_size_common()
    for i in range(params.PKPSIG_NRUNS_TOTAL):
        bulk_parts.append(nbytes)
        spill_bounds_all.extend(spill_bounds)
        spill_bounds_parts.append(len(spill_bounds))
        pass
    for i in range(params.PKPSIG_NRUNS_TOTAL):
        nbytes, spill_bounds = runs[i].get_proof_size_b_dep()
        bulk_parts.append(nbytes)
        spill_bounds_all.extend(spill_bounds)
        spill_bounds_parts.append(len(spill_bounds))
        pass
    bulks = common.split_sequence_fields(proofs_bulk, bulk_parts)
    if len(spill_bounds) != 0:
        spills_size = vectenc.size(spill_bounds) # sanity check
        assert(spills_size.lenS == params.PKPSIG_TOTAL_SPILLS_ENC_LEN)
        assert(spills_size.root_bound == params.PKPSIG_TOTAL_SPILLS_ROOT_BOUND)
        assert(spills_size.root_bytes == params.PKPSIG_TOTAL_SPILLS_ROOT_BYTES)
        spills_root = vectenc.decode_root(spills_root_enc, params.PKPSIG_TOTAL_SPILLS_ROOT_BOUND)
        spills_all = vectenc.decode(spills_enc, spill_bounds_all, spills_root)
        spills_parts = common.split_sequence_fields(spills_all, spill_bounds_parts)
        pass
    else:
        spills_parts = [()]*(params.PKPSIG_NRUNS_TOTAL * 2)
        pass
    # Process the common parts of the proofs
    commit1s = list()
    for i in range(params.PKPSIG_NRUNS_TOTAL):
        commit1s.extend(ctx.decode_proof_common(i, challenge2s[i], bulks[i], spills_parts[i]))
        pass
    # Process the b-dependent parts of the proofs
    commit2s = list()
    for i in range(params.PKPSIG_NRUNS_TOTAL):
        runs[i].decode_proof_b_dep(bulks[params.PKPSIG_NRUNS_TOTAL + i],
                                   spills_parts[params.PKPSIG_NRUNS_TOTAL + i])
        commit1s.extend(runs[i].commit1())
        commit2s.append((runs[i].run_index, runs[i].commit2()))
        pass
    store_intermediate_value(ivs, 'commit1s', commit1s)
    store_intermediate_value(ivs, 'commit2s', commit2s)
    challenge1_seed_check = hash_commit1s(messagehash, commit1s)
    challenge2_seed_check = hash_commit2s(messagehash, commit2s)
    return ((challenge1_seed == challenge1_seed_check) and
            (challenge2_seed == challenge2_seed_check))

