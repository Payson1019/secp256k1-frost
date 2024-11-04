/***********************************************************************
 * Copyright (c) 2023 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

#include <secp256k1.h>
#include <secp256k1_frost.h>

#include "examples_util.h"
#include "frost_dkg_link.h"

/* This function performs the first step of the DKG process. Then the commitment should be exchanged and validated.  */
__attribute__((visibility("default"))) int keygen_dkg_begin(secp256k1_frost_vss_commitments **dkg_commitment,
                                                            secp256k1_frost_keygen_secret_share *shares,
                                                            uint32_t num_participants,
                                                            uint32_t threshold,
                                                            uint32_t generator_index,
                                                            const unsigned char *context,
                                                            uint32_t context_length) {
    secp256k1_context *sign_verify_ctx;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    *dkg_commitment = secp256k1_frost_vss_commitments_create(threshold);
    int result;
    result = secp256k1_frost_keygen_dkg_begin(sign_verify_ctx, *dkg_commitment, shares, num_participants, threshold,
                                           generator_index, context, context_length);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }

    result = secp256k1_frost_keygen_dkg_commitment_validate(sign_verify_ctx, *dkg_commitment, context, context_length);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }
    return result;
}

/* This function gathers commitments from peers and validates the zero knowledge proof of knowledge for the peer's secret term. */
__attribute__((visibility("default"))) int keygen_dkg_commitment_validate(const secp256k1_frost_vss_commitments **peer_commitment,
                                                                          const unsigned char *context,
                                                                          uint32_t context_length) {
    secp256k1_context *sign_verify_ctx;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int result;
    result = secp256k1_frost_keygen_dkg_commitment_validate(sign_verify_ctx, *peer_commitment, context, context_length);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }
    return result;
}

/* This function performs the finalization of the DKG process. */
__attribute__((visibility("default"))) int keygen_dkg_finalize(secp256k1_frost_keypair *keypair,
                                                               uint32_t index,
                                                               uint32_t num_participants,
                                                               const secp256k1_frost_keygen_secret_share *shares,
                                                               secp256k1_frost_vss_commitments **commitments) {
    secp256k1_context *sign_verify_ctx;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int result;
    result = secp256k1_frost_keygen_dkg_finalize(sign_verify_ctx, keypair, index, num_participants, shares, commitments);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }
    return result;
}

/* This function initializes a secp256k1_frost_pubkey using information in a secp256k1_frost_keypair. */
__attribute__((visibility("default"))) int pubkey_from_keypair(secp256k1_frost_pubkey *pubkey,
                                                               const secp256k1_frost_keypair *keypair) {
    int result;
    result = secp256k1_frost_pubkey_from_keypair(pubkey, keypair);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }
    return result;
}

/* This function create a secp256k1 frost nonce. Then the commitment in the nonce should be exchanged. */
__attribute__((visibility("default"))) int create_nonce(secp256k1_frost_nonce** nonce,
                                                        const secp256k1_frost_keypair *keypair) {
    secp256k1_context *sign_verify_ctx;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    if (!fill_random(binding_seed, sizeof(binding_seed))) {
        printf("Failed to generate binding_seed\n");
        return 0;
    }
    if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
        printf("Failed to generate hiding_seed\n");
        return 0;
    }
    printf("index: %d\n", keypair->public_keys.index);
    /* Create the nonce (the function already computes its commitment) */
    *nonce = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                 keypair, binding_seed, hiding_seed);
    printf("nonce commitment index: %d\n", (*nonce)->commitments.index);
    printf("Size of secp256k1_frost_nonce: %zu\n", sizeof(secp256k1_frost_nonce));
    return 1;
}

/* This function compute a tagged hash as defined in BIP-340. */
__attribute__((visibility("default"))) int tagged_sha256(unsigned char *msg_hash,
                                                         const unsigned char *tag,
                                                         uint32_t tag_length,
                                                         const unsigned char *msg,
                                                         uint32_t msg_length) {
    secp256k1_context *sign_verify_ctx;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int result;
    result = secp256k1_tagged_sha256(sign_verify_ctx, msg_hash, tag, tag_length, msg, msg_length);
    print_hex(msg_hash, 32);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }
    return result;
}

/* This function performs the sign process in each participant. */ 
__attribute__((visibility("default"))) int sign(secp256k1_frost_signature_share *signature_share,
                                                const unsigned char *msg_hash,
                                                uint32_t num_signers,
                                                const secp256k1_frost_keypair *keypair,
                                                secp256k1_frost_nonce *nonce,
                                                secp256k1_frost_nonce_commitment *signing_commitments) {
    int result;
    result = secp256k1_frost_sign(signature_share, msg_hash, num_signers, keypair, nonce, signing_commitments);
    print_hex(msg_hash, 32);
    print_hex(signature_share, 64);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }
    return result;
}

/* This function combines signature shares to obtain an aggregated signature. */
__attribute__((visibility("default"))) int aggregate(unsigned char *sig64,
                                                     const unsigned char *msg32,
                                                     const secp256k1_frost_keypair *keypair,
                                                     const secp256k1_frost_pubkey *public_keys,
                                                     secp256k1_frost_nonce_commitment *commitments,
                                                     const secp256k1_frost_signature_share *signature_shares,
                                                     uint32_t num_signers) {
    secp256k1_context *sign_verify_ctx;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int result;
    result = secp256k1_frost_aggregate(sign_verify_ctx, sig64, msg32, keypair, public_keys, commitments, signature_shares, num_signers);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }
    print_hex(msg32, 32);
    print_hex(sig64, 64);
    result = secp256k1_frost_verify(sign_verify_ctx,
                                sig64,
                                msg32,
                                &keypair->public_keys);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }
    return result;
}

/* This function verifies an aggregated signature*/
__attribute__((visibility("default"))) int verify(const unsigned char *sig64,
                                                  const unsigned char *msg32,
                                                  const secp256k1_frost_pubkey *public_keys) {
    secp256k1_context *sign_verify_ctx;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int result;
    result = secp256k1_frost_verify(sign_verify_ctx, sig64, msg32, public_keys);
    if (result != 1) {
        return result; /* Early exit on failure */ 
    }
    return result;
}

#define EXAMPLE_MAX_PARTICIPANTS 4
#define EXAMPLE_MIN_PARTICIPANTS 2
__attribute__((visibility("default"))) int perform_dkg_multisig() {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_by_participant[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_keygen_secret_share shares_per_participant[EXAMPLE_MAX_PARTICIPANTS][EXAMPLE_MAX_PARTICIPANTS];
    int i_share_per_participant[EXAMPLE_MAX_PARTICIPANTS];
    int is_signature_valid;
    int result;
    /* keypairs stores private and public keys for each participant */
    secp256k1_frost_keypair keypair[EXAMPLE_MAX_PARTICIPANTS];
    /* public_key stores only public keys for each participant (this info can/should be shared among signers) */
    secp256k1_frost_pubkey public_key[EXAMPLE_MAX_PARTICIPANTS];
    uint32_t index;
    unsigned char msg[12] = "Hello World!";
    const unsigned char msg_hash[32];
    const unsigned char tag[14] = "frost_protocol";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_share[EXAMPLE_MAX_PARTICIPANTS];
    unsigned char signature[64];
    secp256k1_frost_nonce *nonces[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_nonce_commitment signing_commitments[EXAMPLE_MAX_PARTICIPANTS];

    /* Step 1. initialization */
    dkg_commitment = malloc(EXAMPLE_MAX_PARTICIPANTS * sizeof(secp256k1_frost_vss_commitments *));
    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS; index++) {
        i_share_per_participant[index] = 0;
        dkg_commitment[index] = secp256k1_frost_vss_commitments_create(EXAMPLE_MIN_PARTICIPANTS);
    }
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* Step 2. keygen begin and validate for each participant */
    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS; index++) {
        uint32_t share_index;
        result = secp256k1_frost_keygen_dkg_begin(sign_verify_ctx,
                                                  dkg_commitment[index],
                                                  shares_by_participant,
                /*num_participants*/  EXAMPLE_MAX_PARTICIPANTS, /* threshold */ EXAMPLE_MIN_PARTICIPANTS,
                                                  index + 1, tag, sizeof(tag));
        assert(result == 1);

        result = secp256k1_frost_keygen_dkg_commitment_validate(sign_verify_ctx, dkg_commitment[index], tag, sizeof(tag));
        assert(result == 1);

        /* Step 3. dispatching shares for single participant */
        for (share_index = 0; share_index < EXAMPLE_MAX_PARTICIPANTS; share_index++) {
            uint32_t spi;
            spi = shares_by_participant[share_index].receiver_index - 1;
            shares_per_participant[spi][i_share_per_participant[spi]] =
                    shares_by_participant[share_index];
            i_share_per_participant[spi]++;
        }
    }

    /* Step 4. keygen finalize for each participant */
    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS; index++) {
        result = secp256k1_frost_keygen_dkg_finalize(sign_verify_ctx, &keypair[index], index + 1, EXAMPLE_MAX_PARTICIPANTS,
                                                     shares_per_participant[index],
                                                     dkg_commitment);
        assert(result == 1);
    }

    /* Extracting public_key from keypair. This operation is intended to be executed by each signer.  */
    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS; index++) {
        secp256k1_frost_pubkey_from_keypair(&public_key[index], &keypair[index]);
    }

    /* Step 5: prepare signature commitments */
    /* In FROST, each signer needs to generate a nonce for each signature to compute. A nonce commitment is
     * exchanged among signers to prevent forgery of signature aggregations. */

    /* Nonce:
     * Participants to the signing process generate a new nonce and share the related commitment */
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        /* Generate 32 bytes of randomness to use for computing the nonce. */
        if (!fill_random(binding_seed, sizeof(binding_seed))) {
            printf("Failed to generate binding_seed\n");
            return 1;
        }
        if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
            printf("Failed to generate hiding_seed\n");
            return 1;
        }
        /* Create the nonce (the function already computes its commitment) */
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypair[index], binding_seed, hiding_seed);
        /* Copying secp256k1_frost_nonce_commitment to a shared array across participants */
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Instead of signing (possibly very long) messages directly, we sign a 32-byte hash of the message.
     * We use secp256k1_tagged_sha256 to create this hash.  */
    result = secp256k1_tagged_sha256(sign_verify_ctx, msg_hash, tag, sizeof(tag), msg, sizeof(msg));
    assert(result == 1);

    /* Step 6: compute signature shares
     * At least EXAMPLE_MIN_PARTICIPANTS participants compute a signature share. These
     * signature shares will be then aggregated to compute a single FROST signature. */
        
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        /* The secp256k1_frost_sign function provides a simple interface for signing 32-byte messages
         * (which in our case is a hash of the actual message).
         * Besides the message (msg_hash in this case), the function requires the number of other signers,
         * the private signer keypair and nonce, and the public signing commitments of other participants.
         */
        result = secp256k1_frost_sign(&(signature_share[index]),
                             msg_hash, EXAMPLE_MIN_PARTICIPANTS,
                             &keypair[index],
                             nonces[index],
                             signing_commitments);
        assert(result == 1);
    }

    /* A single entity can aggregate all signature shares. Otherwise, each participant can collect
     * and aggregate all signature shares by the other participants to the signing protocol.
     * We assume all participants are aggregating the signature shares to compute the
     * FROST signature. */

    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        /* Step 4: aggregate signature shares */
        result = secp256k1_frost_aggregate(sign_verify_ctx,
                                           signature,
                                           msg_hash, &keypair[index],
                                           public_key, signing_commitments,
                                           signature_share,
                                           EXAMPLE_MIN_PARTICIPANTS);
        assert(result == 1);

        /* Step 5: verify aggregated signature */
        /* Verify a signature. This will return 1 if it's valid and 0 if it's not. */
        is_signature_valid = secp256k1_frost_verify(sign_verify_ctx,
                                        signature,
                                        msg_hash,
                                        &keypair[index].public_keys);
        assert(is_signature_valid == 1);
    }

    /* Print signature and participant keys */
    printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");
    printf("Group Public Key: ");
    print_hex(keypair[0].public_keys.group_public_key, sizeof(keypair[0].public_keys.group_public_key));
    printf("Signature: ");
    print_hex(signature, sizeof(signature));
    printf("\n");
    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS; index++) {
        printf("Participant #%d: Secret Key: ", index);
        print_hex(keypair[index].secret, sizeof(keypair[index].secret));
        printf("Public Key: ");
        print_hex(keypair[index].public_keys.public_key, sizeof(keypair[index].public_keys.public_key));
    }

    /* Cleaning up */
    /* This will clear everything from the context and free the memory */
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        secp256k1_frost_vss_commitments_destroy(dkg_commitment[index]);
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
    free(dkg_commitment);

    return 0;
}

#define MAX_PARTICIPANTS 4
#define MIN_PARTICIPANTS 2

__attribute__((visibility("default"))) int perform_dkg_multisig_with_interface() {
    /* Context initialization */ 
    const unsigned char context[] = "example_context";
    uint32_t context_length = (uint32_t)strlen((const char*)context);
    uint32_t index;

    /* Step 1: Initialize commitments and shares for participants */ 
    secp256k1_frost_vss_commitments *commitments[MAX_PARTICIPANTS] = {NULL};
    secp256k1_frost_keygen_secret_share shares_by_participant[MAX_PARTICIPANTS][MAX_PARTICIPANTS];
    secp256k1_frost_keypair keypairs[MAX_PARTICIPANTS];

    /* Step 2: DKG Begin for each participant and generate shares */  
    for (index = 0; index < MAX_PARTICIPANTS; index++) {
        printf("Participant %d starting DKG...\n", index);
        
        /* Call DKG Begin */ 
        int result = keygen_dkg_begin(
            &commitments[index], 
            shares_by_participant[index], 
            MAX_PARTICIPANTS, 
            MIN_PARTICIPANTS, 
            index + 1, 
            context, 
            context_length
        );
        
        if (result != 1) {
            printf("Error in DKG Begin for participant %d\n", index);
            return;
        }
    }

    /* Step 3: Validate commitments for each participant */ 
    for (index = 0; index < MAX_PARTICIPANTS; index++) {
        int result = keygen_dkg_commitment_validate((const secp256k1_frost_vss_commitments**)&commitments[index], context, context_length);
        if (result != 1) {
            printf("Commitment validation failed for participant %d\n", index);
            return;
        }
    }

    /* Step 4: Exchange secret shares between participants */ 
    secp256k1_frost_keygen_secret_share shares_per_participant[MAX_PARTICIPANTS][MAX_PARTICIPANTS] = {0};
    int iSharePerParticipant[MAX_PARTICIPANTS] = {0};

    for (index = 0; index < MAX_PARTICIPANTS; index++) {
        printf("Exchanging shares for participant %d...\n", index);
        uint32_t shareIndex;
        for (shareIndex = 0; shareIndex < MAX_PARTICIPANTS; shareIndex++) {
            uint32_t receiverIndex = shares_by_participant[index][shareIndex].receiver_index - 1;
            shares_per_participant[receiverIndex][iSharePerParticipant[receiverIndex]] = shares_by_participant[index][shareIndex];
            iSharePerParticipant[receiverIndex]++;
        }
    }

    /* Step 5: Finalize DKG for each participant */ 
    for (index = 0; index < MAX_PARTICIPANTS; index++) {
        printf("Finalizing DKG for participant %d...\n", index);

        int result = keygen_dkg_finalize(
            &keypairs[index], 
            index + 1, 
            MAX_PARTICIPANTS, 
            shares_per_participant[index], 
            commitments
        );

        if (result != 1) {
            printf("Error in DKG Finalize for participant %d\n", index);
            return;
        }
    }

    /* Step 6: Generate nonces for each participant */ 
    secp256k1_frost_nonce *nonces[MAX_PARTICIPANTS] = {NULL};
    secp256k1_frost_nonce_commitment nonceCommitments[MAX_PARTICIPANTS] = {0};

    for (index = 0; index < MIN_PARTICIPANTS; index++) {
        printf("Creating nonce for participant %d...\n", index);
        int result = create_nonce(&nonces[index], &keypairs[index]);

        if (result != 1) {
            printf("Error in creating nonce for participant %d\n", index);
            return;
        }
        /* nonceCommitments[index] = nonces[index]->commitments; */
        /* Copying secp256k1_frost_nonce_commitment to a shared array across participants */
        memcpy(&nonceCommitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 7: Each participant signs a message */ 
    secp256k1_frost_signature_share signatureShares[MAX_PARTICIPANTS];
    unsigned char msg_hash[32];
    const char message[] = "Test message to sign";
    const unsigned char tag[] = "message_tag";
    uint32_t tag_length = (uint32_t)strlen((const char*)tag);
    
    /* Compute tagged hash for the message */ 
    int result = tagged_sha256(msg_hash, tag, tag_length, (const unsigned char*)message, (uint32_t)strlen(message));
    if (result != 1) {
        printf("Error in creating tagged msg hash\n");
        return;
    }

    for (index = 0; index < MIN_PARTICIPANTS; index++) {
        printf("Participant %d signing message...\n", index);

        result = sign(
            &signatureShares[index], 
            msg_hash, 
            MIN_PARTICIPANTS, 
            &keypairs[index], 
            nonces[index], 
            nonceCommitments
        );

        if (result != 1) {
            printf("Error in signing message for participant %d\n", index);
            return;
        }
    }

    /* Step 8: Aggregate the signatures */ 
    unsigned char aggregateSignature[64];
    secp256k1_frost_pubkey publicKeys[MAX_PARTICIPANTS];

    for (index = 0; index < MAX_PARTICIPANTS; index++) {
        result = pubkey_from_keypair(&publicKeys[index], &keypairs[index]);
        if (result != 1) {
            printf("Error in deriving public key for participant %d\n", index);
            return;
        }
    }

    result = aggregate(
        aggregateSignature, 
        msg_hash, 
        &keypairs[0], 
        publicKeys, 
        nonceCommitments, 
        signatureShares, 
        MIN_PARTICIPANTS
    );
    
    if (result != 1) {
        printf("Error in aggregating signature\n");
        return;
    }

    /* Step 9: Verify the aggregated signature */ 
    result = verify(aggregateSignature, msg_hash, &keypairs[0].public_keys);
    if (result == 1) {
        printf("Signature verified successfully!\n");
    } else {
        printf("Signature verification failed\n");
    }
}