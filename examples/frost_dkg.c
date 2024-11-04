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

#define EXAMPLE_MAX_PARTICIPANTS 4
#define EXAMPLE_MIN_PARTICIPANTS 2

int main(void) {
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
