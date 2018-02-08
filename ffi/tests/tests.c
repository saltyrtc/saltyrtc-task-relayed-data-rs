/**
 * C integration test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "../saltyrtc_task_relayed_data_ffi.h"

int main() {
    printf("START C TESTS\n");

    printf("  Initializing logger (level DEBUG)\n");
    if (!salty_log_init(LEVEL_INFO)) {
        exit(EXIT_FAILURE);
    }
    printf("  Updating logger (level WARN)\n");
    if (!salty_log_change_level(LEVEL_WARN)) {
        exit(EXIT_FAILURE);
    }

    // Variables
    uint32_t interval_seconds = 0;

    printf("  Creating key pairs\n");
    const salty_keypair_t *i_keypair = salty_keypair_new();
    const salty_keypair_t *r_keypair = salty_keypair_new();
    const salty_keypair_t *unused_keypair = salty_keypair_new();

    printf("  Creating event loop\n");
    const salty_event_loop_t *loop = salty_event_loop_new();

    printf("  Getting event loop remote handle\n");
    const salty_remote_t *i_remote = salty_event_loop_get_remote(loop);
    const salty_remote_t *r_remote = salty_event_loop_get_remote(loop);
    const salty_remote_t *unused_remote = salty_event_loop_get_remote(loop);

    printf("  Copying public key from initiator\n");
    uint8_t *i_pubkey = malloc(32 * sizeof(uint8_t));
    if (i_pubkey == NULL) {
        printf("  ERROR: Could not allocate memory for public key");
        exit(EXIT_FAILURE);
    }
    const uint8_t *i_pubkey_ref = salty_keypair_public_key(i_keypair);
    memcpy(i_pubkey, i_pubkey_ref, 32 * sizeof(uint8_t));

    printf("  Creating initiator client instance\n");
    salty_relayed_data_client_ret_t i_client_ret = salty_relayed_data_initiator_new(
        i_keypair,
        i_remote,
        interval_seconds
    );

    printf("  Copying auth token from initiator\n");
    uint8_t *i_auth_token = malloc(32 * sizeof(uint8_t));
    if (i_auth_token == NULL) {
        printf("  ERROR: Could not allocate memory for auth token");
        exit(EXIT_FAILURE);
    }
    const uint8_t *i_auth_token_ref = salty_relayed_data_client_auth_token(i_client_ret.client);
    memcpy(i_auth_token, i_auth_token_ref, 32 * sizeof(uint8_t));

    printf("  Creating responder client instance\n");
    salty_relayed_data_client_ret_t r_client_ret = salty_relayed_data_responder_new(
        r_keypair,
        r_remote,
        interval_seconds,
        i_pubkey,
        i_auth_token
    );

    printf("  Connect initiator\n");
    salty_client_connect_success_t i_connect_success = salty_client_connect(
        "http://127.0.0.1:8765",
        i_client_ret.client,
        loop,
        NULL,
        0
    );
    if (i_connect_success != CONNECT_OK) {
        printf("  ERROR: Connecting was not successful\n");
    } else {
        printf("  OK: Connection was successful\n");
    }

    printf("  Freeing public key copy\n");
    free(i_pubkey);

    printf("  Freeing auth token copy\n");
    free(i_auth_token);

    printf("  Freeing client instances\n");
    salty_relayed_data_client_free(r_client_ret.client);
    salty_relayed_data_client_free(i_client_ret.client);

    printf("  Freeing rx channel instances\n");
    salty_channel_receiver_free(r_client_ret.rx_chan);
    salty_channel_receiver_free(i_client_ret.rx_chan);

    printf("  Freeing unused event loop remote handle\n");
    salty_event_loop_free_remote(unused_remote);

    printf("  Freeing unused keypair\n");
    salty_keypair_free(unused_keypair);

    printf("  Freeing event loop\n");
    salty_event_loop_free(loop);

    printf("END C TESTS\n");

    return EXIT_SUCCESS;
}
