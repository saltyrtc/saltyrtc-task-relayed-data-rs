/**
 * C integration test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../saltyrtc_task_relayed_data_ffi.h"

int main() {
    printf("START C TESTS\n");

    printf("  Creating key pair\n");
    salty_keypair_t *keypair = salty_keypair_new();

    printf("  Creating event loop\n");
    salty_event_loop_t *loop = salty_event_loop_new();

    printf("  Getting event loop remote handle\n");
    salty_remote_t *remote = salty_event_loop_get_remote(loop);

    printf("  Creating client instance\n");
    uint32_t interval_seconds = 0;
    salty_relayed_data_client_ret_t client_ret = salty_relayed_data_initiator_new(
        keypair,
        remote,
        interval_seconds
    );

    printf("  Freeing client instance\n");
    salty_relayed_data_client_free(client_ret.client);

    printf("  Freeing rx channel instance\n");
    salty_channel_receiver_free(client_ret.rx_chan);

    printf("  Freeing event loop\n");
    salty_event_loop_free(loop);

    printf("END C TESTS\n");
}
