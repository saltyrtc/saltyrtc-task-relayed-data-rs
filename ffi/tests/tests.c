/**
 * C integration test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#include "../saltyrtc_task_relayed_data_ffi.h"


// Function prototypes
void *connect_initiator(void *threadarg);
void *connect_responder(void *threadarg);

// Statics
static sem_t auth_token_set;
static uint8_t *auth_token = NULL;

/**
 * Struct used to pass data from the main thread to the client threads.
 */
struct thread_data {
    uint32_t interval_seconds;
    uint16_t timeout_seconds;
    const salty_keypair_t *keypair;
    const uint8_t *initiator_pubkey;
    const uint8_t *ca_cert;
    long ca_cert_len;
};

/**
 * Client thread for the initiator.
 */
void *connect_initiator(void *threadarg) {
    struct thread_data *data = (struct thread_data *) threadarg;
    printf("  THREAD: Started initiator thread\n");

    printf("    INITIATOR: Creating event loop\n");
    const salty_event_loop_t *loop = salty_event_loop_new();

    printf("    INITIATOR: Getting event loop remote handle\n");
    const salty_remote_t *remote = salty_event_loop_get_remote(loop);
    const salty_remote_t *unused_remote = salty_event_loop_get_remote(loop);

    printf("    INITIATOR: Creating client instance\n");
    salty_relayed_data_client_ret_t client_ret = salty_relayed_data_initiator_new(
        data->keypair,
        remote,
        data->interval_seconds
    );
    if (client_ret.success != OK) {
        printf("    INITIATOR ERROR: Could not create client: %d", client_ret.success);
        pthread_exit((void *)NULL);
    }

    printf("    INITIATOR: Copying auth token to static variable\n");
    auth_token = malloc(32 * sizeof(uint8_t));
    if (auth_token == NULL) {
        printf("      INITIATOR ERROR: Could not allocate memory for auth token");
        pthread_exit((void *)NULL);
    }
    const uint8_t *auth_token_ref = salty_relayed_data_client_auth_token(client_ret.client);
    memcpy(auth_token, auth_token_ref, 32 * sizeof(uint8_t));

    printf("    INITIATOR: Notifying responder that the auth token is ready\n");
    sem_post(&auth_token_set);

    printf("    INITIATOR: Connecting\n");
    salty_client_connect_success_t connect_success = salty_client_connect(
        // Host, port
        "localhost",
        8765,
        // Client
        client_ret.client,
        // Event loop
        loop,
        // Timeout seconds
        data->timeout_seconds,
        // CA certificate
        data->ca_cert,
        (uint32_t)data->ca_cert_len
    );

    printf("    INITIATOR: Connection ended with exit code %d\n", connect_success);
    salty_client_connect_success_t* connect_success_copy = malloc(sizeof(connect_success));
    if (connect_success_copy == NULL) {
        printf("      INITIATOR ERROR: Could not malloc %ld bytes\n", sizeof(connect_success));
        pthread_exit((void *)NULL);
    }
    memcpy(connect_success_copy, &connect_success, sizeof(connect_success));

    printf("    INITIATOR: Freeing unused event loop remote handle\n");
    salty_event_loop_free_remote(unused_remote);

    printf("    INITIATOR: Freeing client instance\n");
    salty_relayed_data_client_free(client_ret.client);

    printf("    INITIATOR: Freeing rx channel instance\n");
    salty_channel_receiver_free(client_ret.rx_chan);

    printf("  INITIATOR: Freeing event loop\n");
    salty_event_loop_free(loop);

    printf("  THREAD: Stopping initiator thread\n");
    pthread_exit((void *)connect_success_copy);
}

/**
 * Client thread for the responder.
 */
void *connect_responder(void *threadarg) {
    struct thread_data *data = (struct thread_data *) threadarg;
    printf("  THREAD: Started responder thread\n");

    printf("    RESPONDER: Creating event loop\n");
    const salty_event_loop_t *loop = salty_event_loop_new();

    printf("    RESPONDER: Getting event loop remote handle\n");
    const salty_remote_t *remote = salty_event_loop_get_remote(loop);

    printf("    RESPONDER: Waiting for auth token semaphore\n");
    sem_wait(&auth_token_set);

    printf("    RESPONDER: Creating client instance\n");
    salty_relayed_data_client_ret_t client_ret = salty_relayed_data_responder_new(
        data->keypair,
        remote,
        data->interval_seconds,
        data->initiator_pubkey,
        auth_token
    );
    if (client_ret.success != OK) {
        printf("      RESPONDER ERROR: Could not create client: %d", client_ret.success);
        pthread_exit((void *)NULL);
    }

    printf("    RESPONDER: Connecting\n");
    salty_client_connect_success_t connect_success = salty_client_connect(
        // Host, port
        "localhost",
        8765,
        // Client
        client_ret.client,
        // Event loop
        loop,
        // Timeout seconds
        data->timeout_seconds,
        // CA certificate
        data->ca_cert,
        (uint32_t)data->ca_cert_len
    );

    printf("    RESPONDER: Connection ended with exit code %d\n", connect_success);
    salty_client_connect_success_t* connect_success_copy = malloc(sizeof(connect_success));
    if (connect_success_copy == NULL) {
        printf("      RESPONDER ERROR: Could not malloc %ld bytes\n", sizeof(connect_success));
        pthread_exit((void *)NULL);
    }
    memcpy(connect_success_copy, &connect_success, sizeof(connect_success));

    printf("    RESPONDER: Freeing client instance\n");
    salty_relayed_data_client_free(client_ret.client);

    printf("    RESPONDER: Freeing rx channel instance\n");
    salty_channel_receiver_free(client_ret.rx_chan);

    printf("  RESPONDER: Freeing event loop\n");
    salty_event_loop_free(loop);

    printf("  THREAD: Stopping responder thread\n");
    pthread_exit((void *)connect_success_copy);
}

/**
 * Main program.
 */
int main() {
    printf("START C TEST\n");

    printf("  Reading DER formatted test CA certificate\n");

    // Open file
    const char *const ca_cert_name = "saltyrtc.der";
    FILE *fd = fopen(ca_cert_name, "rb");
    if (fd == NULL) {
        printf("    ERROR: Could not open `%s`\n", ca_cert_name);
        return EXIT_FAILURE;
    }

    // Get file size
    if (fseek(fd, 0, SEEK_END) != 0) {
        printf("    ERROR: Could not fseek `%s`\n", ca_cert_name);
        return EXIT_FAILURE;
    }
    long ca_cert_len = ftell(fd);
    if (ca_cert_len < 0) {
        printf("    ERROR: Could not ftell `%s`\n", ca_cert_name);
        return EXIT_FAILURE;
    } else if (ca_cert_len >= (1L << 32)) {
        printf("    ERROR: ca_cert_len is larger than 2**32\n");
        return EXIT_FAILURE;
    }
    if (fseek(fd, 0, SEEK_SET) != 0) {
        printf("    ERROR: Could not fseek `%s`\n", ca_cert_name);
        return EXIT_FAILURE;
    }

    // Prepare buffer
    uint8_t *ca_cert = malloc((size_t)ca_cert_len);
    if (ca_cert == NULL) {
        printf("    ERROR: Could not malloc %ld bytes\n", ca_cert_len);
        return EXIT_FAILURE;
    }
    size_t read_bytes = fread(ca_cert, (size_t)ca_cert_len, 1, fd);
    if (read_bytes != 1) {
        printf("    ERROR: Could not read file\n");
        return EXIT_FAILURE;
    }
    if (fclose(fd) != 0) printf("Warning: Closing ca cert file descriptor failed");

    printf("  Initializing logger (level DEBUG)\n");
    if (!salty_log_init(LEVEL_INFO)) {
        return EXIT_FAILURE;
    }
    printf("  Updating logger (level WARN)\n");
    if (!salty_log_change_level(LEVEL_WARN)) {
        return EXIT_FAILURE;
    }

    printf("  Creating key pairs\n");
    const salty_keypair_t *i_keypair = salty_keypair_new();
    const salty_keypair_t *r_keypair = salty_keypair_new();
    const salty_keypair_t *unused_keypair = salty_keypair_new();

    printf("  Copying public key from initiator\n");
    uint8_t *i_pubkey = malloc(32 * sizeof(uint8_t));
    if (i_pubkey == NULL) {
        printf("    ERROR: Could not allocate memory for public key");
        return EXIT_FAILURE;
    }
    const uint8_t *i_pubkey_ref = salty_keypair_public_key(i_keypair);
    memcpy(i_pubkey, i_pubkey_ref, 32 * sizeof(uint8_t));

    printf("  Initiating semaphore\n");
    sem_init(&auth_token_set, 0, 0);

    // Start initiator thread
    pthread_t i_thread;
    struct thread_data i_data = {
        .interval_seconds = 0,
        .timeout_seconds = 5,
        .keypair = i_keypair,
        .initiator_pubkey = NULL,
        .ca_cert = ca_cert,
        .ca_cert_len = ca_cert_len
    };
    pthread_create(&i_thread, NULL, connect_initiator, (void*)&i_data);

    // Start responder thread
    pthread_t r_thread;
    struct thread_data r_data = {
        .interval_seconds = 0,
        .timeout_seconds = 5,
        .keypair = r_keypair,
        .initiator_pubkey = i_pubkey,
        .ca_cert = ca_cert,
        .ca_cert_len = ca_cert_len
    };
    pthread_create(&r_thread, NULL, connect_responder, (void*)&r_data);

    // Joining client threads
    salty_client_connect_success_t *i_success;
    salty_client_connect_success_t *r_success;
    pthread_join(i_thread, (void*)&i_success);
    pthread_join(r_thread, (void*)&r_success);

    bool success = true;
    if (*i_success != CONNECT_OK) {
        printf("ERROR: Connecting initiator was not successful\n");
        success = false;
    } else {
        printf("OK: Connection initiator was successful\n");
    }
    free(i_success);
    if (*r_success != CONNECT_OK) {
        printf("ERROR: Connecting responder was not successful\n");
        success = false;
    } else {
        printf("OK: Connection responder was successful\n");
    }
    free(r_success);
    if (!success) {
        return EXIT_FAILURE;
    }

    printf("CLEANUP\n");

    printf("  Freeing CA cert bytes\n");
    free(ca_cert);

    printf("  Freeing public key copy\n");
    free(i_pubkey);

    printf("  Freeing unused keypair\n");
    salty_keypair_free(unused_keypair);

    printf("  Destroying semaphore\n");
    sem_destroy(&auth_token_set);

    printf("END C TEST\n");

    // Close stdout / stderr to please valgrind
    if (fclose(stdin) != 0) printf("Warning: Closing stdin failed");
    if (fclose(stdout) != 0) printf("Warning: Closing stdout failed");
    if (fclose(stderr) != 0) printf("Warning: Closing stderr failed");

    return EXIT_SUCCESS;
}
