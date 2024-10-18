#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <libpldm/pldm.h>
#include <libpldm/firmware_update.h>
#include <libpldm/firmware_fd.h>
#include <libpldm/utils.h>

typedef uint64_t pldm_fd_time_t;

struct pldm_fd_req {
    enum {
        // Ready to send a request
        PLDM_FD_REQ_READY,
        // Waiting for a response
        PLDM_FD_REQ_SENT,
        // Completed and failed, will not send more requests.
        // Waiting for a cancel from the UA.
        PLDM_FD_REQ_FAILED,
    } state;

    /* Only valid in SENT state */
    uint8_t instance;
    uint8_t command;
    pldm_fd_time_t sent_time;

    /* Only valid in FAILED state */
    uint8_t failed_ccode;

    /* Instance ID of last request */
    uint8_t instance_id;
};

struct pldm_fd_download {
    /* Set once when ready to exit from Download mode, will return
     * this value for TransferComplete request. */
    bool complete;
    enum pldm_firmware_update_transfer_result_values result;

    bitfield32_t update_flags;
    uint32_t offset;
};

struct pldm_fd_verify {
    bool complete;
    enum pldm_firmware_update_verify_result_values result;
};

struct pldm_fd_apply {
    bool complete;
    enum pldm_firmware_update_apply_result_values result;
    bitfield16_t activation_methods;
};

/* Update mode idle timeout, 120 seconds */
// static const uint64_t FD_T1_TIMEOUT = 120000;

struct pldm_fd {
    enum pldm_firmware_device_states state;
    enum pldm_firmware_device_states prev_state;

    /* Reason for last transition to idle state,
     * only valid when state == PLDM_FD_STATE_IDLE */
    enum pldm_get_status_reason_code_values reason;

    union {
        struct pldm_fd_download download;
        struct pldm_fd_verify verify;
        struct pldm_fd_apply apply;
    } specific;
    /* Details of the component currently being updated.
     * Set by UpdateComponent, available during download/verify/apply.
     * Also used as temporary storage for PassComponentTable */
    struct pldm_firmware_update_component update_comp;

    /* Used for download/verify/apply requests */
    struct pldm_fd_req req;

    pldm_tid_t ua_tid;
    bool ua_tid_set;

    /* Maximum size allowed by the UA */
    uint32_t max_transfer;

    /* Maximum firmware data size allowed by local application */
    uint32_t local_max_transfer;

    /* Timestamp for FD T1 timeout, milliseconds */
    // TODO: datatype?
    uint64_t update_timestamp_fd_t1;

    const struct pldm_fd_ops *ops;
    void *ops_ctx;

};
