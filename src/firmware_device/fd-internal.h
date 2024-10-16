#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <libpldm/pldm.h>
#include <libpldm/firmware_update.h>
#include <libpldm/firmware_fd.h>
#include <libpldm/utils.h>

struct pldm_fd_download {
    size_t offset;

    /* Set once when ready to exit from Download mode, will return
     * this value for TransferComplete request. */
    enum pldm_firmware_update_transfer_result_values result;

    // TODO FDReq

    bitfield32_t update_flags;

    /* Details of the component currently being updated */
    struct pldm_component_image_information image;

    // TODO req_comm
    /* Whether a resp is currently expected on req_comm */
    bool req_pending;
};

struct pldm_fd_verify {
    enum pldm_firmware_update_verify_result_values result;

    // TODO FDReq

    /* Details of the component currently being updated */
    struct pldm_component_image_information image;

    // TODO req_comm
    /* Whether a resp is currently expected on req_comm */
    bool req_pending;
};

struct pldm_fd_apply {
    enum pldm_firmware_update_apply_result_values result;
    bitfield16_t activation_methods;

    // TODO FDReq

    /* Details of the component currently being updated */
    struct pldm_component_image_information image;

    // TODO req_comm
    /* Whether a resp is currently expected on req_comm */
    bool req_pending;
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

    pldm_tid_t ua_tid;

    /* Timestamp for FD T1 timeout, milliseconds */
    // TODO: datatype?
    uint64_t update_timestamp_fd_t1;

    const struct pldm_fd_ops *ops;
    void *ops_ctx;
};
