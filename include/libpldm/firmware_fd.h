#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <libpldm/pldm.h>
#include <libpldm/base.h>
#include <libpldm/libpldm-fd-sizes.h>

/* Device-specific callbacks provided by an application */
struct pldm_fd_ops {
    uint8_t (*query_device_identifiers)(void* ctx,
        uint32_t *descriptors_len, uint8_t *descriptors_count,
        const uint8_t **descriptors);
};

/* Static storage can be allocated with
 * PLDM_SIZEOF_PLDM_FD macro */
struct pldm_fd;

pldm_requester_rc_t pldm_fd_setup(struct pldm_fd *fd,
    const struct pldm_fd_ops *ops, void *ops_ctx);

pldm_requester_rc_t pldm_fd_handle_msg(struct pldm_fd *fd, pldm_tid_t tid,
    const void *pldm_msg, size_t msg_len,
    void *resp_msg, size_t *resp_len);
