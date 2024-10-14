#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <libpldm/pldm.h>
#include <libpldm/firmware_update.h>
#include <libpldm/firmware_fd.h>
#include <compiler.h>
#include <msgbuf.h>

struct pldm_fd_component_details {
    uint16_t comp_classification;
    uint16_t comp_identifier;
    uint8_t comp_classification_index;
    // uint32_t comp_comparison_stamp; // TODO not needed?
    uint32_t comp_image_size;
};

struct pldm_fd_download {
    size_t offset;

    /* Set once when ready to exit from Download mode, will return
     * this value for TransferComplete request. */
    enum pldm_firmware_update_transfer_result_values result;

    // TODO FDReq

    bitfield32_t update_flags;

    /* Details of the component currently being updated */
    struct pldm_fd_component_details details;

    // TODO req_comm
    /* Whether a resp is currently expected on req_comm */
    bool req_pending;
};

struct pldm_fd_verify {
    enum pldm_firmware_update_verify_result_values result;

    // TODO FDReq

    /* Details of the component currently being updated */
    struct pldm_fd_component_details details;

    // TODO req_comm
    /* Whether a resp is currently expected on req_comm */
    bool req_pending;
};

struct pldm_fd_apply {
    enum pldm_firmware_update_apply_result_values result;
    bitfield16_t activation_methods;

    // TODO FDReq

    /* Details of the component currently being updated */
    struct pldm_fd_component_details details;

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

/* Creates a response header from a given request */
static pldm_requester_rc_t pldm_fd_resp_header(
    const struct pldm_header_info *req_hdr,
    void *resp_msg, size_t resp_len) {

    if (resp_len < sizeof(struct pldm_msg_hdr)) {
        return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
    }

    struct pldm_header_info resp_hdr;
    memcpy(&resp_hdr, req_hdr, sizeof(resp_hdr));
    resp_hdr.msg_type = PLDM_RESPONSE;

    /* Can't fail */
    pack_pldm_header(&resp_hdr, resp_msg);
    return PLDM_REQUESTER_SUCCESS;
}

static pldm_requester_rc_t pldm_fd_reply_error(uint8_t ccode, 
    const struct pldm_header_info *req_hdr,
    void *resp_msg, size_t *resp_len) {

    pldm_requester_rc_t rc;

    /* Header plus 1 byte completion code */
    if (*resp_len < sizeof(struct pldm_msg_hdr) + 1) {
        return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
    }

    rc = pldm_fd_resp_header(req_hdr, resp_msg, *resp_len);
    if (rc != PLDM_REQUESTER_SUCCESS) {
        return rc;
    }

    struct pldm_msg *r = resp_msg;
    r->payload[0] = ccode;
    *resp_len = sizeof(struct pldm_msg_hdr) + 1;

    return PLDM_REQUESTER_SUCCESS;
}

static pldm_requester_rc_t pldm_fd_qdi(struct pldm_fd *fd,
    const struct pldm_header_info *hdr,
    const void *req LIBPLDM_CC_UNUSED, size_t req_len,
    void *resp_msg, size_t *resp_len)
{
    pldm_requester_rc_t rc;

    /* QDI has no request data */
    if (req_len != PLDM_QUERY_DEVICE_IDENTIFIERS_REQ_BYTES) {
        return pldm_fd_reply_error(PLDM_ERROR_INVALID_LENGTH,
            hdr, resp_msg, resp_len);
    }

    rc = pldm_fd_resp_header(hdr, resp_msg, *resp_len);
    if (rc != PLDM_REQUESTER_SUCCESS) {
        return rc;
    }

    /* Retrieve platform-specific data */
    uint32_t descriptors_len;
    uint8_t descriptors_count;
    const uint8_t* descriptors;
    rc = fd->ops->query_device_identifiers(fd->ops_ctx, 
        &descriptors_len, &descriptors_count, &descriptors);
    if (rc) {
        return pldm_fd_reply_error(rc, hdr, resp_msg, resp_len);
    }

    struct pldm_msgbuf msgbuf;
    struct pldm_msg *msg = resp_msg;
    rc = pldm_msgbuf_init_cc(&msgbuf, 0,
        msg->payload, *resp_len - offsetof(struct pldm_msg, payload));
    if (rc) {
        return pldm_fd_reply_error(rc, hdr, resp_msg, resp_len);
    }

    /* Errors are handled by pldm_msgbuf_destroy */
    rc = pldm_msgbuf_insert_uint8(&msgbuf, PLDM_SUCCESS);
    rc = pldm_msgbuf_insert(&msgbuf, descriptors_len);
    rc = pldm_msgbuf_insert(&msgbuf, descriptors_count);
    rc = pldm_msgbuf_insert_array(&msgbuf, descriptors_len,
        descriptors, descriptors_len);

    size_t used = msgbuf.cursor - msg->payload;
    rc = pldm_msgbuf_destroy(&msgbuf);
    if (rc) {
        return pldm_fd_reply_error(rc, hdr, resp_msg, resp_len);
    }
    *resp_len = used + sizeof(struct pldm_msg_hdr);
    return PLDM_REQUESTER_SUCCESS;
}
 
static pldm_requester_rc_t pldm_fd_handle_resp(struct pldm_fd *fd, pldm_tid_t tid, 
    const void *pldm_msg, size_t msg_len,
    void *resp_msg, size_t *resp_len)
{
    // TODO
    return PLDM_REQUESTER_INVALID_SETUP;
}

pldm_requester_rc_t pldm_fd_setup(struct pldm_fd *fd,
    const struct pldm_fd_ops *ops, void *ops_ctx)
{
    memset(fd, 0x0, sizeof(*fd));
    fd->ops = ops;
    fd->ops_ctx = ops_ctx;

    return PLDM_REQUESTER_SUCCESS;
}

pldm_requester_rc_t pldm_fd_handle_msg(struct pldm_fd *fd, pldm_tid_t tid, 
    const void *pldm_msg, size_t msg_len,
    void *resp_msg, size_t *resp_len)
{
    uint8_t rc;

    if (msg_len < sizeof(struct pldm_msg_hdr)) {
        return PLDM_REQUESTER_INVALID_RECV_LEN;
    }

    struct pldm_header_info hdr;

    rc = unpack_pldm_header(pldm_msg, &hdr);
    if (rc != PLDM_SUCCESS) {
        return PLDM_REQUESTER_RECV_FAIL;
    }
    const void* payload = pldm_msg + sizeof(struct pldm_msg_hdr);
    size_t payload_len = msg_len - sizeof(struct pldm_msg_hdr);

    if (hdr.pldm_type != PLDM_FWUP) {
        return PLDM_REQUESTER_RECV_FAIL;
    }

    if (hdr.msg_type == PLDM_RESPONSE) {
        return pldm_fd_handle_resp(fd, tid, pldm_msg, msg_len, resp_msg, resp_len);
    }

    if (hdr.msg_type != PLDM_REQUEST) {
        return PLDM_REQUESTER_RECV_FAIL;
    }

    /* Check TID */
    switch (hdr.command) {
        case PLDM_QUERY_DEVICE_IDENTIFIERS:
        case PLDM_GET_FIRMWARE_PARAMETERS:
        case PLDM_GET_STATUS:
        case PLDM_CANCEL_UPDATE:
        case PLDM_QUERY_DOWNSTREAM_DEVICES:
        case PLDM_QUERY_DOWNSTREAM_IDENTIFIERS:
        case PLDM_QUERY_DOWNSTREAM_FIRMWARE_PARAMETERS:
            /* Information or cancel commands are always allowed */
            break;
        case PLDM_REQUEST_UPDATE:
            /* Command handler will check TID */
            break;
        default:
            /* Requests must come from the same TID that requested the update */
            if (tid != fd->ua_tid) {
                return pldm_fd_reply_error(PLDM_ERROR_NOT_READY, &hdr, resp_msg, resp_len);
            }
    }

    /* Dispatch command */
    switch (hdr.command) {
        case PLDM_QUERY_DEVICE_IDENTIFIERS:
            rc = pldm_fd_qdi(fd, &hdr, payload, payload_len, resp_msg, resp_len);
            break;
        default:
            rc = PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
    }

    if (rc != PLDM_SUCCESS) {
        return pldm_fd_reply_error(rc, &hdr, resp_msg, resp_len);
    }

    return PLDM_REQUESTER_SUCCESS;
}
