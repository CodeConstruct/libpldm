#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <libpldm/pldm.h>
#include <libpldm/firmware_update.h>
#include <libpldm/firmware_fd.h>
#include <libpldm/utils.h>
#include <compiler.h>
#include <msgbuf.h>

#include "fd-internal.h"

static pldm_requester_rc_t pldm_fd_reply_error(uint8_t ccode,
	const struct pldm_header_info *req_hdr,
	struct pldm_msg *resp, size_t *resp_payload_len) {

	int rc;

	/* 1 byte completion code */
	if (*resp_payload_len < 1) {
		return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
	}
	*resp_payload_len = 1;

	rc = encode_cc_only_resp(req_hdr->instance,
		PLDM_FWUP, req_hdr->command, ccode, resp);
	if (rc != PLDM_SUCCESS) {
		return PLDM_REQUESTER_RECV_FAIL;
	}
	return PLDM_REQUESTER_SUCCESS;
}


static void pldm_fd_set_state(struct pldm_fd *fd,
	enum pldm_firmware_device_states state) {
	/* pldm_fd_set_idle should be used instead */
	assert(state != PLDM_FD_STATE_IDLE);

	if (fd->state == state) {
		return;
	}

	fd->prev_state = fd->state;
	fd->state = fd->state;
}

// static void pldm_fd_set_idle(struct pldm_fd *fd,
// 	enum pldm_get_status_reason_code_values reason) {
// 	fd->prev_state = fd->state;
// 	fd->ua_tid_set = false;
// 	fd->reason = reason;
// }

static pldm_requester_rc_t pldm_fd_qdi(struct pldm_fd *fd,
	const struct pldm_header_info *hdr,
	const struct pldm_msg *req LIBPLDM_CC_UNUSED, size_t req_payload_len,
	struct pldm_msg *resp, size_t *resp_payload_len)
{
	uint8_t ccode;

	/* QDI has no request data */
	if (req_payload_len != PLDM_QUERY_DEVICE_IDENTIFIERS_REQ_BYTES) {
		return pldm_fd_reply_error(PLDM_ERROR_INVALID_LENGTH,
			hdr, resp, resp_payload_len);
	}

	/* Retrieve platform-specific data */
	uint32_t descriptors_len;
	uint8_t descriptor_count;
	const uint8_t* descriptors;
	ccode = fd->ops->device_identifiers(fd->ops_ctx,
		&descriptors_len, &descriptor_count, &descriptors);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
	}

	ccode = encode_query_device_identifiers_resp(hdr->instance,
		descriptors_len, descriptor_count, descriptors,
		resp, resp_payload_len);

	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
	}

	return PLDM_REQUESTER_SUCCESS;
}

static pldm_requester_rc_t pldm_fd_fw_param(struct pldm_fd *fd,
	const struct pldm_header_info *hdr,
	const struct pldm_msg *req LIBPLDM_CC_UNUSED, size_t req_payload_len,
	struct pldm_msg *resp, size_t *resp_payload_len)
{
	uint8_t ccode;

	/* No request data */
	if (req_payload_len != PLDM_GET_FIRMWARE_PARAMETERS_REQ_BYTES) {
		return pldm_fd_reply_error(PLDM_ERROR_INVALID_LENGTH,
			hdr, resp, resp_payload_len);
	}

	/* Retrieve platform-specific data */
	uint16_t entry_count;
	const struct pldm_firmware_component_standalone **entries;
	ccode = fd->ops->components(fd->ops_ctx, &entry_count, &entries);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
	}
	struct pldm_firmware_string active;
	struct pldm_firmware_string pending;
	ccode = fd->ops->imageset_versions(fd->ops_ctx, &active, &pending);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
	}


	struct pldm_msgbuf _buf;
	struct pldm_msgbuf *buf = &_buf;

	ccode = pldm_msgbuf_init_cc(buf, 0, resp->payload, *resp_payload_len);
	if (ccode) {
		return PLDM_REQUESTER_RECV_FAIL;
	}

	/* Add the fixed parameters */
	{
		const struct pldm_get_firmware_parameters_resp fwp = {
			.completion_code = PLDM_SUCCESS,
			// TODO defaulted to 0, could have a callback.
			.capabilities_during_update = {0},
			.comp_count = entry_count,
			.active_comp_image_set_ver_str_type = active.str_type,
			.active_comp_image_set_ver_str_len = active.str_len,
			.pending_comp_image_set_ver_str_type = pending.str_type,
			.pending_comp_image_set_ver_str_len = pending.str_len,
		};

		const struct variable_field active_ver = {
			.ptr = active.str_data,
			.length = active.str_len,
		};
		const struct variable_field pending_ver = {
			.ptr = pending.str_data,
			.length = pending.str_len,
		};
		size_t len = buf->remaining;
		ccode = encode_get_firmware_parameters_resp(hdr->instance,
			&fwp, &active_ver, &pending_ver, resp, &len);
		if (ccode) {
			return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
		}
		ccode = pldm_msgbuf_increment(buf, len);
		if (ccode) {
			return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
		}
	}

	/* Add the component table entries */
	for (uint16_t i = 0; i < entry_count; i++) {
		const struct pldm_firmware_component_standalone *e = entries[i];
		struct pldm_component_parameter_entry comp = {
			.comp_classification = e->comp_classification,
			.comp_identifier = e->comp_identifier,
			.comp_classification_index = e->comp_classification_index,
			.active_comp_comparison_stamp = e->active_ver.stamp,
			.active_comp_ver_str_type = e->active_ver.str.str_type,
			.active_comp_ver_str_len = e->active_ver.str.str_len,
			.pending_comp_comparison_stamp = e->pending_ver.stamp,
			.pending_comp_ver_str_type = e->pending_ver.str.str_type,
			.pending_comp_ver_str_len = e->pending_ver.str.str_len,
			.comp_activation_methods = e->comp_activation_methods,
			.capabilities_during_update = e->capabilities_during_update,
		};
		memcpy(comp.active_comp_release_date, e->active_ver.date,
			PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN);
		memcpy(comp.pending_comp_release_date, e->pending_ver.date,
			PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN);
		const struct variable_field active_ver = {
			.ptr = e->active_ver.str.str_data,
			.length = e->active_ver.str.str_len,
		};
		const struct variable_field pending_ver = {
			.ptr = e->pending_ver.str.str_data,
			.length = e->pending_ver.str.str_len,
		};

		void* out = NULL;
		size_t len;
		if (pldm_msgbuf_peek_remaining(buf, &out, &len)) {
			return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
		}
		ccode = encode_get_firmware_parameters_resp_comp_entry(
			&comp, &active_ver, &pending_ver, out, &len);
		if (ccode) {
			return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
		}
		ccode = pldm_msgbuf_increment(buf, len);
		if (ccode) {
			return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
		}
	}

	*resp_payload_len = *resp_payload_len - buf->remaining;
	return PLDM_REQUESTER_SUCCESS;
}

static pldm_requester_rc_t pldm_fd_request_update(struct pldm_fd *fd,
	const struct pldm_header_info *hdr,
	const struct pldm_msg *req, size_t req_payload_len,
	struct pldm_msg *resp, size_t *resp_payload_len,
	pldm_tid_t tid)
{
	uint8_t ccode;

	if (fd->state != PLDM_FD_STATE_IDLE) {
		return pldm_fd_reply_error(PLDM_FWUP_ALREADY_IN_UPDATE_MODE, hdr, resp, resp_payload_len);
	}

	uint32_t max_transfer_size;
	uint16_t num_of_comp;
	uint8_t max_outstanding_transfer_req;
	uint16_t pkg_data_len;
	uint8_t comp_image_set_ver_str_type;
	struct variable_field comp_img_set_ver_str;

	ccode = decode_request_update_req(req, req_payload_len,
		&max_transfer_size,
		&num_of_comp,
		&max_outstanding_transfer_req,
		&pkg_data_len,
		&comp_image_set_ver_str_type,
		&comp_img_set_ver_str);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
	}

	/* No metadata nor pkg data */
	ccode = encode_request_update_resp(hdr->instance, 0, 0, resp, resp_payload_len);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
	}

	fd->max_transfer = max_transfer_size;
	if (fd->max_transfer < PLDM_FWUP_BASELINE_TRANSFER_SIZE) {
		// Don't let it be zero
		fd->max_transfer = PLDM_FWUP_BASELINE_TRANSFER_SIZE;
	}
	fd->ua_tid = tid;
	fd->ua_tid_set = true;
	// TODO: Update update_timestamp_fd_t1

	pldm_fd_set_state(fd, PLDM_FD_STATE_LEARN_COMPONENTS);

	return PLDM_REQUESTER_SUCCESS;
}

/* Wrapper around ops->update_component() that first checks that the component
 * is in the list returned from ops->components() */
static enum pldm_component_response_codes
pldm_fd_check_update_component(struct pldm_fd *fd, bool update,
    	const struct pldm_firmware_update_component *comp) {

	uint8_t ccode;

	uint16_t entry_count;
	const struct pldm_firmware_component_standalone **entries;
	ccode = fd->ops->components(fd->ops_ctx, &entry_count, &entries);
	if (ccode) {
		return PLDM_CRC_COMP_NOT_SUPPORTED;
	}

	bool found = false;
	for (uint16_t i = 0; i < entry_count; i++) {
		if (entries[i]->comp_classification == comp->comp_classification
			&& entries[i]->comp_identifier == comp->comp_identifier
			&& entries[i]->comp_classification_index == comp->comp_classification_index) {
			found = true;
			break;
		}
	}
	if (found) {
		return fd->ops->update_component(fd->ops_ctx, update, comp);
	} else {
		return PLDM_CRC_COMP_NOT_SUPPORTED;
	}
}


static pldm_requester_rc_t pldm_fd_pass_comp(struct pldm_fd *fd,
	const struct pldm_header_info *hdr,
	const struct pldm_msg *req, size_t req_payload_len,
	struct pldm_msg *resp, size_t *resp_payload_len)
{
	uint8_t ccode;

	if (fd->state != PLDM_FD_STATE_LEARN_COMPONENTS) {
		return pldm_fd_reply_error(PLDM_FWUP_INVALID_STATE_FOR_COMMAND, hdr, resp, resp_payload_len);
	}

	uint8_t transfer_flag;

	/* Some portions are unused for PassComponentTable */
	struct pldm_firmware_update_component comp = {
		.size = 0,
		.flags.value = 0,
	};

	ccode = decode_pass_component_table_req(req, req_payload_len,
		&transfer_flag,
		&comp.comp_classification,
		&comp.comp_identifier,
		&comp.comp_classification_index,
		&comp.comp_comparison_stamp,
		&comp.comp_ver_str_type,
		&comp.comp_ver_str);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
	}

	uint8_t comp_response_code = pldm_fd_check_update_component(fd, false, &comp);

	/* Component Response Code is 0 for ComponentResponse, 1 otherwise */
	uint8_t comp_resp = (comp_response_code != 0);

	ccode = encode_pass_component_table_resp(hdr->instance,
		comp_resp, comp_response_code, resp, resp_payload_len);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp, resp_payload_len);
	}

	if (transfer_flag & PLDM_END) {
		pldm_fd_set_state(fd, PLDM_FD_STATE_READY_XFER);
	}

	return PLDM_SUCCESS;
}

static pldm_requester_rc_t pldm_fd_handle_resp(struct pldm_fd *fd, pldm_tid_t tid,
	const void *msg, size_t msg_len)
{
	// TODO
	return PLDM_REQUESTER_INVALID_SETUP;
}

LIBPLDM_ABI_TESTING
pldm_requester_rc_t pldm_fd_setup(struct pldm_fd *fd,
	size_t pldm_fd_size,
	const struct pldm_fd_ops *ops, void *ops_ctx)
{
	if (pldm_fd_size < sizeof(struct pldm_fd)) {
		/* Safety check that sufficient storage was provided for *fd,
		 * in case PLDM_SIZEOF_PLDM_FD is incorrect */
		return PLDM_REQUESTER_INVALID_SETUP;
	}
	memset(fd, 0x0, sizeof(*fd));
	fd->ops = ops;
	fd->ops_ctx = ops_ctx;

	return PLDM_REQUESTER_SUCCESS;
}

/* A response should only be used when this returns PLDM_SUCCESS, and *resp_len > 0 */
LIBPLDM_ABI_TESTING
pldm_requester_rc_t pldm_fd_handle_msg(struct pldm_fd *fd, pldm_tid_t tid,
	const void *req_msg, size_t req_len,
	void *resp_msg, size_t *resp_len)
{
	uint8_t rc;

	/* Space for header plus completion code */
	if (*resp_len < sizeof(struct pldm_msg_hdr)+1) {
		return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
	}
	size_t resp_payload_len = *resp_len - sizeof(struct pldm_msg_hdr);
	struct pldm_msg *resp = resp_msg;

	if (req_len < sizeof(struct pldm_msg_hdr)) {
		return PLDM_REQUESTER_INVALID_RECV_LEN;
	}
	size_t req_payload_len = req_len - sizeof(struct pldm_msg_hdr);
	const struct pldm_msg *req = req_msg;

	struct pldm_header_info hdr;
	rc = unpack_pldm_header(&req->hdr, &hdr);
	if (rc != PLDM_SUCCESS) {
		return PLDM_REQUESTER_RECV_FAIL;
	}

	if (hdr.pldm_type != PLDM_FWUP) {
		/* Caller should not have passed non-pldmfw */
		return PLDM_REQUESTER_RECV_FAIL;
	}

	if (hdr.msg_type == PLDM_RESPONSE) {
		*resp_len = 0;
		return pldm_fd_handle_resp(fd, tid, req_msg, req_len);
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
			/* Command handler will set TID */
			break;
		default:
			/* Requests must come from the same TID that requested the update */
			if (!fd->ua_tid_set || tid != fd->ua_tid) {
				return pldm_fd_reply_error(PLDM_ERROR_NOT_READY, &hdr, resp, &resp_payload_len);
			}
	}

	/* Dispatch command */
	switch (hdr.command) {
		case PLDM_QUERY_DEVICE_IDENTIFIERS:
			rc = pldm_fd_qdi(fd, &hdr, req, req_payload_len, resp, &resp_payload_len);
			break;
		case PLDM_GET_FIRMWARE_PARAMETERS:
			rc = pldm_fd_fw_param(fd, &hdr, req, req_payload_len, resp, &resp_payload_len);
			break;
		case PLDM_REQUEST_UPDATE:
			rc = pldm_fd_request_update(fd, &hdr, req, req_payload_len, resp, &resp_payload_len,
				tid);
			break;
		case PLDM_PASS_COMPONENT_TABLE:
			rc = pldm_fd_pass_comp(fd, &hdr, req, req_payload_len, resp, &resp_payload_len);
			break;
		default:
			rc = pldm_fd_reply_error(PLDM_ERROR_UNSUPPORTED_PLDM_CMD, &hdr, resp, &resp_payload_len);
	}

	if (rc == PLDM_SUCCESS) {
		*resp_len = resp_payload_len + sizeof(struct pldm_msg_hdr);
	}

	return rc;
}
