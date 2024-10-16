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
	void *resp_msg, size_t *resp_len) {

	int rc;

	/* Header plus 1 byte completion code */
	if (*resp_len < sizeof(struct pldm_msg_hdr) + 1) {
		return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
	}
	*resp_len = sizeof(struct pldm_msg_hdr) + 1;

	rc = encode_cc_only_resp(req_hdr->instance,
		PLDM_FWUP, req_hdr->command, ccode, resp_msg);
	if (rc != PLDM_SUCCESS) {
		return PLDM_REQUESTER_RECV_FAIL;
	}
	return PLDM_REQUESTER_SUCCESS;
}

static pldm_requester_rc_t pldm_fd_qdi(struct pldm_fd *fd,
	const struct pldm_header_info *hdr,
	const void *req LIBPLDM_CC_UNUSED, size_t req_len,
	void *resp_msg, size_t *resp_len)
{
	uint8_t ccode;

	/* QDI has no request data */
	if (req_len != PLDM_QUERY_DEVICE_IDENTIFIERS_REQ_BYTES) {
		return pldm_fd_reply_error(PLDM_ERROR_INVALID_LENGTH,
			hdr, resp_msg, resp_len);
	}

	/* Retrieve platform-specific data */
	uint32_t descriptors_len;
	uint8_t descriptor_count;
	const uint8_t* descriptors;
	ccode = fd->ops->device_identifiers(fd->ops_ctx,
		&descriptors_len, &descriptor_count, &descriptors);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp_msg, resp_len);
	}

	if (*resp_len < sizeof(struct pldm_msg_hdr)) {
		return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
	}
	size_t payload_len = *resp_len - sizeof(struct pldm_msg_hdr);

	struct pldm_msg *r = resp_msg;
	ccode = encode_query_device_identifiers_resp(hdr->instance,
		descriptors_len, descriptor_count, descriptors,
		r, &payload_len);

	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp_msg, resp_len);
	}

	*resp_len = sizeof(struct pldm_msg_hdr) + payload_len;
	return PLDM_REQUESTER_SUCCESS;
}

static pldm_requester_rc_t pldm_fd_fw_param(struct pldm_fd *fd,
	const struct pldm_header_info *hdr,
	const void *req LIBPLDM_CC_UNUSED, size_t req_len,
	void *resp_msg, size_t *resp_len)
{
	uint8_t ccode;

	/* No request data */
	if (req_len != PLDM_GET_FIRMWARE_PARAMETERS_REQ_BYTES) {
		return pldm_fd_reply_error(PLDM_ERROR_INVALID_LENGTH,
			hdr, resp_msg, resp_len);
	}

	/* Retrieve platform-specific data */
	uint16_t entry_count;
	const struct pldm_firmware_component_standalone **entries;
	ccode = fd->ops->components(fd->ops_ctx, &entry_count, &entries);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp_msg, resp_len);
	}
	struct pldm_firmware_string active;
	struct pldm_firmware_string pending;
	ccode = fd->ops->imageset_versions(fd->ops_ctx, &active, &pending);
	if (ccode) {
		return pldm_fd_reply_error(ccode, hdr, resp_msg, resp_len);
	}


	if (*resp_len < sizeof(struct pldm_msg_hdr)) {
		return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
	}

	struct pldm_msgbuf _buf;
	struct pldm_msgbuf *buf = &_buf;

	struct pldm_msg *r = resp_msg;
	ccode = pldm_msgbuf_init_cc(buf, 0, r->payload, *resp_len - sizeof(struct pldm_msg_hdr));
	if (ccode) {
		return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
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
		size_t payload_len = buf->remaining;
		ccode = encode_get_firmware_parameters_resp(hdr->instance,
			&fwp, &active_ver, &pending_ver, r, &payload_len);
		if (ccode) {
			return pldm_fd_reply_error(ccode, hdr, resp_msg, resp_len);
		}
		ccode = pldm_msgbuf_increment(buf, payload_len);
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
		size_t payload_len;
		if (pldm_msgbuf_peek_remaining(buf, &out, &payload_len)) {
			return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
		}
		ccode = encode_get_firmware_parameters_resp_comp_entry(
			&comp, &active_ver, &pending_ver, out, &payload_len);
		if (ccode) {
			return pldm_fd_reply_error(ccode, hdr, resp_msg, resp_len);
		}
		ccode = pldm_msgbuf_increment(buf, payload_len);
		if (ccode) {
			return PLDM_REQUESTER_RESP_MSG_TOO_SMALL;
		}
	}

	*resp_len = *resp_len - buf->remaining;
	return PLDM_REQUESTER_SUCCESS;
}

static pldm_requester_rc_t pldm_fd_handle_resp(struct pldm_fd *fd, pldm_tid_t tid,
	const void *pldm_msg, size_t msg_len,
	void *resp_msg, size_t *resp_len)
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

LIBPLDM_ABI_TESTING
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
		case PLDM_GET_FIRMWARE_PARAMETERS:
			rc = pldm_fd_fw_param(fd, &hdr, payload, payload_len, resp_msg, resp_len);
			break;
		default:
			// rc = pldm_fd_reply_error(PLDM_ERROR_UNSUPPORTED_PLDM_CMD, &hdr, resp_msg, resp_len);
			rc = PLDM_SUCCESS;
	}

	return rc;
}
