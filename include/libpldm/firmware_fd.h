#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <libpldm/pldm.h>
#include <libpldm/base.h>
#include <libpldm/firmware_update.h>

struct pldm_firmware_component_standalone {
	uint16_t comp_classification;
	uint16_t comp_identifier;
	uint8_t comp_classification_index;

	struct pldm_firmware_version active_ver;
	struct pldm_firmware_version pending_ver;

	bitfield16_t comp_activation_methods;
	bitfield32_t capabilities_during_update;
};

/* Device-specific callbacks provided by an application.
 * All return a ccode. */
struct pldm_fd_ops {
	uint8_t (*device_identifiers)(void* ctx,
		uint32_t *ret_descriptors_len, uint8_t *ret_descriptors_count,
		const uint8_t **ret_descriptors);

	uint8_t (*components)(void* ctx,
		uint16_t *ret_entry_count,
		const struct pldm_firmware_component_standalone ***ret_entries);

	uint8_t (*imageset_versions)(void* ctx,
		struct pldm_firmware_string *active,
		struct pldm_firmware_string *pending);
};

/* Static storage can be allocated with
 * PLDM_SIZEOF_PLDM_FD macro */
struct pldm_fd;

pldm_requester_rc_t pldm_fd_setup(struct pldm_fd *fd,
    size_t pldm_fd_size,
	const struct pldm_fd_ops *ops, void *ops_ctx);

pldm_requester_rc_t pldm_fd_handle_msg(struct pldm_fd *fd, pldm_tid_t tid,
	const void *pldm_msg, size_t msg_len,
	void *resp_msg, size_t *resp_len);
