#ifndef __QTWRITER_H__
#define __QTWRITER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "qtrace_record.h"

struct qtwriter_state {
	uint32_t version;
	uint32_t magic;
	struct qtrace_record prev_record;
	bool header_written;
	uint64_t next_insn_addr;
	uint32_t next_insn_rpn;
	bool next_insn_rpn_valid;
	uint32_t next_insn_page_shift;
	bool next_insn_page_shift_valid;
	void *mem;
	void *ptr;
	size_t size;
	int fd;
	uint16_t header_comment;

	uint16_t flags3;

	bool vsid_present;
	bool ptcr_present;
	uint32_t ptcr;
	bool lpid_present;
	uint32_t lpid;
	bool pid_present;
	uint32_t pid;
};

bool qtwriter_open(struct qtwriter_state *state, char *filename,
		   uint32_t magic);
bool qtwriter_write_record(struct qtwriter_state *state,
			   struct qtrace_record *record);
void qtwriter_close(struct qtwriter_state *state);

#ifdef __cplusplus
}
#endif

#endif
