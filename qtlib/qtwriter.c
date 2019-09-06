/*
 * Qtrace writer library
 *
 * Copyright (C) 2017 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "qtrace_record.h"
#include "qtrace.h"
#include "qtwriter.h"
#include "endian-helpers.h"

static int fallocate_or_ftruncate(int fd, size_t size)
{
	if (fallocate(fd, 0, 0, size) == 0)
		return 0;

	if (errno != EOPNOTSUPP)
		return -1;

	if (ftruncate(fd, size) == -1)
		return -1;

	return 0;
}

#define QTWRITER_VERSION 0x7010000

/*
 * This needs to be bigger than the maximum qtrace record size. We also
 * want it to be large enough that we don't continually extend the file
 * with fallocate/mremap.
 */
#define BUFFER	(128*1024)
static unsigned int get_radix_insn_ptes(uint16_t flags3)
{
	unsigned int host_mode;

	host_mode = (flags3 >> QTRACE_HOST_XLATE_MODE_INSTRUCTION_SHIFT) &
			QTRACE_XLATE_MODE_MASK;

	if (host_mode == QTRACE_XLATE_MODE_RADIX) {
		return NR_RADIX_PTES;
	}
	return 0;
}

bool qtwriter_open(struct qtwriter_state *state, char *filename,
		   uint32_t magic)
{
	void *p;

	memset(state, 0, sizeof(*state));

	state->magic = magic;
	state->version = QTWRITER_VERSION;

	state->fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (state->fd == -1) {
		perror("open");
		return false;
	}

	state->size = BUFFER;

	if (fallocate_or_ftruncate(state->fd, state->size) == -1) {
		perror("fallocate/ftruncate");
		return false;
	}

	p = mmap(NULL, state->size, PROT_READ|PROT_WRITE, MAP_SHARED,
		 state->fd, 0);

	if (p == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	state->mem = p;
	state->ptr = state->mem;

	return true;
}

static inline void put8(struct qtwriter_state *state, uint8_t val)
{
	typeof(val) *p = state->ptr;
	*p = val;
	state->ptr += sizeof(*p);
}

static inline void put16(struct qtwriter_state *state, uint16_t val)
{
	typeof(val) *p = state->ptr;
	*p = cpu_to_be16(val);
	state->ptr += sizeof(*p);
}

static inline void put32(struct qtwriter_state *state, uint32_t val)
{
	typeof(val) *p = state->ptr;
	*p = cpu_to_be32(val);
	state->ptr += sizeof(*p);
}

static inline void put64(struct qtwriter_state *state, uint64_t val)
{
	typeof(val) *p = state->ptr;
	*p = cpu_to_be64(val);
	state->ptr += sizeof(*p);
}

static inline void skip(struct qtwriter_state *state, uint64_t val)
{
	if (state->ptr + val <= (state->mem + state->size))
		state->ptr += val;
}

static bool parse_radix(struct qtwriter_state *state, unsigned int nr, uint64_t *ptes)
{
	unsigned long i;
	for (i = 0; i < nr; i++) {
		if (ptes) {
			put64(state, ptes[i]);
		}
		else {
			put64(state, 0);
		}
	}

	return true;
}

/*
 * The header contains the address of the first instruction, so we can't
 * write it until we get the first trace entry.
 */
static bool qtwriter_write_header(struct qtwriter_state *state,
				  struct qtrace_record *record)
{
	uint16_t flags = 0, flags2 = 0, flags3 = 0, hdr_flags = 0;
	/* Header is identified by a zero instruction */
	put32(state, 0);

	flags = QTRACE_EXTENDED_FLAGS_PRESENT;
	put16(state, flags);

	flags2 = QTRACE_FILE_HEADER_PRESENT;
	if (state->flags3) {
		flags3 = state->flags3;
		flags2 |= QTRACE_EXTENDED_FLAGS2_PRESENT;
	}
	put16(state, flags2);

	if (state->ptcr_present)
		flags3 |= QTRACE_PTCR_PRESENT;

	if (state->lpid_present)
		flags3 |= QTRACE_LPID_PRESENT;

	if (state->pid_present)
		flags3 |= QTRACE_PID_PRESENT;

	if (flags3)
		put16(state, state->flags3);

	hdr_flags = QTRACE_HDR_IAR_PRESENT;
	if (record->insn_ra_valid)
		hdr_flags |= QTRACE_HDR_IAR_RPN_PRESENT;

	if (record->insn_page_shift_valid)
		hdr_flags |= QTRACE_HDR_IAR_PAGE_SIZE_PRESENT;

	if (state->version)
		hdr_flags |= QTRACE_HDR_VERSION_NUMBER_PRESENT;

	if (state->magic)
		hdr_flags |= QTRACE_HDR_MAGIC_NUMBER_PRESENT;

	if (state->header_comment)
		hdr_flags |= QTRACE_HDR_COMMENT_PRESENT;

	if (state->next_insn_rpn_valid)
		hdr_flags |= QTRACE_HDR_IAR_RPN_PRESENT;

	put16(state, hdr_flags);

	if (state->magic)
		put32(state, state->magic);

	if (state->version)
		put32(state, state->version);

	put64(state, record->insn_addr);

	if (state->vsid_present) {
		hdr_flags |= QTRACE_HDR_IAR_VSID_PRESENT;
		skip(state, 7);
	}

	if ((hdr_flags & QTRACE_HDR_IAR_RPN_PRESENT) && IS_RADIX(flags2)) {
		unsigned int nr = get_radix_insn_ptes(flags3);
		if (parse_radix(state, nr, NULL) == false)
			return false;
	}

	if (state->next_insn_rpn_valid)
		put32(state, state->next_insn_rpn);

	if (state->next_insn_page_shift_valid)
		put8(state, state->next_insn_page_shift);

	if (hdr_flags & QTRACE_HDR_IAR_GPAGE_SIZE_PRESENT)
		skip(state, 1);

	if (flags3 & QTRACE_PTCR_PRESENT)
		put64(state, state->ptcr);

	if (flags3 & QTRACE_LPID_PRESENT)
		put64(state, state->lpid);

	if (flags3 & QTRACE_PID_PRESENT)
		put32(state, state->pid);

	/*
	 * We should either write the header comment or just write the comment
	 * length as zero. This is to make the byte comparision of a trace parsed
	 * by qtreader and qtwriter with the original easier.
	 */
	if (state->header_comment) {
		uint16_t len = state->header_comment;
		put16(state, len);
		if (state->ptr + len > (state->mem + state->size))
			goto err;

		state->ptr += len;
	}

	return true;

err:
	return false;
}

static void write_reg(struct qtwriter_state *state, struct qtrace_reg_info *reg, int nr_regs, int reg_type)
{
	int i;

	switch (reg_type) {
	case GPR:
	case FPR:
		for (i = 0; i < nr_regs; i++) {
			put8(state, reg[i].index);
			put64(state, reg[i].value);
		}
		break;
	case VMX:
	case VSX:
		for (i = 0; i < nr_regs; i++) {
			put16(state, reg[i].index);
			put64(state, reg[i].value);
			put64(state, reg[i].value2);
		}
		break;
	case SPR:
		for (i = 0; i < nr_regs; i++) {
			put16(state, reg[i].index);
			put64(state, reg[i].value);
		}
		break;
	}
}

static bool write_regs(struct qtwriter_state *state, struct qtrace_reg_state *regs, bool tlbie)
{
	put8(state, regs->nr_gprs_in);
	put8(state, regs->nr_fprs_in);
	put8(state, regs->nr_vmxs_in);
	if (state->version >= 0x7000000)
		put8(state, regs->nr_vsxs_in);
	put8(state, regs->nr_sprs_in);

	put8(state, regs->nr_gprs_out);
	put8(state, regs->nr_fprs_out);
	put8(state, regs->nr_vmxs_out);
	if (state->version >= 0x7000000)
		put8(state, regs->nr_vsxs_out);
	put8(state, regs->nr_sprs_out);

	write_reg(state, regs->gprs_in, regs->nr_gprs_in, GPR);
	write_reg(state, regs->fprs_in, regs->nr_fprs_in, FPR);
	write_reg(state, regs->vmxs_in, regs->nr_vmxs_in, VMX);
	write_reg(state, regs->vsxs_in, regs->nr_vsxs_in, VSX);
	write_reg(state, regs->sprs_in, regs->nr_sprs_in, SPR);

	write_reg(state, regs->gprs_out, regs->nr_gprs_out, GPR);
	write_reg(state, regs->fprs_out, regs->nr_fprs_out, FPR);
	write_reg(state, regs->vmxs_out, regs->nr_vmxs_out, VMX);
	write_reg(state, regs->vsxs_out, regs->nr_vsxs_out, VSX);
	write_reg(state, regs->sprs_out, regs->nr_sprs_out, SPR);

	if (state->ptr > (state->mem + state->size))
		return true;
	else
		return false;
}


bool qtwriter_write_record(struct qtwriter_state *state,
			   struct qtrace_record *record)
{
	uint16_t flags;
	uint16_t flags2;
	uint16_t flags3;
	bool iar_change = false;
	bool is_branch = false;

   /*
	* We sometimes see two file headers at the start of a mambo trace, or
	* a header in the middle of a trace. These are identified by a null
	* instruction and we skip over them.
	*/
	if (!record->insn_addr) {
		qtwriter_write_header(state, record);
	}

	/* Do we need to allocate more space? */
	if ((state->ptr + BUFFER) > (state->mem + state->size)) {
		void *p;
		size_t offset;

		if (fallocate_or_ftruncate(state->fd, state->size + BUFFER) == -1) {
			perror("fallocate/ftruncate");
			return false;
		}

		p = mremap(state->mem, state->size, state->size + BUFFER,
			   MREMAP_MAYMOVE);
		if (p == MAP_FAILED) {
			perror("mmap");
			return false;
		}

		state->size += BUFFER;
		offset = state->ptr - state->mem;

		state->mem = p;

		/* adjust ->ptr, mremap may have returned a new address */
		state->ptr = state->mem + offset;
	} 

	if (state->header_written == false) {
		qtwriter_write_header(state, record);
		state->header_written = true;

		memcpy(&state->prev_record, record, sizeof(*record));

		return true;
	}

	flags = 0;
	flags2 = 0;
	flags3 = state->prev_record.flags3;

	/* Some sort of branch */
	if (state->prev_record.branch == true ||
	    record->insn_addr != (state->prev_record.insn_addr + 4))
		is_branch = true;

	if ((record->insn_addr != (state->prev_record.insn_addr + 4)))
		iar_change = true;

	/* Setup flags */
	if (state->prev_record.data_addr_valid)
		flags |= QTRACE_DATA_ADDRESS_PRESENT;

	if (state->prev_record.data_ra_valid)
		flags |= QTRACE_DATA_RPN_PRESENT;

	if (record->insn_ra_valid && iar_change)
		flags |= QTRACE_IAR_RPN_PRESENT;

	if (state->prev_record.data_ra_valid)
		flags |= QTRACE_DATA_RPN_PRESENT;

	if (is_branch) {
		flags |= QTRACE_NODE_PRESENT | QTRACE_TERMINATION_PRESENT;

		if (iar_change)
			flags |= (QTRACE_IAR_CHANGE_PRESENT | QTRACE_IAR_PRESENT);
	}

	if (state->prev_record.regs_valid)
		flags |= QTRACE_REGISTER_TRACE_PRESENT;

	if (state->prev_record.processor_valid)
		flags |= QTRACE_PROCESSOR_PRESENT;

	/* Setup flags2 */
	if (state->prev_record.nr_radix_data_valid || 
		state->prev_record.nr_radix_insn_valid ||
		flags3)
		flags2 |= QTRACE_EXTENDED_FLAGS2_PRESENT;

	if (record->insn_page_shift_valid && iar_change)
		flags2 |= QTRACE_IAR_PAGE_SIZE_PRESENT;

	if (state->prev_record.data_page_shift_valid)
		flags2 |= QTRACE_DATA_PAGE_SIZE_PRESENT;

	if (state->prev_record.err_present)
		flags2 |= QTRACE_TRACE_ERROR_CODE_PRESENT;

	if (state->prev_record.insn_rpn_valid)
		flags2 |= QTRACE_SEQUENTIAL_INSTRUCTION_RPN_PRESENT;

	if (flags2)
		flags |= QTRACE_EXTENDED_FLAGS_PRESENT;

	put32(state, state->prev_record.insn);

	put16(state, flags);

	if (flags & QTRACE_EXTENDED_FLAGS_PRESENT)
		put16(state, flags2);

	if (flags2 & QTRACE_EXTENDED_FLAGS2_PRESENT)
		put16(state, flags3);



	if (flags & QTRACE_NODE_PRESENT)
		put8(state, 0);

	/* Termination present */
	if (flags & QTRACE_TERMINATION_PRESENT) {
		uint8_t termination_code = 0;

		/* termination node */
		put8(state, 0);

		/* termination code */
		if (state->prev_record.branch) {
			if (state->prev_record.conditional_branch == true)
				if (state->prev_record.max_inst_depth == true)
					termination_code = QTRACE_EXCEEDED_MAX_INST_DEPTH;
				else
					termination_code = QTRACE_EXCEEDED_MAX_BRANCH_DEPTH;
			else
				termination_code = QTRACE_UNCONDITIONAL_BRANCH;
		}

		put8(state, termination_code);
	}

	/* Processor present */
	if (flags & QTRACE_PROCESSOR_PRESENT)
		put8(state, record->processor);

	if (flags & QTRACE_DATA_ADDRESS_PRESENT)
		put64(state, state->prev_record.data_addr);

	/* RADIX 1 */
	if ((flags & QTRACE_DATA_RPN_PRESENT) && IS_RADIX(flags2)) {
		unsigned int nr = state->prev_record.nr_radix_data_ptes;
		if (parse_radix(state, nr, state->prev_record.radix_data_ptes) == false)
			goto err;
	}

	if (flags & QTRACE_DATA_RPN_PRESENT) {
		uint8_t pshift = 16;
		if (state->prev_record.data_page_shift_valid)
			pshift = state->prev_record.data_page_shift;

		put32(state, state->prev_record.data_ra >> pshift);
	}

	if (iar_change)
		put64(state, record->insn_addr);


	/* RADIX 2 */
	if ((flags & QTRACE_IAR_RPN_PRESENT) && IS_RADIX(flags2)) {

		unsigned int nr_ptes = state->prev_record.nr_radix_insn_ptes;
		if (parse_radix(state, nr_ptes, state->prev_record.radix_insn_ptes) == false)
			goto err;
	}

	if (record->insn_ra_valid && iar_change) {
		uint8_t pshift = 16;

		if (record->insn_page_shift_valid)
			pshift = record->insn_page_shift;

		put32(state, record->insn_ra >> pshift);
	}

	/* Registers present */
	if (flags & QTRACE_REGISTER_TRACE_PRESENT)
		write_regs(state, &state->prev_record.regs, state->prev_record.tlbie);

	/* Sequential insn rpn */
	if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_RPN_PRESENT)
		put32(state, state->prev_record.insn_rpn);

	if (flags2 & QTRACE_TRACE_ERROR_CODE_PRESENT)
		put8(state, state->prev_record.err);

	/* Sequential insn page size */
	if (flags2 & QTRACE_SEQUENTIAL_INSTRUCTION_PAGE_SIZE_PRESENT) {
		put8(state, state->next_insn_page_shift);
	}

	if (record->insn_page_shift_valid && iar_change)
		put8(state, record->insn_page_shift);

	if (flags2 & QTRACE_DATA_PAGE_SIZE_PRESENT)
		put8(state, state->prev_record.data_page_shift);

	memcpy(&state->prev_record, record, sizeof(*record));

	return true;
err:
	return false;
}

#if 0
void qtwriter_write_record_simple(struct qtwriter_state *state, uint32_t insn,
				  unsigned long insn_addr)
{
	struct qtrace_record record;

	memset(&record, 0, sizeof(record));

	record.insn = insn;
	record.insn_addr = insn_addr;

	/* what about branches? */

	qtwriter_write_record(state, &record);
}

void qtwriter_write_storage_record_simple(struct qtwriter_state *state,
					  uint32_t insn, unsigned long insn_addr,
					  unsigned long storage_addr,
					  unsigned long storage_size)
{
	struct qtrace_record record;

	memset(&record, 0, sizeof(record));

	record.insn = insn;
	record.insn_addr = insn_addr;

	record.data_addr_valid = true;
	record.data_addr = storage_addr;

	/* what about branches? */

	qtwriter_write_record(state, &record);
}
#endif

void qtwriter_close(struct qtwriter_state *state)
{
	struct qtrace_record record;

	/* Flush the final instruction */
	memset(&record, 0, sizeof(record));
	record.insn_addr = state->prev_record.insn_addr + 4;
	qtwriter_write_record(state, &record);

	munmap(state->mem, state->size);

	/* truncate file to actual size */
	if (ftruncate(state->fd, state->ptr - state->mem)) {
		fprintf(stderr, "ftruncate\n");
	}

	close(state->fd);
}
