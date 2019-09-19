#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "qtreader.h"
#include "qtwriter.h"

/*
 * The resulting qtrace won't be quite one-to-one with the original, but should
 * mostly be the same. Repeated headers are ignored, a few bits of information
 * in the header are ignored, and we add in missing termination nodes for
 * conditional branches that weren't taken.
 */

static unsigned int verbose = 0;

void static print_record(struct qtrace_record *record)
{
	if (verbose) {
		fprintf(stdout, "0x%lx \t 0x%x", record->insn_addr, record->insn);
		fprintf(stdout, "\n");
	}
}

static void usage(void)
{
	fprintf(stderr, "Usage: test6 [OPTION] [INPUT QTRACE] [OUTPUT QTRACE]\n");
	fprintf(stderr, "\t-v\t\t\tprint verbose info\n");
}

int main(int argc, char *argv[])
{
	int fd;
	struct qtreader_state qtreader_state;
	struct qtwriter_state qtwriter_state;
	struct qtrace_record record;

	while (1) {
		signed char c = getopt(argc, argv, "e:d:rvbsci");
		if (c < 0)
			break;

		switch (c) {
		case 'v':
			verbose++;
			break;

		default:
			usage();
			exit(1);
		}
	}
	if ((argc - optind) != 2) {
		usage();
		exit(1);
	}

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	if (qtreader_initialize_fd(&qtreader_state, fd, 0) == false) {
		fprintf(stderr, "qtreader_initialize_fd failed\n");
		exit(1);
	}

	optind++;
	if (qtwriter_open(&qtwriter_state, argv[optind], 0) == false) {
		fprintf(stderr, "qtwriter_open failed\n");
		exit(1);
	}

	if (qtreader_state.vsid_present)
        qtwriter_state.vsid_present = true;

	if (qtreader_state.flags3)
	        qtwriter_state.flags3 = qtreader_state.flags3;

	if (qtreader_state.header_comment)
	        qtwriter_state.header_comment = qtreader_state.header_comment;

	/* This is a bit gross, but requires a bit massaging to make this nicer */
	qtwriter_state.magic = qtreader_state.magic;
	qtwriter_state.version = qtreader_state.version;
	qtwriter_state.vsid_present = qtreader_state.vsid_present;
	qtwriter_state.next_insn_rpn_valid = qtreader_state.next_insn_rpn_valid;
	qtwriter_state.next_insn_rpn = qtreader_state.next_insn_rpn;
	qtwriter_state.next_insn_page_shift_valid = qtreader_state.next_insn_page_shift_valid;
	qtwriter_state.next_insn_page_shift = qtreader_state.next_insn_page_shift;
	qtwriter_state.ptcr_present = qtreader_state.ptcr_present;
	qtwriter_state.ptcr = qtreader_state.ptcr;
	qtwriter_state.lpid = qtreader_state.lpid;
	qtwriter_state.pid = qtreader_state.pid;

	while (qtreader_next_record(&qtreader_state, &record) == true) {
		if (qtwriter_write_record(&qtwriter_state, &record) == false) {
			fprintf(stderr, "qtwriter_write_record failed\n");
			exit(1);
		}
		print_record(&record);
	}

	qtwriter_close(&qtwriter_state);

	return 0;
}
