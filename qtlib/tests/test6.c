#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "qtreader.h"
#include "qtwriter.h"

static unsigned int verbose = 0;

void static print_record(struct qtrace_record *record)
{
	if (verbose) {
		fprintf(stdout, "0x%lx \t 0x%x", record->insn_addr, record->insn);
		fprintf(stdout, "\n");
	}
}

void static adjust_record(struct qtwriter_state *qt, struct qtrace_record *record)
{
	struct qtrace_record rec;
	uint64_t ea = record->insn_addr;

	// add magic Debapriya stuff here
	if ((record->insn & 0xfc000003) == 0x48000001) { // bl
		memset(&rec, 0, sizeof(struct qtrace_record));
		rec.insn = 0xf9610000;     // std     r11,0(r1)
		rec.insn_addr = ea - 8; //???
		// Other rec.???
		qtwriter_write_record(qt, &rec);
		print_record(&rec);

		memset(&rec, 0, sizeof(struct qtrace_record));
		rec.insn = 0x7d0741d2; //     mulld   r8,r7,r8
		rec.insn_addr = ea - 4; //???
		// Other rec.???
		qtwriter_write_record(qt, &rec);
		print_record(&rec);
	}
	// add more magic Debapriya stuff here
	if ((record->insn & 0xffc007fe) == 0x4e800020) { // blr
		memset(&rec, 0, sizeof(struct qtrace_record));
		rec.insn = 0xe8010010; // ld      r0,16(r1)
		rec.insn_addr = ea - 12; //???
		// Other rec.???
		qtwriter_write_record(qt, &rec);
		print_record(&rec);

		memset(&rec, 0, sizeof(struct qtrace_record));
		rec.insn = 0x7d0741d2; //     mulld   r8,r7,r8
		rec.insn_addr = ea - 8; //???
		// Other rec.???
		qtwriter_write_record(qt, &rec);
		print_record(&rec);

		memset(&rec, 0, sizeof(struct qtrace_record));
		rec.insn = 0x7fe00008; // 	trap
		rec.insn_addr = ea - 4; //???
		// Other rec.???
		qtwriter_write_record(qt, &rec);
		print_record(&rec);
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
	struct qtrace_record record;
	struct qtwriter_state qtwriter_state;

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
		adjust_record(&qtwriter_state, &record);

		if (qtwriter_write_record(&qtwriter_state, &record) == false) {
			fprintf(stderr, "qtwriter_write_record failed\n");
			exit(1);
		}
		print_record(&record);

	}
	qtwriter_close(&qtwriter_state);
	return 0;
}
