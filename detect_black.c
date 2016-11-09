#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <libavcodec/avcodec.h>
#include "mp4.h"

AVCodec *h264;

static int mp4_stsc_ptr_init(mp4_stsc_ptr_t *ptr, mp4_atom_stsc_t *atom, uint32_t chunk_count)
{
	uint32_t entry_cnt = be32toh(atom->sample_cnt);
	if (be32toh(atom->hdr.size) != sizeof(mp4_atom_stsc_t) + sizeof(mp4_stsc_entry_t) * entry_cnt) {
		fprintf(stderr, "mp4_stsc_ptr_init: stsc atom size doesn't match entry count\n");
		return -1;
	}
	if (entry_cnt == 0) {
		fprintf(stderr, "mp4_stsc_ptr_init: stsc table is empty!\n");
		return -1;
	}
	ptr->chunk_count = chunk_count;
	ptr->chunk_no = be32toh(atom->tbl[0].first_chunk);
	ptr->samp_cnt = be32toh(atom->tbl[0].sample_cnt);
	ptr->samp_left = be32toh(atom->tbl[0].sample_cnt);
	ptr->entry = atom->tbl + 1;
	ptr->end = atom->tbl + entry_cnt;
	if (entry_cnt == 1)
		ptr->next = ptr->chunk_count;
	else
		ptr->next = be32toh(atom->tbl[1].first_chunk);
	return 0;
}
static int mp4_stsc_ptr_advance_entry2(mp4_stsc_ptr_t *ptr) {
	if (ptr->entry >= ptr->end) {
		ptr->samp_left = 1;
		return -1;
	}
	ptr->samp_cnt = be32toh(ptr->entry++->sample_cnt);
	if (ptr->entry == ptr->end)
		ptr->next = ptr->chunk_count + 1;
	else
		ptr->next = be32toh(ptr->entry->first_chunk);
	ptr->samp_left = ptr->samp_cnt;
	return 0;
}
static int mp4_stsc_ptr_advance_entry(mp4_stsc_ptr_t *ptr) {
	if (++ptr->chunk_no >= ptr->next)
		return mp4_stsc_ptr_advance_entry2(ptr);
	ptr->samp_left = ptr->samp_cnt;
	return 0;
}
static int mp4_stsc_ptr_advance(mp4_stsc_ptr_t *ptr) {
	if (--ptr->samp_left)
		return 0;
	if (mp4_stsc_ptr_advance_entry(ptr)) {
		return -1;
	}
	return 0;
}
static int mp4_stsc_ptr_advance_n(mp4_stsc_ptr_t *ptr, uint32_t n) {
	while (n >= ptr->samp_left) {
		n -= ptr->samp_left;
		if (mp4_stsc_ptr_advance_entry(ptr) != 0)
			return -1;
	}
	ptr->samp_left -= n;
	return 0;
}

mp4_atom_stsd_t *stsd = NULL;
mp4_atom_stsc_t *stsc = NULL;
mp4_atom_stco_t *stco = NULL;
mp4_atom_stss_t *stss = NULL;
mp4_atom_stsz_t *stsz = NULL;
char co64 = 0;

int parse_atoms(uint8_t *ptr, uint8_t *end) {
	uint64_t size;
	while (ptr < end) {
		size = be32toh(*(uint32_t*)ptr);
		if (size == 1)
			size = be64toh(*(uint64_t*)(ptr + 8));
		if (size < 8) return -1;
		//fprintf(stderr, "%li %c%c%c%c\n", size, ptr[4],ptr[5],ptr[6],ptr[7]);
		if (ptr + size > end) return -1;
		switch (*(uint32_t*)(ptr + 4)) {
			case ATOM('m', 'o', 'o', 'v'):
			case ATOM('t', 'r', 'a', 'k'):
			case ATOM('m', 'd', 'i', 'a'):
			case ATOM('m', 'i', 'n', 'f'):
			case ATOM('s', 't', 'b', 'l'):
				parse_atoms(ptr + 8, ptr + size); break;
			case ATOM('m', 'p', '4', 'a'):
				parse_atoms(ptr + 36, ptr + size); break;
			case ATOM('h', 'd', 'l', 'r'):
				if (((mp4_atom_hdlr_t*)ptr)->subtype != ATOM('v','i','d','e'))
					return 0;
				break;
			case ATOM('s', 't', 's', 'd'):
				stsd = (mp4_atom_stsd_t*)ptr;
				if (stsd->entry.hdr.type != ATOM('a','v','c','1') &&
						stsd->entry.hdr.type != ATOM('h','2','6','4') &&
						stsd->entry.hdr.type != ATOM('H','2','6','4')) {
					stsd = NULL;
					return -1;
				}
				break;
			case ATOM('s', 't', 's', 'c'):
				stsc = (mp4_atom_stsc_t*)ptr;
				break;
			case ATOM('c', 'o', '6', '4'):
				co64 = 1;
			case ATOM('s', 't', 'c', 'o'):
				stco = (mp4_atom_stco_t*)ptr;
				break;
			case ATOM('s', 't', 's', 's'):
				stss = (mp4_atom_stss_t*)ptr;
				break;
			case ATOM('s', 't', 's', 'z'):
				stsz = (mp4_atom_stsz_t*)ptr;
				break;
		}
		ptr += size;
	}
	return 0;
}
int black_tresh = 32;
int frag_tresh = 20;
int process_file(char *filename)
{
	struct stat st;
	uint8_t *map, *pixptr;
	uint32_t *ptr, *end;
	uint32_t fnum = 1;
	int fd, i, len, mx;
	int x,y;
	int got_frame;
	AVFrame frame;
	AVPacket pkt;
	AVCodecContext avctx;
	mp4_stsc_ptr_t sp;
	uint64_t co;
	fd = open(filename, O_RDONLY);
	fstat(fd, &st);

	map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		return -1;
	}
	parse_atoms(map, map + st.st_size);
	if (!stsd || !stsc || !stco || !stss || !stsz) {
		fprintf(stderr, "Invalid mp4\n");
		return -1;
	}
	av_init_packet(&pkt);
	memset(&frame, 0, sizeof(frame));
	av_frame_unref(&frame);
	avcodec_get_context_defaults3(&avctx, h264);
	avctx.extradata = &stsd->entry.avc1.avcC.version;
	avctx.extradata_size = be32toh(stsd->entry.avc1.avcC.hdr.size) - 8;
	avcodec_open2(&avctx, h264, NULL);
	mp4_stsc_ptr_init(&sp, stsc, be32toh(stco->chunk_cnt));
	ptr = stss->tbl;
	end = ptr + be32toh(stss->entries);
	for (;ptr < end; ptr++) {
		if (mp4_stsc_ptr_advance_n(&sp, be32toh(*ptr) - fnum) != 0) {
			fprintf(stderr, "stsc advance failed!\n");
			break;
		}
		fnum = be32toh(*ptr);
		pkt.data = map + (co64 ? be64toh(stco->u.tbl64[sp.chunk_no - 1]) : be32toh(stco->u.tbl[sp.chunk_no - 1]));
		if (fnum > be32toh(stsz->sample_cnt)){
			fprintf(stderr, "frame %u is out of range!\n", fnum);
			break;
		}
		for (i = fnum - 1 - (be32toh(sp.entry[-1].sample_cnt) - sp.samp_left); i < (fnum - 1); i++)
			pkt.data += be32toh(stsz->tbl[i]);
		pkt.size = be32toh(stsz->tbl[i]);
		while (pkt.size > 0) {
			len = avcodec_decode_video2(&avctx, &frame, &got_frame, &pkt);
			if (len < 0) {
				fprintf(stderr, "Decode frame %i failed\n", i);
				goto ex;
			}
			if (got_frame) {
				if (!frame.data[0])
					break;
				i = 0;
				mx = (int64_t)frame.width * frame.height / frag_tresh;
				for (y = 0; y < frame.height; y++) {
					pixptr = frame.data[0] + y * frame.linesize[0];
					for (x = 0; x < frame.height; x++)
						if (*pixptr++ > black_tresh) {
							i += *pixptr;
							if (i > mx) {
								y = frame.height + 1;
								break;
							}
						}
				}
				if (y == frame.height)
					printf("%i\n", fnum - 1);
			}
			pkt.data += len;
			pkt.size -= len;
		}
	}
ex:
	avcodec_close(&avctx);
	munmap(map, st.st_size);
	close(fd);
}


int main(int argc, char **argv)
{
	int i;

	avcodec_register_all();
	h264 = avcodec_find_decoder_by_name("h264");
    //avcodec_register(&ff_h264_decoder);

	for (i = 1; i < argc; i++)
		process_file(argv[i]);

	return 0;
}
