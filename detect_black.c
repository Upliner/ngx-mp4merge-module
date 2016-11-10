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

static int mp4_xtts_ptr_init(mp4_xtts_ptr_t *ptr, mp4_atom_xtts_t *atom) {
	uint32_t entry_count = be32toh(atom->entries);
	if (be32toh(atom->hdr.size) != entry_count * sizeof(mp4_xtts_entry_t) + sizeof(mp4_atom_xtts_t)) {
		fprintf(stderr, "mp4_xtts_ptr_init: atom size doesn't match entry count");
		return -1;
	}
	if (!entry_count) {
		fprintf(stderr, "mp4_xtts_ptr_init: atom is empty");
		return -1;
	}

	ptr->entry = atom->tbl;
	ptr->end = ptr->entry + entry_count;
	ptr->samp_left = be32toh(ptr->entry->count);
	ptr->value = be32toh(ptr->entry->value);
	return 0;
}

static int mp4_xtts_ptr_advance_entry(mp4_xtts_ptr_t *ptr) {
	if (++ptr->entry >= ptr->end) {
		ptr->samp_left = 1; // Make sure that subsequent calls will return error too
		return -1;
	}
	ptr->samp_left = be32toh(ptr->entry->count);
	ptr->value = be32toh(ptr->entry->value);
	return 0;
}
static int mp4_xtts_ptr_advance(mp4_xtts_ptr_t *ptr) {
	if (--ptr->samp_left)
		return 0;
	return mp4_xtts_ptr_advance_entry(ptr);
}
static int mp4_xtts_ptr_advance_n(mp4_xtts_ptr_t *ptr, uint32_t n) {
	while (n >= ptr->samp_left) {
		n -= ptr->samp_left;
		if (mp4_xtts_ptr_advance_entry(ptr) != 0)
			return -1;
	}
	ptr->samp_left -= n;
	return 0;
}
static int mp4_xtts_ptr_advance_accum(mp4_xtts_ptr_t *ptr, uint32_t n, uint64_t *sample_no) {
	while (n >= ptr->samp_left) {
		n -= ptr->samp_left;
		*sample_no += ptr->samp_left * ptr->value;
		if (mp4_xtts_ptr_advance_entry(ptr) != 0)
			return -1;
	}
	ptr->samp_left -= n;
	*sample_no += n * ptr->value;
	return 0;
}

mp4_atom_stsd_t *stsd;
mp4_atom_stsc_t *stsc;
mp4_atom_stco_t *stco;
mp4_atom_stss_t *stss;
mp4_atom_stsz_t *stsz;
mp4_atom_xtts_t *stts, *ctts;
char co64;
uint32_t timescale;
int black_tresh = 32;
int frag_tresh = 20;
double sec_tresh = 0.2;
uint64_t sample_tresh;
int reset_mp4() {
	stsd = NULL; stsc = NULL; stco = NULL; stss = NULL; stsz = NULL;
	stts = ctts = NULL;
	co64 = 0;
	timescale = 0;
}
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
			case ATOM('s', 't', 't', 's'):
				stts = (mp4_atom_xtts_t*)ptr;
				break;
			case ATOM('c', 't', 't', 's'):
				ctts = (mp4_atom_xtts_t*)ptr;
				break;
			case ATOM('m', 'd', 'h', 'd'):
				switch (((mp4_atom_mdhd_v0_t*)ptr)->version) {
				case 0: timescale = be32toh(((mp4_atom_mdhd_v0_t*)ptr)->timescale); break;
				case 1: timescale = be32toh(((mp4_atom_mdhd_v1_t*)ptr)->timescale); break;
				default:
					fprintf(stderr, "Invalid mdhd version\n");
					return -1;
				}
				sample_tresh = sec_tresh * timescale;
				break;
		}
		ptr += size;
	}
	return 0;
}
uint8_t *map;
AVFrame frame;
int is_black() {
	int x,y, i = 0, mx = (int64_t)frame.width * frame.height / frag_tresh;
	uint8_t *ptr;
	if (!frame.data[0])
		return 0;
	for (y = 0; y < frame.height; y++) {
		ptr = frame.data[0] + y * frame.linesize[0];
		for (x = 0; x < frame.height; x++)
			if (*ptr++ > black_tresh) {
				i += *ptr;
				if (i > mx)
					return 0;
			}
	}
	return 1;
}
static inline uint8_t *mp4_chunk(uint32_t chunk_no) {
	return map + (co64 ? be64toh(stco->u.tbl64[chunk_no]) : be32toh(stco->u.tbl[chunk_no]));
}
int process_file(char *filename)
{
	struct stat st;
	uint32_t *ptr, *end;
	uint32_t fnum = 1, chunk_no, frame_cnt;
	uint64_t sample_no = 0, sample_kf, sample_nonblack;
	int fd, i, len;
	int got_frame;
	AVPacket pkt;
	AVCodecContext avctx;
	mp4_stsc_ptr_t stscp;
	mp4_xtts_ptr_t sttsp, cttsp;
	uint64_t co;
	fd = open(filename, O_RDONLY);
	fstat(fd, &st);

	map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		return -1;
	}
	reset_mp4();
	parse_atoms(map, map + st.st_size);
	if (!stsd || !stsc || !stco || !stss || !stsz || !stts || !timescale)
		goto mp4err;
	cttsp.value = 0;
	if (mp4_stsc_ptr_init(&stscp, stsc, be32toh(stco->chunk_cnt)) != 0
			|| mp4_xtts_ptr_init(&sttsp, stts) != 0
			|| (ctts && mp4_xtts_ptr_init(&cttsp, ctts) != 0))
		goto mp4err;
	av_init_packet(&pkt);
	avcodec_get_context_defaults3(&avctx, h264);
	avctx.extradata = &stsd->entry.avc1.avcC.version;
	avctx.extradata_size = be32toh(stsd->entry.avc1.avcC.hdr.size) - 8;
	avcodec_open2(&avctx, h264, NULL);
	ptr = stss->tbl;
	end = ptr + be32toh(stss->entries);
	frame_cnt = be32toh(stsz->sample_cnt);
	for (;ptr < end; ptr++) {
		// go to the next keyframe
		i = be32toh(*ptr) - fnum;
		if (i < 0)
			continue;
		if (mp4_stsc_ptr_advance_n(&stscp, i) != 0) {
			fprintf(stderr, "stsc advance failed!\n");
			break;
		}
		if (mp4_xtts_ptr_advance_accum(&sttsp, i, &sample_no) != 0) {
			fprintf(stderr, "stts advance failed!\n");
			break;
		}
		if (ctts && mp4_xtts_ptr_advance_n(&cttsp, i) != 0) {
			fprintf(stderr, "ctts advance failed!\n");
			break;
		}
		fnum = be32toh(*ptr);
		pkt.data = mp4_chunk(stscp.chunk_no - 1);
		if (fnum > frame_cnt){
			fprintf(stderr, "Frame %u is out of range!\n", fnum);
			break;
		}
		for (i = fnum - 1 - (be32toh(stscp.entry[-1].sample_cnt) - stscp.samp_left); i < (fnum - 1); i++)
			pkt.data += be32toh(stsz->tbl[i]);
		pkt.size = be32toh(stsz->tbl[i]);
		sample_kf = sample_no + cttsp.value;
		sample_nonblack = -1;
		chunk_no = stscp.chunk_no;
		while (fnum < frame_cnt) {
			if (pkt.data < map || pkt.data + pkt.size > map + st.st_size) {
				fprintf(stderr, "Frame %u has invalid chunk offset: %li\n", fnum, pkt.data - map);
				break;
			}
			while (pkt.size > 0) {
				len = avcodec_decode_video2(&avctx, &frame, &got_frame, &pkt);
				if (len < 0) {
					fprintf(stderr, "Decode frame %i failed\n", len);
					break;
				}
				if (got_frame && sample_no + cttsp.value < sample_nonblack && !is_black())
					sample_nonblack = sample_no + cttsp.value;
				pkt.data += len;
				pkt.size -= len;
			}
			if (sample_nonblack == sample_kf)
				break;
			sample_no += sttsp.value;
			if (sample_no > sample_kf + sample_tresh || sample_no >= sample_nonblack)
				break;
			if (mp4_stsc_ptr_advance(&stscp) != 0
					|| mp4_xtts_ptr_advance(&sttsp) != 0
					|| (ctts && mp4_xtts_ptr_advance(&cttsp) != 0))
				break;
			if (stscp.chunk_no != chunk_no) {
				chunk_no = stscp.chunk_no;
				pkt.data = mp4_chunk(chunk_no - 1);
			} else
				pkt.data += pkt.size;
			pkt.size = be32toh(stsz->tbl[fnum++]);
		}
		if (sample_nonblack - sample_kf > sample_tresh)
			printf("%i\n", i);
	}
ex:
	avcodec_close(&avctx);
	munmap(map, st.st_size);
	close(fd);
	return 0;
mp4err:
	fprintf(stderr, "Invalid mp4\n");
	munmap(map, st.st_size);
	close(fd);
	return 1;
}


int main(int argc, char **argv)
{
	int i;

	avcodec_register_all();
	h264 = avcodec_find_decoder_by_name("h264");
    //avcodec_register(&ff_h264_decoder);
	memset(&frame, 0, sizeof(frame));
	av_frame_unref(&frame);

	if (argc < 2) {
		fprintf(stderr, "Usage: detect_black [-t secs] filename");
		return 1;
	}
	i = 1;
	if (argc > 3 && argv[i] == "-t") {
		sec_tresh =
		i += 2;
	}
	process_file(argv[i]);
	return 0;
}
