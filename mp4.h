#ifndef __MP4_H__
#define __MP4_H__

#include <stdint.h>
#include <sys/types.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ATOM(n1,n2,n3,n4) (((uint32_t)n4<<24)|((uint32_t)n3<<16)|((uint32_t)n2<<8)|(uint32_t)n1)
#else
#define ATOM(n1,n2,n3,n4) (((uint32_t)n1<<24)|((uint32_t)n2<<16)|((uint32_t)n3<<8)|(uint32_t)n4)
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

typedef struct {
	uint32_t size;
	uint32_t type;
	union {
		u_char data[0];
		uint32_t data32[0];
		uint64_t data64[0];
	} u;
} __packed mp4_atom_hdr_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t ctype;
	uint32_t subtype;
	uint32_t manufacturer;
	uint32_t cflags;
	uint32_t cflags_mask;
	u_char name[0];
} __packed mp4_atom_hdlr_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char prof_ind;
	u_char prof_comp;
	u_char level;
	u_char sf_len;
	u_char data[0];
} __packed mp4_atom_avcC_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t entries;
	u_char reserved[16];
	uint16_t width;
	uint16_t height;
	uint32_t hres;
	uint32_t vres;
	uint32_t data_size;
	uint16_t fpsamp;
	u_char	codec_name[32];
	uint16_t bpcs;
	uint16_t ct_id;
	mp4_atom_avcC_t avcC;
} __packed mp4_atom_avc1_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t entries;
	union {
		mp4_atom_hdr_t hdr;
		mp4_atom_avc1_t avc1;
	} entry;
} __packed mp4_atom_stsd_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t sample_size;
	uint32_t sample_cnt;
	uint32_t tbl[0];
} __packed mp4_atom_stsz_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t entries;
	uint32_t tbl[0];
} __packed mp4_atom_stss_t;

typedef struct {
	uint32_t first_chunk;
	uint32_t sample_cnt;
	uint32_t desc_id;
} __packed mp4_stsc_entry_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t sample_cnt;
	mp4_stsc_entry_t tbl[0];
} __packed mp4_atom_stsc_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t chunk_cnt;
	union {
		uint32_t tbl[0];
		uint64_t tbl64[0];
	} u;
} __packed mp4_atom_stco_t;

typedef struct {
	mp4_stsc_entry_t *entry, *end;
	uint32_t chunk_count;
	uint32_t chunk_no;
	uint32_t next;
	uint32_t samp_left;
	uint32_t samp_cnt;
} mp4_stsc_ptr_t;

typedef struct {
	uint32_t count;
	uint32_t value;
} __packed mp4_xtts_entry_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t entries;
	mp4_xtts_entry_t tbl[0];
} __packed mp4_atom_xtts_t;

typedef struct {
	mp4_xtts_entry_t *entry, *end;
	uint32_t samp_left;
	uint32_t value;
} mp4_xtts_ptr_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t ctime;
	uint32_t mtime;
	uint32_t timescale;
	uint32_t duration;
	uint16_t lang;
	uint16_t q;
} __packed mp4_atom_mdhd_v0_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint64_t ctime;
	uint64_t mtime;
	uint32_t timescale;
	uint64_t duration;
	uint16_t lang;
	uint16_t q;
} __packed mp4_atom_mdhd_v1_t;
#endif
