#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <nginx.h>

#if (NGX_FREEBSD)
#include <sys/endian.h>
#endif

#include "ngx_http_mp4mux_list.h"
#include "mp4.h"

#define MAX_ATOM_SIZE 16*1024*1024

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ATOM(n1,n2,n3,n4) (((uint32_t)n4<<24)|((uint32_t)n3<<16)|((uint32_t)n2<<8)|(uint32_t)n1)
#else
#define ATOM(n1,n2,n3,n4) (((uint32_t)n1<<24)|((uint32_t)n2<<16)|((uint32_t)n3<<8)|(uint32_t)n4)
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define TIMESCALE_MAX 4000000000

// We need 6-10 bytes for frame header conversion
// 2048 is enough for 200-340 frames
#define CONV_BUFSIZE 2048

typedef u_char bool_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t ctime;
	uint32_t mtime;
	uint32_t timescale;
	uint32_t duration;
	uint32_t pref_rate;
	uint16_t pref_vol;
	uint8_t reserved[10];
	uint8_t matrix[36];
	uint32_t preview_time;
	uint32_t preview_duration;
	uint32_t poster_time;
	uint32_t selection_time;
	uint32_t selection_duration;
	uint32_t current_time;
	uint32_t next_track_id;
} __packed mp4_atom_mvhd_t;

typedef struct {
	mp4_atom_hdr_t hdr;
	u_char version;
	u_char flags[3];
	uint32_t ctime;
	uint32_t mtime;
	uint32_t track_id;
	uint32_t reserved;
	uint32_t duration;
} __packed mp4_atom_tkhd_t;

struct mp4_atom_s;
struct mp4_atom_s {
	mp4mux_list_t entry;
	mp4mux_list_t atoms;
	mp4_atom_hdr_t *hdr;
	mp4_atom_hdr_t data[0];
};

typedef struct mp4_atom_s mp4_atom_t;

typedef struct mp4merge_cache_entry_s mp4merge_cache_entry_t;

typedef struct {
	mp4merge_cache_entry_t **hashtable;
	u_char *start, *end;
	u_char *write_pos;
} mp4merge_cache_header_t;

struct mp4merge_cache_entry_s {
	mp4merge_cache_entry_t *hash_next;
	u_char md5[16];
	uint64_t frame_no;
};

typedef struct mp4_file_s mp4_file_t;
typedef struct mp4_trak_s mp4_trak_t;
typedef struct {
	uint64_t timescale;
	mp4_atom_t *mdhd;
	mp4_atom_t *stbl;
	mp4_atom_stco_t *stco;
} mp4_trak_output_t;
struct mp4_trak_s {
	mp4_file_t *file;
	mp4_trak_output_t *dest;
	mp4_atom_t *trak;
	mp4_atom_tkhd_t *tkhd;
	mp4_atom_hdlr_t *hdlr;
	mp4_atom_mdhd_v0_t *mdhd;
	mp4_atom_t *minf;
	mp4_atom_t *stbl;
	mp4_atom_stsd_t *stsd;
	mp4_atom_xtts_t *stts;
	mp4_atom_stsc_t *stsc;
	mp4_atom_stsz_t *stsz;
	mp4_atom_stco_t *stco;
	mp4_atom_xtts_t *ctts;
	mp4_atom_stss_t *stss;
	mp4_trak_t *next;
	uint64_t duration;
	off_t co;
	mp4_stsc_ptr_t stsc_ptr;
	uint32_t timescale;
	uint32_t frame_no, frame_end;
	bool_t co64;
	bool_t shift_pps;
};
struct mp4_file_s {
	ngx_file_t file;

	ngx_str_t basename;
	ngx_str_t fname;

	mp4_atom_mvhd_t *mvhd;
	mp4mux_list_t atoms;
	mp4_trak_t *traksl;
	mp4_trak_t **traksa;
	ngx_int_t vid_cnt, aid_cnt;

	size_t file_size;
	time_t file_mtime;
};

typedef struct ngx_http_mp4merge_ctx_s {
	ngx_http_request_t *req;
	ngx_chain_t *chain, *chain_last;
	mp4mux_list_t atoms_head;
	mp4_trak_output_t *traks;
	ngx_int_t trak_cnt;
	mp4_file_t main;
	mp4_file_t mixin;
	ngx_int_t secpos;
	ngx_int_t fpos;
	uint64_t mdat_len;
	off_t range_start, range_end;
	u_char convbuf[CONV_BUFSIZE];
	bool_t co64;
	unsigned done:1;
	unsigned move_meta:1;
} ngx_http_mp4merge_ctx_t;

typedef struct {
	ngx_flag_t move_meta;
} ngx_http_mp4merge_conf_t;

typedef struct {
	ngx_shm_zone_t *cache_zone;
	size_t cache_size;
	size_t cache_hash_size;
} ngx_http_mp4merge_main_conf_t;

static uint32_t mp4_atom_containers[] = {
	ATOM('m', 'o', 'o', 'v'),
	ATOM('t', 'r', 'a', 'k'),
	ATOM('m', 'd', 'i', 'a'),
	ATOM('m', 'i', 'n', 'f'),
	ATOM('s', 't', 'b', 'l')
};

/* These two structs must be kept in sync with ngx_http_range_filter_module.c
   It seems that there are no other way to hook range-skipping.
   Fortunately, these structures changes really rarely,
   last changed 29 Dec 2006 */
typedef struct {
	off_t        start;
	off_t        end;
	ngx_str_t    content_range;
} ngx_http_range_t;
typedef struct {
	off_t        offset;
	ngx_str_t    boundary_header;
	ngx_array_t  ranges;
} ngx_http_range_filter_ctx_t;

const uint32_t mp4merge_version = 0x01; // This value should be changed after every change in the merging algorighm to change ETag

extern ngx_module_t ngx_http_range_body_filter_module;

static char *ngx_http_mp4merge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_mp4merge_create_conf(ngx_conf_t *cf);
static char *ngx_http_mp4merge_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t mp4_stsc_ptr_init(mp4_stsc_ptr_t *ptr, mp4_atom_stsc_t *atom, uint32_t chunk_count, ngx_log_t *log);
static ngx_int_t mp4_xtts_ptr_init(mp4_xtts_ptr_t *ptr, mp4_atom_xtts_t *atom, ngx_log_t *log);
//static ngx_int_t mp4_xtts_ptr_advance(mp4_xtts_ptr_t *ptr);
static ngx_int_t mp4_xtts_ptr_advance_entry(mp4_xtts_ptr_t *ptr);

static ngx_int_t mp4_atom_to_trak(mp4_atom_t *a, mp4_trak_t **t, ngx_pool_t *pool);
static ngx_int_t mp4_parse_atom(ngx_pool_t *pool, mp4_file_t *mp4f, mp4_trak_t **trak, mp4_atom_t *atom);
static ngx_int_t mp4_parse(ngx_http_mp4merge_ctx_t *ctx, mp4_file_t *f);
static mp4_atom_t *mp4_clone_primitive_atom(mp4_atom_hdr_t *hdr, ngx_pool_t *pool);
static mp4_atom_t *mp4_clone_atom(mp4_atom_t *atom, mp4_trak_output_t *dst_trak, ngx_pool_t *pool);
static off_t mp4_build_atoms(mp4mux_list_t *list, ngx_log_t *log);
static ngx_int_t mp4_build_chain_ex(ngx_http_mp4merge_ctx_t *ctx, mp4mux_list_t *list, ngx_chain_t **out, ngx_chain_t **last);
static ngx_chain_t *mp4_build_chain(ngx_http_mp4merge_ctx_t *ctx, mp4mux_list_t *list);
static ngx_int_t mp4merge_open_file(ngx_http_mp4merge_ctx_t *ctx, mp4_file_t *f);
static ngx_int_t mp4_do_merge(ngx_http_mp4merge_ctx_t *ctx);

static ngx_command_t  ngx_http_mp4merge_commands[] = {

	{ ngx_string("mp4merge"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
	  ngx_http_mp4merge,
	  0,
	  0,
	  NULL },

	{ ngx_string("mp4merge_move_meta"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_mp4merge_conf_t, move_meta),
	  NULL },

	ngx_null_command
};

static ngx_http_module_t  ngx_http_mp4merge_module_ctx = {
	NULL,                          /* preconfiguration */
	NULL,                          /* postconfiguration */

	NULL,//ngx_http_mp4merge_create_main_conf,/* create main configuration */
	NULL,//ngx_http_mp4merge_init_main_conf,  /* init main configuration */

	NULL,                          /* create server configuration */
	NULL,                          /* merge server configuration */

	ngx_http_mp4merge_create_conf,   /* create location configuration */
	ngx_http_mp4merge_merge_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_mp4merge_module = {
	NGX_MODULE_V1,
	&ngx_http_mp4merge_module_ctx,   /* module context */
	ngx_http_mp4merge_commands,      /* module directives */
	NGX_HTTP_MODULE,               /* module type */
	NULL,                          /* init master */
	NULL,                          /* init module */
	NULL,                          /* init process */
	NULL,                          /* init thread */
	NULL,                          /* exit thread */
	NULL,                          /* exit process */
	NULL,                          /* exit master */
	NGX_MODULE_V1_PADDING
};

static u_char* parseint(u_char *str, u_char *end, ngx_int_t *result)
{
	*result = 0;
	while (str < end && *str >= '0' && *str <= '9')
		*result = *result * 10 + *str++ - '0';
	return str;
}

static uint64_t gcd(uint64_t u, uint64_t v) {
	if (u == v)
		return u;
	if (u == 0)
		return v;
	if (v == 0)
		return u;
	if ((u & 1) == 0) {
		if (v & 1)
			return gcd(u >> 1, v);
		else
			return gcd(u >> 1, v >> 1) << 1;
	}
	if ((v & 1) == 0)
		return gcd(u, v >> 1);
	if (u > v)
		return gcd((u - v) >> 1, v);
	return gcd((v - u) >> 1, u);
}
static uint64_t lcm(uint32_t u, uint32_t v) {
	return (uint64_t)u*v/gcd(u,v);
}
static ngx_int_t mp4_set_path(mp4_file_t *f, ngx_http_request_t *r, char *arg, ngx_str_t *path)
{
	ngx_str_t fname, value;
	if (ngx_http_arg(r, (u_char *) arg, strlen(arg), &value) != NGX_OK)
		return NGX_HTTP_NOT_FOUND;

	fname.len = path->len + value.len;
	fname.data = ngx_pnalloc(r->pool, fname.len + 1);
	if (!fname.data)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ngx_memcpy(fname.data, path->data, path->len);
	ngx_memcpy(fname.data + path->len, value.data, value.len);
	fname.data[fname.len] = 0;

	f->fname = fname;
	f->basename = value;
	return NGX_OK;
}

static ngx_int_t mp4merge_add_etag(ngx_http_mp4merge_ctx_t *ctx)
{
	u_char md5_result[16];
	ngx_table_elt_t *hdr;
	ngx_md5_t etag_md5;
	if (!(hdr = ngx_list_push(&ctx->req->headers_out.headers)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	hdr->hash = 1;
	ngx_str_set(&hdr->key, "ETag");
	hdr->value.len = 34;
	if (!(hdr->value.data = ngx_palloc(ctx->req->pool, 34)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	ngx_md5_init(&etag_md5);
	ngx_md5_update(&etag_md5, &ctx->secpos, sizeof(ngx_int_t));
	ngx_md5_update(&etag_md5, &ctx->fpos, sizeof(ngx_int_t));
	ngx_md5_update(&etag_md5, &ctx->main.file_mtime, sizeof(time_t));
	ngx_md5_update(&etag_md5, &ctx->main.file_size, sizeof(size_t));
	ngx_md5_update(&etag_md5, &ctx->mixin.file_mtime, sizeof(time_t));
	ngx_md5_update(&etag_md5, &ctx->mixin.file_size, sizeof(size_t));
	ngx_md5_final(md5_result, &etag_md5);
	ngx_hex_dump(hdr->value.data + 1, md5_result, 16);
	hdr->value.data[0] = '"';
	hdr->value.data[33] = '"';
	ctx->req->headers_out.etag = hdr;
	return NGX_OK;
}
static void mp4_adjust_co(mp4_trak_output_t *t, int32_t a, bool_t co64) {
	uint32_t i, n = t->stco->chunk_cnt;
	if (co64)
		for (i = 0; i < n; i++)
			t->stco->u.tbl64[i] = htobe64(t->stco->u.tbl64[i] + a);
	else
		for (i = 0; i < n; i++)
			t->stco->u.tbl[i] = htobe32(t->stco->u.tbl[i] + a);
	t->stco->chunk_cnt = htobe32(t->stco->chunk_cnt);
}
static mp4_atom_t *mp4_alloc_atom(ngx_pool_t *pool, size_t data_size) {
	mp4_atom_t *a = ngx_palloc(pool, sizeof(mp4_atom_t) + data_size);
	if (!a) return NULL;
	MP4MUX_INIT_LIST_HEAD(&a->atoms);
	if (data_size) a->hdr = a->data;
	return a;
}
static ngx_int_t ngx_http_mp4merge_handler(ngx_http_request_t *r)
{
	u_char                    *last;
	size_t                     root;
	ngx_int_t                  rc;
	ngx_str_t                  path, value;
	ngx_http_range_filter_ctx_t *rangectx;
	ngx_http_mp4merge_ctx_t *ctx;
	ngx_chain_t *out, *ol;
	ngx_log_t *log = r->connection->log;
	mp4_atom_t *a;
	off_t len_head;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
		"http_mp4merge_handler");

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
		return NGX_HTTP_NOT_ALLOWED;

	if (!r->args.len)
		return NGX_HTTP_NOT_FOUND;

	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK)
		return rc;

	rangectx = ngx_http_get_module_ctx(r, ngx_http_range_body_filter_module);
	if (rangectx != NULL && rangectx->ranges.nelts != 1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4mux: requests with multiple ranges are not supported", &value);
		return NGX_HTTP_BAD_REQUEST;
	}

	//conf = ngx_http_get_module_loc_conf(r, ngx_http_mp4merge_module);

	last = ngx_http_map_uri_to_path(r, &path, &root, 0);
	if (last == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	path.len = last - path.data;

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mp4merge_ctx_t));

	if (ctx == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	ctx->req = r;

	ngx_http_set_ctx(r, ctx, ngx_http_mp4merge_module);
	if ((rc = mp4_set_path(&ctx->main, r, "main", &path)) != NGX_OK)
		return rc;
	if ((rc = mp4_set_path(&ctx->mixin, r, "mixin", &path)) != NGX_OK)
		return rc;

	if (ngx_http_arg(r, (u_char *) "pos", 3, &value) == NGX_OK)
		parseint(value.data, value.data + value.len, &ctx->secpos);
	else if (ngx_http_arg(r, (u_char *) "fpos", 4, &value) == NGX_OK)
		parseint(value.data, value.data + value.len, &ctx->fpos);
	else
		return NGX_HTTP_NOT_FOUND;


	if (mp4merge_add_etag(ctx) != NGX_OK)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	if ((rc = mp4merge_open_file(ctx, &ctx->main)) != NGX_OK)
		return rc;
	if ((rc = mp4merge_open_file(ctx, &ctx->mixin)) != NGX_OK)
		return rc;

	if ((rc = mp4_do_merge(ctx)) != NGX_OK)
		return rc;

	len_head = mp4_build_atoms(&ctx->atoms_head, log);
	if (len_head < 0)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	len_head += (ctx->co64 ? 16 : 8);
	for (rc = 0; rc < ctx->trak_cnt; rc++)
		mp4_adjust_co(ctx->traks + rc, len_head, ctx->co64);

	// Add mdat
	if (!(a = mp4_alloc_atom(ctx->req->pool, sizeof(mp4_atom_hdr_t) + ctx->co64 ? 8 : 0)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	a->hdr->type = ATOM('m', 'd', 'a', 't');
	if (ctx->co64) {
		a->hdr->size = htobe32(1);
		a->hdr->u.data64[0] = htobe64(sizeof(mp4_atom_hdr_t) + 8 + ctx->mdat_len);
	} else
		a->hdr->size = htobe32(sizeof(mp4_atom_hdr_t) + ctx->mdat_len);

	mp4mux_list_add_tail(&a->entry, &ctx->atoms_head);

	r->root_tested = !r->error_page;
	r->allow_ranges = 1;
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = len_head + ctx->mdat_len;
	ngx_str_set(&r->headers_out.content_type, "video/mp4");
	r->headers_out.content_type_len = r->headers_out.content_type.len;

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
		return rc;

	out = mp4_build_chain(ctx, &ctx->atoms_head);
	if (!out)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	for (ol = out; ol->next; ol = ol->next);
	ol->next = ctx->chain;

	return ngx_http_output_filter(r, out);
}
static ngx_int_t mp4_xtts_ptr_init(mp4_xtts_ptr_t *ptr, mp4_atom_xtts_t *atom, ngx_log_t *log) {
	uint32_t entry_count = be32toh(atom->entries);
	if (be32toh(atom->hdr.size) != entry_count * sizeof(mp4_xtts_entry_t) + sizeof(mp4_atom_xtts_t)) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_xtts_ptr_init: atom size doesn't match entry count");
		return NGX_ERROR;
	}
	if (!entry_count) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "mp4_xtts_ptr_init: atom is empty");
		return NGX_ERROR;
	}

	ptr->entry = atom->tbl;
	ptr->end = ptr->entry + entry_count;
	ptr->samp_left = be32toh(ptr->entry->count);
	ptr->value = be32toh(ptr->entry->value);
	return NGX_OK;
}

static ngx_int_t mp4_xtts_ptr_advance_entry(mp4_xtts_ptr_t *ptr) {
	if (++ptr->entry >= ptr->end) {
		ptr->samp_left = 1; // Make sure that subsequent calls will return error too
		return NGX_ERROR;
	}
	ptr->samp_left = be32toh(ptr->entry->count);
	ptr->value = be32toh(ptr->entry->value);
	return NGX_OK;
}
/*static ngx_int_t mp4_xtts_ptr_advance(mp4_xtts_ptr_t *ptr) {
	if (--ptr->samp_left)
		return NGX_OK;
	return mp4_xtts_ptr_advance_entry(ptr);
}*/
static ngx_int_t mp4_xtts_ptr_advance_n(mp4_xtts_ptr_t *ptr, uint32_t n) {
	while (n >= ptr->samp_left) {
		n -= ptr->samp_left;
		if (mp4_xtts_ptr_advance_entry(ptr) != NGX_OK)
			return NGX_ERROR;
	}
	ptr->samp_left -= n;
	return NGX_OK;
}
static ngx_int_t mp4_xtts_ptr_advance_accum(mp4_xtts_ptr_t *ptr, uint32_t n, uint64_t *sample_no) {
	while (n >= ptr->samp_left) {
		n -= ptr->samp_left;
		*sample_no += ptr->samp_left * ptr->value;
		if (mp4_xtts_ptr_advance_entry(ptr) != NGX_OK)
			return NGX_ERROR;
	}
	ptr->samp_left -= n;
	*sample_no += n * ptr->value;
	return NGX_OK;
}
static ngx_int_t mp4_stsc_ptr_init(mp4_stsc_ptr_t *ptr, mp4_atom_stsc_t *atom, uint32_t chunk_count, ngx_log_t *log)
{
	uint32_t entry_cnt = be32toh(atom->sample_cnt);
	if (be32toh(atom->hdr.size) != sizeof(mp4_atom_stsc_t) + sizeof(mp4_stsc_entry_t) * entry_cnt) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_stsc_ptr_init: stsc atom size doesn't match entry count");
		return NGX_ERROR;
	}
	if (entry_cnt == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4_stsc_ptr_init: stsc table is empty!");
		return NGX_ERROR;
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
	return NGX_OK;
}
static ngx_int_t mp4_stsc_ptr_advance_entry2(mp4_stsc_ptr_t *ptr) {
	if (ptr->entry >= ptr->end) {
		ptr->samp_left = 1;
		return NGX_ERROR;
	}
	ptr->samp_cnt = be32toh(ptr->entry++->sample_cnt);
	if (ptr->entry == ptr->end)
		ptr->next = ptr->chunk_count + 1;
	else
		ptr->next = be32toh(ptr->entry->first_chunk);
	ptr->samp_left = ptr->samp_cnt;
	return NGX_OK;
}
static ngx_int_t mp4_stsc_ptr_advance_entry(mp4_stsc_ptr_t *ptr) {
	if (++ptr->chunk_no >= ptr->next)
		return mp4_stsc_ptr_advance_entry2(ptr);
	ptr->samp_left = ptr->samp_cnt;
	return NGX_OK;
}
static ngx_int_t mp4_stsc_ptr_advance(mp4_stsc_ptr_t *ptr) {
	if (--ptr->samp_left)
		return NGX_OK;
	if (mp4_stsc_ptr_advance_entry(ptr)) {
		return NGX_ERROR;
	}
	return NGX_OK;
}
static ngx_int_t mp4_stsc_ptr_advance_n(mp4_stsc_ptr_t *ptr, uint32_t n) {
	while (n >= ptr->samp_left) {
		n -= ptr->samp_left;
		if (mp4_stsc_ptr_advance_entry(ptr) != NGX_OK)
			return NGX_ERROR;
	}
	ptr->samp_left -= n;
	return NGX_OK;
}
static ngx_int_t mp4_detect_traks(mp4_file_t *f, ngx_pool_t *pool)
{
	mp4_trak_t *t, **ta;
	for (t = f->traksl;t;t=t->next)
		switch (t->hdlr->subtype) {
		case ATOM('v','i','d','e'):f->vid_cnt++;break;
		case ATOM('s','o','u','n'):f->aid_cnt++;break;
		}
	if (!f->vid_cnt && !f->aid_cnt)
		return NGX_ERROR;
	if (f->vid_cnt > 1) {
		ngx_log_error(NGX_LOG_ERR, pool->log, 0,
			"mp4merge: more than 1 video track is not supported");
		return NGX_ERROR;
	}
	if (!(ta = ngx_palloc(pool, sizeof(mp4_trak_t*) * (f->vid_cnt + f->aid_cnt))))
		return NGX_ERROR;
	f->traksa = ta;
	for (t = f->traksl;t;t=t->next)
		if (t->hdlr->subtype == ATOM('v','i','d','e'))
			*ta++ = t;
	for (t = f->traksl;t;t=t->next)
		if (t->hdlr->subtype == ATOM('s','o','u','n'))
			*ta++ = t;
	return NGX_OK;
}
static uint32_t adjust_to_keyframe(mp4_trak_t *trak, uint32_t frame_no, mp4_xtts_ptr_t *stts_ptr, uint64_t *sample_no) {
	uint32_t *ptr, *end;
	uint32_t keyframe;
	for (ptr = trak->stss->tbl, end = ptr + be32toh(trak->stss->entries); ptr < end; ptr++)
		if ((keyframe = be32toh(*ptr) - 1) >= frame_no)
			break;
	if (ptr >= end) {
		do {
			frame_no += stts_ptr->samp_left;
			*sample_no += stts_ptr->samp_left * stts_ptr->value;
		} while (mp4_xtts_ptr_advance_entry(stts_ptr) == NGX_OK);
		return frame_no;
	} else {
		mp4_xtts_ptr_advance_accum(stts_ptr, keyframe - frame_no, sample_no);
		return keyframe;
	}
}
static uint32_t ins_frameno(mp4_trak_t *trak, mp4_xtts_ptr_t *stts_ptr, int64_t sample_cnt, uint64_t *sample_no)
{
	uint64_t i;
	uint32_t frame_no = 0;
	*sample_no = 0;
	while (sample_cnt > 0) {
		i = stts_ptr->value * stts_ptr->samp_left;
		sample_cnt -= i;
		if (sample_cnt >= 0) {
			frame_no += stts_ptr->samp_left;
			*sample_no += i;
			if (mp4_xtts_ptr_advance_entry(stts_ptr) != NGX_OK)
				return frame_no;
		} else {
			i = stts_ptr->samp_left + sample_cnt / stts_ptr->value;
			frame_no += i;
			*sample_no += i * stts_ptr->value;
			if (mp4_xtts_ptr_advance_n(stts_ptr, i) != NGX_OK)
				return frame_no;
		}
	}
	if (!trak->stss)
		return frame_no;
	return adjust_to_keyframe(trak, frame_no, stts_ptr, sample_no);
}
static void *mp4_create_table(mp4_atom_t *stbl, uint32_t atom_type, ngx_int_t size, ngx_pool_t *pool)
{
	mp4_atom_t *a = mp4_alloc_atom(pool, size);
	if (!a)
		return NULL;

	a->hdr->type = atom_type;
	mp4mux_list_add_tail(&a->entry, &stbl->atoms);
	a->hdr->u.data32[0] = 0;
	return a->hdr;
}
static mp4_atom_xtts_t *merge_xtts(mp4_atom_t *stbl, uint32_t atom_type,
                        mp4_atom_xtts_t *a, mp4_xtts_ptr_t *ap, mp4_atom_xtts_t *b,
                        uint32_t ts_a, uint32_t ts_b, uint32_t ts_d, ngx_pool_t *pool)
{
	mp4_atom_xtts_t *x = mp4_create_table(stbl, atom_type,
		sizeof(mp4_atom_xtts_t) + (be32toh(a->entries) + be32toh(b->entries) + 1) * 8,  pool);
	mp4_xtts_entry_t *wr, *rd, *b_end;
	if (!x)
		return NULL;
	wr = x->tbl;
	for (rd = a->tbl; rd < ap->entry; rd++, wr++) {
		wr->value = htobe32((uint64_t)be32toh(rd->value) * ts_d / ts_a);
		wr->count = rd->count;
	}
	if (rd < ap->end) {
		wr->value = htobe32((uint64_t)be32toh(rd->value) * ts_d / ts_a);
		wr->count = htobe32(be32toh(rd->count)-ap->samp_left);
		if (wr->count) wr++;
	}
	b_end = b->tbl + be32toh(b->entries);
	for (rd = b->tbl; rd < b_end; rd++, wr++) {
		wr->value = htobe32((uint64_t)be32toh(rd->value) * ts_d / ts_b);
		wr->count = rd->count;
	}
	if (ap->entry < ap->end)
		do {
			wr->value = htobe32((uint64_t)ap->value * ts_d / ts_a);
			wr->count = htobe32(ap->samp_left);
			wr++;
		} while (mp4_xtts_ptr_advance_entry(ap) == NGX_OK);
	x->entries = htobe32(wr - x->tbl);
	x->hdr.size = htobe32(sizeof(mp4_atom_xtts_t) + sizeof(mp4_xtts_entry_t) * (wr - x->tbl));
	return x;
}
static mp4_atom_stsc_t *merge_stsc(mp4_atom_t *stbl, mp4_atom_stsc_t *a, mp4_stsc_ptr_t *ap,
                                   mp4_atom_stsc_t *b, uint32_t b_chunks, uint32_t b_offs, ngx_pool_t *pool)
{
	mp4_atom_stsc_t *x = mp4_create_table(stbl, ATOM('s', 't', 's', 'c'),
		sizeof(mp4_atom_stsc_t) + (be32toh(a->sample_cnt) + be32toh(b->sample_cnt) + 3) * 12,  pool);
	mp4_stsc_entry_t *wr, *rd, *b_end;
	if (!x)
		return NULL;
	wr = x->tbl;
	uint32_t chunk_offs = 0;

	ngx_memcpy(wr, a->tbl, (u_char*)(ap->entry - 1) - (u_char*)a->tbl);
	wr += ap->entry - a->tbl - 1;
	if (ap->chunk_no > be32toh(ap->entry[-1].first_chunk))
		*wr++ = ap->entry[-1];
	if (ap->chunk_no <= ap->chunk_count) {
		wr->first_chunk = htobe32(ap->chunk_no);
		wr->desc_id = ap->entry[-1].desc_id;
		wr->sample_cnt = htobe32(be32toh(ap->entry[-1].sample_cnt)-ap->samp_left);
		if (wr->sample_cnt) {
			wr++;
			chunk_offs = 1;
		}
	}
	b_end = b->tbl + be32toh(b->sample_cnt);
	for (rd = b->tbl; rd < b_end; rd++, wr++) {
		wr->first_chunk = htobe32(be32toh(rd->first_chunk) + ap->chunk_no - 1 + chunk_offs);
		wr->desc_id = htobe32(be32toh(rd->desc_id) + b_offs);
		wr->sample_cnt = rd->sample_cnt;
	}
	if (ap->chunk_no <= ap->chunk_count) {
		wr->first_chunk = htobe32(ap->chunk_no + b_chunks + chunk_offs);
		wr->desc_id = ap->entry[-1].desc_id;
		wr->sample_cnt = htobe32(ap->samp_left);
		wr++;
		mp4_stsc_ptr_advance_entry(ap);
	}
	if (ap->chunk_no <= ap->chunk_count)
		do {
			wr->first_chunk = htobe32(ap->chunk_no + b_chunks + chunk_offs);
			wr->desc_id = ap->entry[-1].desc_id;
			wr->sample_cnt = htobe32(ap->samp_left);
			ap->chunk_no = ap->next;
			wr++;
		} while (mp4_stsc_ptr_advance_entry2(ap) == NGX_OK);
	x->sample_cnt = htobe32(wr - x->tbl);
	x->hdr.size = htobe32(sizeof(mp4_atom_stsc_t) + sizeof(mp4_stsc_entry_t) * (wr - x->tbl));
	return x;
}
static ngx_int_t mp4_validate_stsd_video(ngx_log_t *log, mp4_atom_stsd_t *stsd) {
	u_char *stsd_end = (u_char*)stsd + be32toh(stsd->hdr.size);
	avcC_xps_t *sps, *pps;
	uint16_t sps_len, pps_len;
	if (be32toh(stsd->hdr.size) < sizeof(mp4_atom_stsd_t) + sizeof(avcC_xps_t)) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: stsd atom is too small");
	}
	if (be32toh(stsd->entries) != 1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: number of entries in stsd must be 1");
		return NGX_ERROR;
	}
	if (stsd->entry.hdr.type != ATOM('a','v','c','1')) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: only avc1(h264) format is supported now");
		return NGX_ERROR;
	}
	if (be32toh(stsd->entry.avc1.entries) != 1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: number of entries in avc1 must be 1");
		return NGX_ERROR;
	}
	if (stsd->entry.avc1.avcC.hdr.type != ATOM('a','v','c','C')) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: avcC atom is not found in avc1");
		return NGX_ERROR;
	}
	sps = &stsd->entry.avc1.avcC.sps;
	sps_len = be16toh(sps->len);
	if (sps_len < 5 || sps->data + sps_len + sizeof(avcC_xps_t) >= stsd_end) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: invalid sps data size");
		return NGX_ERROR;
	}
	pps = (avcC_xps_t*)(sps->data + sps_len);
	if (sps->cnt != 0xe1 || pps->cnt != 0x01) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: only one sps and one pps is now supported");
		return NGX_ERROR;
	}
	pps_len = be16toh(pps->len);
	if (pps_len < 2 || pps->data + pps_len > stsd_end) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: invalid pps data size");
		return NGX_ERROR;
	}
	if (!(stsd->entry.avc1.avcC.sps_id & 0x80)) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: sps_id must be 0");
		return NGX_ERROR;
	}
	if (!(pps->data[1] & 0xC0)) {
		ngx_log_error(NGX_LOG_ERR, log, 0,
			"mp4merge: pps_id must be 0");
		return NGX_ERROR;
	}
	return NGX_OK;
}
static void merge_avcC(mp4_atom_stsd_t *dest, mp4_atom_avcC_t *a, mp4_atom_avcC_t *b) {
	u_char *ptr = dest->entry.avc1.avcC.sps.data + be16toh(a->sps.len);
	u_char *src;
	uint16_t len;
	dest->entry.avc1.avcC.sps.cnt = 0xe2;
	*(uint16_t*)ptr = htobe16(be16toh(b->sps.len) + 1);
	ptr += 2;
	memcpy(ptr, b->sps.data, 4);
	ptr += 4;
	*ptr++ = 0x08;
	len = be16toh(b->sps.len) - 4;
	memcpy(ptr, b->sps.data + 4, len);
	ptr += len;
	*ptr++ = 0x02;
	src = a->sps.data + be16toh(a->sps.len) + 1;
	len = be16toh(*(uint16_t*)src) + 2;
	memcpy(ptr, src, len);
	ptr += len;
	src = b->sps.data + be16toh(b->sps.len) + 1;
	len = be16toh(*(uint16_t*)src);
	*(uint16_t*)ptr = htobe16(len + 2);
	src += 2;
	ptr += 2;
	len -= 2;
	*ptr++ = *src++;
	*ptr++ = 0x08; *ptr++ = 0x84;
	*ptr++ = *src++ & 0x7f;
	memcpy(ptr, src, len);
	ptr += len;
	dest->entry.avc1.avcC.hdr.size = htobe32(ptr - (u_char*)&dest->entry.avc1.avcC);
	dest->entry.avc1.hdr.size = htobe32(ptr - (u_char*)&dest->entry.avc1);
	dest->hdr.size = htobe32(ptr - (u_char*)dest);
}
static ngx_int_t merge_trak(mp4_trak_output_t *dest, mp4_trak_t *a, mp4_trak_t *b,
                            ngx_int_t frame_no, mp4_xtts_ptr_t *stts_ptr, ngx_pool_t *pool)
{
	uint32_t frame_count;
	uint32_t size, size2, b_offs = 0, stss_ptr;
	uint32_t *ptr, *rptr, *eptr;
	mp4_atom_stss_t *stss;
	mp4_atom_stsz_t *stsz;
	mp4_atom_stsd_t *stsd;
	mp4_atom_t *atom;
	mp4_xtts_ptr_t ctts_ptr;
	mp4_stsc_ptr_t stsc_ptr;
	dest->timescale = lcm(a->timescale, b->timescale); // calculate new timescale
	if (dest->timescale > TIMESCALE_MAX)
		dest->timescale = TIMESCALE_MAX;

	a->frame_end = frame_no;
	b->frame_end = -1;

	// mdhd
	if (((mp4_atom_mdhd_v0_t*)dest->mdhd->hdr)->version == 0) {
		((mp4_atom_mdhd_v0_t*)dest->mdhd->hdr)->timescale = htobe32(dest->timescale);
		((mp4_atom_mdhd_v0_t*)dest->mdhd->hdr)->duration = htobe32(a->duration*dest->timescale/a->timescale + b->duration*dest->timescale/b->timescale);
	} else {
		((mp4_atom_mdhd_v1_t*)dest->mdhd->hdr)->timescale = htobe32(dest->timescale);
		((mp4_atom_mdhd_v1_t*)dest->mdhd->hdr)->duration = htobe64(a->duration*dest->timescale/a->timescale + b->duration*dest->timescale/b->timescale);
	}

	// stss
	if (a->stss && b->stss) {
		frame_count = be32toh(a->stss->entries) + be32toh(b->stss->entries);
		size = sizeof(mp4_atom_stss_t) + frame_count * 4;
		if (!(stss = mp4_create_table(dest->stbl, ATOM('s', 't', 's', 's'), size, pool)))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		stss->hdr.size = htobe32(size);
		stss->entries = htobe32(frame_count);
		frame_count = be32toh(a->stss->entries);
		for (stss_ptr = 0; stss_ptr < frame_count; stss_ptr++)
			if (be32toh(a->stss->tbl[stss_ptr]) > frame_no)
				break;
		ngx_memcpy(stss->tbl, a->stss->tbl, stss_ptr * 4);
		ptr = stss->tbl + stss_ptr;
		eptr = b->stss->tbl + be32toh(b->stss->entries);
		for (rptr = b->stss->tbl; rptr < eptr; rptr++)
			*ptr++ = htobe32(be32toh(*rptr) + frame_no);
		size = be32toh(b->stsz->sample_cnt);
		eptr = a->stss->tbl + be32toh(a->stss->entries);
		for (rptr = a->stss->tbl + stss_ptr; rptr < eptr; rptr++)
			*ptr++ = htobe32(be32toh(*rptr) + size);
	}

	// stsd
	size = be32toh(a->stsd->hdr.size);
	size2 = be32toh(b->stsd->hdr.size) - offsetof(mp4_atom_stsd_t, entry);
	if (a->stsd->hdr.size == b->stsd->hdr.size && memcmp(a->stsd, b->stsd, size) == 0) {
		if (!(atom = mp4_clone_primitive_atom(&a->stsd->hdr, pool)))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		mp4mux_list_add_tail(&atom->entry, &dest->stbl->atoms);
	} else {
		if (!(stsd = mp4_create_table(dest->stbl, ATOM('s', 't', 's', 'd'), size + size2, pool)))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		memcpy(stsd, a->stsd, size);
		if (a->hdlr->subtype == ATOM('v','i','d','e')) {
			if (mp4_validate_stsd_video(pool->log, a->stsd) != NGX_OK || mp4_validate_stsd_video(pool->log, b->stsd) != NGX_OK)
				return NGX_HTTP_NOT_FOUND;
			merge_avcC(stsd, &a->stsd->entry.avc1.avcC, &b->stsd->entry.avc1.avcC);
			b->shift_pps = 1;
		} else {
			b_offs = be32toh(a->stsd->entries);
			stsd->entries = htobe32(b_offs + be32toh(b->stsd->entries));
			stsd->hdr.size = htobe32(size + size2);
			memcpy((u_char*)stsd + size, &b->stsd->entry, size2);
		}
	}

	// stsz
	frame_count = be32toh(a->stsz->sample_cnt) + be32toh(b->stsz->sample_cnt);
	size = sizeof(mp4_atom_stsz_t) + frame_count * 4;
	if (!(stsz = mp4_create_table(dest->stbl, ATOM('s', 't', 's', 'z'), size, pool)))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	stsz->hdr.size = htobe32(size);
	stsz->sample_cnt = htobe32(frame_count);
	stsz->sample_size = 0;
	ngx_memcpy(stsz->tbl, a->stsz->tbl, frame_no * 4);
	ptr = stsz->tbl + frame_no;
	size = be32toh(b->stsz->sample_cnt);
	if (b->shift_pps) {
		for(rptr = b->stsz->tbl; size; size--)
			*ptr++ = htobe32(be32toh(*rptr++) + 1);
	} else {
		ngx_memcpy(ptr, b->stsz->tbl, size * 4);
		ptr += size;
	}
	ngx_memcpy(ptr, a->stsz->tbl + frame_no, (be32toh(a->stsz->sample_cnt) - frame_no) * 4);

	// stts, ctts, stsc
	if (!merge_xtts(dest->stbl, ATOM('s', 't', 't', 's'), a->stts, stts_ptr, b->stts, a->timescale, b->timescale, dest->timescale, pool))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (a->ctts && b->ctts) {
		if (mp4_xtts_ptr_init(&ctts_ptr, a->ctts, pool->log))
			return NGX_HTTP_NOT_FOUND;
		mp4_xtts_ptr_advance_n(&ctts_ptr, frame_no);
		if (!merge_xtts(dest->stbl, ATOM('c', 't', 't', 's'), a->ctts, &ctts_ptr, b->ctts, a->timescale, b->timescale, dest->timescale, pool))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if (mp4_stsc_ptr_init(&stsc_ptr, a->stsc, be32toh(a->stco->chunk_cnt), pool->log) != NGX_OK)
		return NGX_HTTP_NOT_FOUND;
	mp4_stsc_ptr_advance_n(&stsc_ptr, frame_no);
	if (!merge_stsc(dest->stbl, a->stsc, &stsc_ptr, b->stsc, be32toh(b->stco->chunk_cnt), b_offs, pool))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	return NGX_OK;
}
static inline uint64_t mp4_chunk_offset(mp4_trak_t *trak, uint32_t chunk_no) {
	return trak->co64 ? be64toh(trak->stco->u.tbl64[chunk_no]) : be32toh(trak->stco->u.tbl[chunk_no]);
}

static ngx_int_t mp4merge_append_fbuf(ngx_http_mp4merge_ctx_t *ctx, mp4_trak_t *t, off_t size) {
	ctx->mdat_len += size;
	if (ctx->chain_last) {
		if (ctx->chain_last->buf->file_last == t->co && ctx->chain_last->buf->file == &t->file->file) {
			t->co += size;
			ctx->chain_last->buf->file_last = t->co;
			return NGX_OK;
		}
		ctx->chain_last->next = ngx_alloc_chain_link(ctx->req->pool);
		ctx->chain_last = ctx->chain_last->next;
	} else {
		ctx->chain = ngx_alloc_chain_link(ctx->req->pool);
		ctx->chain_last = ctx->chain;
	}
	if (!ctx->chain_last)
		return NGX_ERROR;
	ctx->chain_last->next = NULL;
	if (!(ctx->chain_last->buf = ngx_calloc_buf(ctx->req->pool)))
		return NGX_ERROR;
	ctx->chain_last->buf->in_file = 1;
	ctx->chain_last->buf->file = &t->file->file;
	ctx->chain_last->buf->file_pos = t->co;
	t->co += size;
	ctx->chain_last->buf->file_last = t->co;
	return NGX_OK;
}
static ngx_int_t do_pps_shift(u_char *buf) {
	u_char i = 40, c = 0;
	if ((buf[4] & 0x1f) != 1 && (buf[4] & 0x1f) != 5)
		return NGX_ERROR;
	for (; !(buf[i >> 3] & (0x80 >> (i & 7))); i++) {
		c++;
		if (i >= 128)
			return NGX_ERROR;
	}
	i += c + 1;
	c = 0;
	for (; !(buf[i >> 3] & (0x80 >> (i & 7))); i++) {
		c++;
		if (i >= 128)
			return NGX_ERROR;
	}
	i += c + 1;
	c = i & 7;
	i >>= 3;
	if (!(buf[i] & (0x80 >> c)))
		return NGX_ERROR;
	if (i > 14)
		return NGX_ERROR;
	buf[i + 1] = (buf[i] & (0xff >> c)) | (0x0800 >> c);
	buf[i] = (buf[i] & ~(0xff >> c)) | (0x08 >> c);
	*(uint32_t*)buf = htobe32(be32toh(*(uint32_t*)buf) + 1);
	return i + 2;
}
static ngx_int_t mp4merge_append_chunk(ngx_http_mp4merge_ctx_t *ctx, mp4_trak_t *t)
{
	uint32_t size = 0, flen, chunk = t->stsc_ptr.chunk_no;
	u_char buf[16];
	ngx_int_t rc;
	if (ctx->co64)
		t->dest->stco->u.tbl64[t->dest->stco->chunk_cnt++] = ctx->mdat_len;
	else
		t->dest->stco->u.tbl[t->dest->stco->chunk_cnt++] = (uint32_t)ctx->mdat_len;
	while (t->frame_no < t->frame_end && t->stsc_ptr.chunk_no == chunk) {
		flen = be32toh(t->stsz->tbl[t->frame_no++]);
		if (t->shift_pps) {
			if (ngx_read_file(&t->file->file, buf, 16, t->co) != 16)
				return NGX_ERROR;
			size = be32toh(*(uint32_t*)buf) + 4;
			if ((buf[4] & 0x1f) != 1 && (buf[4] & 0x1f) != 5 && size < flen) {
				if (mp4merge_append_fbuf(ctx, t, size) != NGX_OK)
					return NGX_ERROR;
				flen -= size;
				if (ngx_read_file(&t->file->file, buf, 16, t->co) != 16)
					return NGX_ERROR;
				size = be32toh(*(uint32_t*)buf);
			}
			if ((rc = do_pps_shift(buf)) > 0) {
				if (ctx->chain_last) {
					ctx->chain_last->next = ngx_alloc_chain_link(ctx->req->pool);
					ctx->chain_last = ctx->chain_last->next;
				} else {
					ctx->chain = ngx_alloc_chain_link(ctx->req->pool);
					ctx->chain_last = ctx->chain;
				}
				if (!ctx->chain_last)
					return NGX_ERROR;
				if (!(ctx->chain_last->buf = ngx_create_temp_buf(ctx->req->pool, rc)))
					return NGX_ERROR;
				ctx->chain_last->buf->last = ctx->chain_last->buf->end;
				ngx_memcpy(ctx->chain_last->buf->start, buf, rc);
				ctx->mdat_len += rc;
				rc--;
				t->co += rc;
				if (mp4merge_append_fbuf(ctx, t, flen - rc) != NGX_OK)
					return NGX_ERROR;
			} else {
				ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
					"mp4merge: failed to do pps shift for frame %i at co %i",
					t->frame_no, t->co);
				if (mp4merge_append_fbuf(ctx, t, flen + 1) != NGX_OK)
					return NGX_ERROR;
				t->co--;
			}
		} else
			size += flen;
		if (mp4_stsc_ptr_advance(&t->stsc_ptr) != NGX_OK)
			t->frame_no = UINT32_MAX;
	}

	if (!t->shift_pps) {
		if (mp4merge_append_fbuf(ctx, t, size) != NGX_OK)
			return NGX_ERROR;
	}
	if (t->stsc_ptr.chunk_no != chunk)
		t->co = mp4_chunk_offset(t, t->stsc_ptr.chunk_no - 1);
	return NGX_OK;
}
static ngx_int_t mp4merge_co_trak_init(mp4_trak_t *trak, ngx_log_t *log) {
	if (!trak->stco->chunk_cnt)
		return NGX_ERROR;
	trak->co = mp4_chunk_offset(trak, 0);
	return mp4_stsc_ptr_init(&trak->stsc_ptr, trak->stsc, be32toh(trak->stco->chunk_cnt), log);
}
static ngx_int_t mp4merge_co_alloc_seg(ngx_http_mp4merge_ctx_t *ctx, mp4_trak_t **traks)
{
	ngx_int_t i;
	int64_t min_co;
	mp4_trak_t *mintrak;
	while (1) {
		min_co = INT64_MAX;
		mintrak = NULL;
		for (i = 0; i < ctx->trak_cnt; i++)
			if (traks[i]->frame_no < traks[i]->frame_end && traks[i]->co < min_co) {
				mintrak = traks[i];
				min_co = mintrak->co;
			}
		if (!mintrak)
			break;
		if (mp4merge_append_chunk(ctx, mintrak) != NGX_OK)
			return NGX_ERROR;
	}
	return NGX_OK;
}
static ngx_int_t mp4_do_merge(ngx_http_mp4merge_ctx_t *ctx)
{
	mp4_atom_t *a, *ac, *tc;
	uint64_t ts_d, sample_a;
	uint32_t ts_a, ts_b;
	uint32_t frameno;
	uint64_t sample_no;
	mp4_xtts_ptr_t sp;
	mp4_atom_mvhd_t *mvhd = ctx->main.mvhd;
	ngx_int_t rc, i;
	mp4_trak_t *t;

	MP4MUX_INIT_LIST_HEAD(&ctx->atoms_head);
	// detect and merge traks
	if (mp4_detect_traks(&ctx->main, ctx->req->pool) != NGX_OK)
		return NGX_HTTP_NOT_FOUND;
	if (mp4_detect_traks(&ctx->mixin, ctx->req->pool) != NGX_OK)
		return NGX_HTTP_NOT_FOUND;
	if (ctx->main.vid_cnt != ctx->mixin.vid_cnt) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4merge: video track count differs! %i != %i", ctx->main.vid_cnt, ctx->mixin.vid_cnt);
		return NGX_HTTP_NOT_FOUND;
	}
	if (!ctx->main.vid_cnt && ctx->fpos) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4merge: fpos is supported only when video is present!");
	}
	if (ctx->main.aid_cnt != ctx->mixin.aid_cnt) {
		ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
			"mp4merge: audio track count differs! %i != %i", ctx->main.aid_cnt, ctx->mixin.aid_cnt);
		return NGX_HTTP_NOT_FOUND;
	}
	ctx->trak_cnt = ctx->main.vid_cnt + ctx->main.aid_cnt;
	if (!(ctx->traks = ngx_palloc(ctx->req->pool, sizeof(mp4_trak_output_t) * ctx->trak_cnt)))
		return NGX_HTTP_NOT_FOUND;
	mp4mux_list_for_each_entry(a, &ctx->main.atoms, entry) {
		if (!(ac = mp4_clone_atom(a, NULL, ctx->req->pool)))
			return NGX_HTTP_NOT_FOUND;
		mp4mux_list_add_tail(&ac->entry, &ctx->atoms_head);
		if (ac->hdr->type == ATOM('m','o','o','v'))
			for (i = 0; i < ctx->trak_cnt; i++) {
				if (!(tc = mp4_clone_atom(ctx->main.traksa[i]->trak, ctx->traks + i, ctx->req->pool)))
					return NGX_HTTP_NOT_FOUND;
				mp4mux_list_add_tail(&tc->entry, &ac->atoms);
			}
	}

	if (ctx->main.vid_cnt) {
		t = ctx->main.traksa[0];
		if (mp4_xtts_ptr_init(&sp, t->stts, ctx->req->connection->log))
			return NGX_HTTP_NOT_FOUND;
		if (ctx->secpos) {
			frameno = ins_frameno(t, &sp, ctx->secpos * t->timescale, &sample_no);
		} else {
			sample_no = 0;
			mp4_xtts_ptr_advance_accum(&sp, ctx->fpos, &sample_no);
			frameno= adjust_to_keyframe(t, ctx->fpos, &sp, &sample_no);
		}
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"mp4merge: vframe = %uD sample_no = %uL", frameno, sample_no);
		if ((rc = merge_trak(ctx->traks, t, ctx->mixin.traksa[0], frameno, &sp, ctx->req->pool)) != NGX_OK)
			return rc;
		ts_a = t->timescale;
		sample_a = sample_no;
		t++;
	} else {
		ts_a = 1;
		sample_a = ctx->secpos;
	}

	for(i = ctx->main.vid_cnt; i < ctx->trak_cnt; i++) {
		t = ctx->main.traksa[i];
		if (mp4_xtts_ptr_init(&sp, t->stts, ctx->req->connection->log))
			return NGX_HTTP_NOT_FOUND;
		frameno = ins_frameno(t, &sp, sample_a * t->timescale / ts_a, &sample_no);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"mp4merge: aframe = %uD sample_no = %uL", frameno, sample_no);
		if ((rc = merge_trak(ctx->traks + i, t, ctx->mixin.traksa[i], frameno, &sp, ctx->req->pool)) != NGX_OK)
			return rc;
	}

	ts_a = be32toh(ctx->main.mvhd->timescale);
	ts_b = be32toh(ctx->mixin.mvhd->timescale);
	ts_d = lcm(ts_a, ts_b);
	if (ts_d > TIMESCALE_MAX)
		ts_d = TIMESCALE_MAX;
	mvhd->timescale = htobe32(ts_d);
	mvhd->duration = htobe32((uint64_t)be32toh(ctx->main.mvhd->duration)*ts_d/ts_a + (uint64_t)be32toh(ctx->mixin.mvhd->duration)*ts_d/ts_b);
	for (i = 0; i < ctx->trak_cnt; i++)
	// allocate chunks
	ctx->co64 = ctx->main.file_size + ctx->mixin.file_size > 0xffff0000;

	for (i = 0; i < ctx->trak_cnt; i++) {
		rc = be32toh(ctx->main.traksa[i]->stco->chunk_cnt) + be32toh(ctx->mixin.traksa[i]->stco->chunk_cnt) + 1;
		if (ctx->co64)
			ctx->traks[i].stco = mp4_create_table(ctx->traks[i].stbl, ATOM('c', 'o', '6', '4'), sizeof(mp4_atom_stco_t) + rc * 8, ctx->req->pool);
		else
			ctx->traks[i].stco = mp4_create_table(ctx->traks[i].stbl, ATOM('s', 't', 'c', 'o'), sizeof(mp4_atom_stco_t) + rc * 4, ctx->req->pool);
		if (!ctx->traks[i].stco)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		ctx->traks[i].stco->chunk_cnt = 0;
		ctx->main.traksa[i]->tkhd->duration = mvhd->duration;
		ctx->main.traksa[i]->dest = ctx->traks + i;
		ctx->mixin.traksa[i]->dest = ctx->traks + i;
		if (mp4merge_co_trak_init(ctx->main.traksa[i], ctx->req->connection->log) != NGX_OK)
			return NGX_HTTP_NOT_FOUND;
		if (mp4merge_co_trak_init(ctx->mixin.traksa[i], ctx->req->connection->log) != NGX_OK)
			return NGX_HTTP_NOT_FOUND;
	}

	if (mp4merge_co_alloc_seg(ctx, ctx->main.traksa))
		return NGX_ERROR;
	if (mp4merge_co_alloc_seg(ctx, ctx->mixin.traksa))
		return NGX_ERROR;
	for (i = 0; i < ctx->trak_cnt; i++)
		ctx->main.traksa[i]->frame_end = -1;
	if (mp4merge_co_alloc_seg(ctx, ctx->main.traksa))
		return NGX_ERROR;
	for (i = 0; i < ctx->trak_cnt; i++)
		ctx->traks[i].stco->hdr.size = htobe32(sizeof(mp4_atom_stco_t) + ctx->traks[i].stco->chunk_cnt * (ctx->co64 ? 8 : 4));
	return NGX_OK;
}
static ngx_int_t mp4merge_do_open_file(ngx_open_file_info_t *of, ngx_file_t *f, ngx_http_core_loc_conf_t *clcf, ngx_http_request_t *r, ngx_str_t *name)
{
	ngx_uint_t level;
	ngx_int_t rc;
	of->read_ahead = clcf->read_ahead;
	of->valid = clcf->open_file_cache_valid;
	of->min_uses = clcf->open_file_cache_min_uses;
	of->errors = clcf->open_file_cache_errors;
	of->events = clcf->open_file_cache_events;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"mp4mux: open file: \"%V\"", name);
	if (ngx_open_cached_file(clcf->open_file_cache, name, of, r->pool) != NGX_OK)
	{
		switch (of->err) {

		case 0:
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		case NGX_ENOENT:
		case NGX_ENOTDIR:
		case NGX_ENAMETOOLONG:

			level = NGX_LOG_ERR;
			rc = NGX_HTTP_NOT_FOUND;
			break;

		case NGX_EACCES:

			level = NGX_LOG_ERR;
			rc = NGX_HTTP_FORBIDDEN;
			break;

		default:

			level = NGX_LOG_CRIT;
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			break;
		}

		if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
			ngx_log_error(level, r->connection->log, of->err,
				"%s \"%V\" failed", of->failed, name);
		}

		return rc;
	}

	if (!of->is_file) {

		if (ngx_close_file(of->fd) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
				ngx_close_file_n " \"%V\" failed", name);
		}

		return NGX_HTTP_NOT_FOUND;
	}
	f->fd = of->fd;
	f->name = *name;
	f->directio = of->is_directio;
	f->log = r->connection->log;
	return NGX_OK;
}
static ngx_int_t mp4_validate_trak(mp4_trak_t *t) {
	return (t->mdhd && t->tkhd && t->hdlr && t->stbl &&
		t->stsd && t->stsz && t->stts && t->stsc && t->stco) ? NGX_OK : NGX_ERROR;
}
static ngx_int_t mp4_validate_file(mp4_file_t *f) {
	mp4_trak_t *t;
	if (!f->mvhd)
		goto err;
	for (t = f->traksl; t; t = t->next)
		if (mp4_validate_trak(t) != NGX_OK)
			goto err;
	return NGX_OK;
err:
	ngx_log_error(NGX_LOG_ERR, f->file.log, 0,
		"mp4merge: \"%V\" is invalid", &f->fname);
	return NGX_HTTP_NOT_FOUND;
}
static ngx_int_t mp4merge_open_file(ngx_http_mp4merge_ctx_t *ctx, mp4_file_t *f)
{
	ngx_http_core_loc_conf_t *clcf;
	ngx_open_file_info_t      of;
	ngx_int_t rc;

	clcf = ngx_http_get_module_loc_conf(ctx->req, ngx_http_core_module);
	ngx_memzero(&of, sizeof(of));
	of.directio = clcf->directio;

	if ((rc = mp4merge_do_open_file(&of, &f->file, clcf, ctx->req, &f->fname)) != NGX_OK)
		return rc;

	f->file_size = of.size;
	f->file_mtime = of.mtime;

	MP4MUX_INIT_LIST_HEAD(&f->atoms);

	if ((rc = mp4_parse(ctx, f)) != NGX_OK)
		return rc;
	return mp4_validate_file(f);
}
static ngx_int_t mp4_add_primitive_atom(mp4mux_list_t *list, void *data, ngx_pool_t *pool) {
	mp4_atom_t *a = mp4_alloc_atom(pool, 0);
	if (!a) return NGX_ERROR;
	a->hdr = data;
	mp4mux_list_add_tail(&a->entry, list);
	return NGX_OK;
}

static char *
ngx_http_mp4merge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t  *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_mp4merge_handler;

	return NGX_CONF_OK;
}
static ngx_int_t mp4_atom_to_trak(mp4_atom_t *a, mp4_trak_t **tt, ngx_pool_t *pool) {
	mp4_trak_t *t = *tt;
	if (!t) {
		if (a->hdr->type == ATOM('t', 'r', 'a', 'k')) {
			if (!(*tt = ngx_pcalloc(pool, sizeof(mp4_trak_t))))
				return NGX_ERROR;
			(*tt)->trak = a;
		}
		return NGX_OK;
	}
	switch (a->hdr->type) {
	case ATOM('t', 'r', 'a', 'k'):
		ngx_log_error(NGX_LOG_ERR, pool->log, 0,
			  "mp4merge: nested trak atoms found!");
		return NGX_ERROR;
	case ATOM('t', 'k', 'h', 'd'):
		if (t->tkhd) return NGX_ERROR;
		t->tkhd = (mp4_atom_tkhd_t *)a->hdr;
		break;
	case ATOM('m', 'd', 'h', 'd'):
		if (t->mdhd) return NGX_ERROR;
		t->mdhd = (mp4_atom_mdhd_v0_t *)a->hdr;
		switch (((mp4_atom_mdhd_v0_t*)a->hdr)->version) {
		case 0:
			t->timescale  = be32toh(((mp4_atom_mdhd_v0_t*)a->hdr)->timescale);
			t->duration = be32toh(((mp4_atom_mdhd_v0_t*)a->hdr)->duration);
			break;
		case 1:
			t->timescale  = be32toh(((mp4_atom_mdhd_v1_t*)a->hdr)->timescale); break;
			t->duration = be64toh(((mp4_atom_mdhd_v1_t*)a->hdr)->duration);
		default:
			ngx_log_error(NGX_LOG_ERR, pool->log, 0,
				"mp4merge: invalid mdhd version");
			return NGX_ERROR;
		}
		break;
	case ATOM('h', 'd', 'l', 'r'):
		if (t->hdlr) return NGX_ERROR;
		t->hdlr = (mp4_atom_hdlr_t *)a->hdr;
		break;
	case ATOM('m', 'i', 'n', 'f'):
		if (t->minf) return NGX_ERROR;
		t->minf = a;
		break;
	case ATOM('s', 't', 'b', 'l'):
		if (t->stbl || !t->minf) return NGX_ERROR;
		t->stbl = a;
		break;
	case ATOM('s', 't', 's', 'd'):
		if (t->stsd || !t->stbl) return NGX_ERROR;
		t->stsd = (mp4_atom_stsd_t *)a->hdr;
		break;
	case ATOM('s', 't', 's', 'z'):
		if (t->stsz || !t->stbl) return NGX_ERROR;
		t->stsz = (mp4_atom_stsz_t *)a->hdr;
		break;
	case ATOM('c', 'o', '6', '4'):
		t->co64 = 1;
	case ATOM('s', 't', 'c', 'o'):
		if (t->co || !t->stbl) return NGX_ERROR;
		t->stco = (mp4_atom_stco_t *)a->hdr;
		break;
	case ATOM('s', 't', 's', 'c'):
		if (t->stsc || !t->stbl) return NGX_ERROR;
		t->stsc = (mp4_atom_stsc_t *)a->hdr;
		break;
	case ATOM('s', 't', 't', 's'):
		if (t->stts || !t->stbl) return NGX_ERROR;
		t->stts = (mp4_atom_xtts_t *)a->hdr;
		break;
	case ATOM('c', 't', 't', 's'):
		if (t->ctts || !t->stbl) return NGX_ERROR;
		t->ctts = (mp4_atom_xtts_t *)a->hdr;
		break;
	case ATOM('s', 't', 's', 's'):
		if (t->stss || !t->stbl) return NGX_ERROR;
		t->stss = (mp4_atom_stss_t *)a->hdr;
		break;
	}
	return NGX_OK;
}
static ngx_int_t mp4_parse_atom(ngx_pool_t *pool, mp4_file_t *mp4f, mp4_trak_t **trak, mp4_atom_t *atom)
{
	ngx_uint_t i;
	mp4_atom_hdr_t *hdr;
	off_t pos;
	uint32_t size, atom_size;
	char atom_name[5];

	atom_name[4] = 0;

	if (atom->hdr->type == ATOM('m', 'v', 'h', 'd')) {
		if (mp4f->mvhd)
			return NGX_ERROR;
		mp4f->mvhd = (mp4_atom_mvhd_t*)atom->hdr;
	}
	if (mp4_atom_to_trak(atom, trak, pool) != NGX_OK)
		return NGX_ERROR;

	for (i = 0; i < sizeof(mp4_atom_containers)/sizeof(mp4_atom_containers[0]); i++)
		if (atom->hdr->type == mp4_atom_containers[i]) {
			atom_size = be32toh(atom->hdr->size) - sizeof(*hdr);
			for (pos = 0; pos < atom_size; pos += size) {
				hdr = (mp4_atom_hdr_t *)(atom->hdr->u.data + pos);
				size = be32toh(hdr->size);
				if (hdr->type == ATOM('e', 'd', 't', 's'))
					continue;

				ngx_memcpy(atom_name, &hdr->type, 4);
				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->file.log, 0,
					"begin atom: %s %i", atom_name, size);

				if (size < 8) {
					ngx_log_error(NGX_LOG_ERR, mp4f->file.log, 0,
						"mp4mux: \"%V\": atom is too small:%uL",
						&mp4f->fname, size);
					return NGX_ERROR;
				}

				if (mp4_add_primitive_atom(&atom->atoms, hdr, pool) != NGX_OK)
					return NGX_ERROR;

				if (mp4_parse_atom(pool, mp4f, trak, mp4mux_list_entry(atom->atoms.prev, mp4_atom_t, entry))) {
					ngx_log_error(NGX_LOG_ERR, mp4f->file.log, 0,
						"mp4mux: \"%V\": error while parsing \"%s\" atom",
						&mp4f->fname, atom_name);
					return NGX_ERROR;
				}
				if (*trak && hdr->type == ATOM('t', 'r', 'a', 'k')) {
					(*trak)->file = mp4f;
					trak = &(*trak)->next;
				}

				ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4f->file.log, 0,
					"end atom: %s %i", atom_name, size);
			}
			return NGX_OK;
		}
	return NGX_OK;
}
static ngx_int_t mp4_parse(ngx_http_mp4merge_ctx_t *ctx, mp4_file_t *mp4f)
{
	mp4_atom_hdr_t hdr;
	mp4_atom_t *atom;
	size_t pos;
	uint32_t size;
	uint64_t size64;
	ngx_int_t n;
	char atom_name[5];

	atom_name[4] = 0;

	MP4MUX_INIT_LIST_HEAD(&mp4f->atoms);

	if (mp4f->file.directio)
		ngx_directio_off(mp4f->file.fd);

	for (pos = 0; pos < mp4f->file_size; pos += size) {
		n = ngx_read_file(&mp4f->file, (u_char *)&hdr, sizeof(hdr), pos);

		if (n == NGX_ERROR)
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		size = be32toh(hdr.size);

		memcpy(atom_name, &hdr.type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"begin atom: %s %i", atom_name, size);

		if (size == 1) {
			n = ngx_read_file(&mp4f->file, (u_char *)&size64, 8, pos + sizeof(hdr));
			if (n == NGX_ERROR)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			size64 = be64toh(size64);
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0, "size64 %L", size64);
		}

		if (size == 0) {
			size = mp4f->file_size - pos;
			hdr.size = htobe32(size);
		} else if (size != 1 && size < 8) {
			ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
				"mp4mux: \"%V\": atom is too small:%uL",
				&mp4f->fname, size);
			return NGX_HTTP_NOT_FOUND;
		}

		if (hdr.type == ATOM('m', 'd', 'a', 't')) {
			if (size == 1)
				pos += size64 - 1;
		} else if (hdr.type != ATOM('f', 'r', 'e', 'e')) {
			if (size == 1 || size > MAX_ATOM_SIZE) {
				ngx_log_error(NGX_LOG_ERR, ctx->req->connection->log, 0,
					"mp4mux: \"%V\": mp4 atom is too large:%uL",
					&mp4f->fname, size);
				return NGX_HTTP_NOT_FOUND;
			}

			atom = ngx_pcalloc(ctx->req->pool, sizeof(*atom) + size);
			if (!atom)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;

			ngx_memcpy(atom->data, &hdr, sizeof(hdr));

			n = ngx_read_file(&mp4f->file, (u_char*)atom->data + sizeof(hdr), size - sizeof(hdr), pos + sizeof(hdr));
			if (n == NGX_ERROR)
				return NGX_HTTP_INTERNAL_SERVER_ERROR;

			atom->hdr = (mp4_atom_hdr_t *)atom->data;

			MP4MUX_INIT_LIST_HEAD(&atom->atoms);
			mp4mux_list_add_tail(&atom->entry, &mp4f->atoms);

			if (mp4_parse_atom(ctx->req->pool, mp4f, &mp4f->traksl, atom))
				return NGX_HTTP_NOT_FOUND;
		}
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"end atom: %s %i", atom_name, size);
	}

	if (mp4f->file.directio)
		ngx_directio_on(mp4f->file.fd);

	mp4mux_list_for_each_entry(atom, &mp4f->atoms, entry) {
		memcpy(atom_name, &atom->hdr->type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"atom: %s %i", atom_name, be32toh(atom->hdr->size));
	}

	return NGX_OK;
}
static mp4_atom_t *mp4_clone_primitive_atom(mp4_atom_hdr_t *hdr, ngx_pool_t *pool) {
	mp4_atom_t *anew;
	char atom_name[5] = {0,0,0,0,0};

	memcpy(atom_name, &hdr->type, 4);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
		"clone atom: %s ", atom_name);

	if (!(anew = mp4_alloc_atom(pool, 0)))
		return NULL;

	anew->hdr = hdr;
	return anew;
}
static mp4_atom_t *mp4_clone_atom(mp4_atom_t *atom, mp4_trak_output_t *dst_trak, ngx_pool_t *pool)
{
	mp4_atom_t *anew, *asub, *nsub;

	if (!(anew = mp4_clone_primitive_atom(atom->hdr, pool)))
		return NULL;

	mp4mux_list_for_each_entry(asub, &atom->atoms, entry) {
		switch(asub->hdr->type) {
		case ATOM('t', 'r', 'a', 'k'):
		case ATOM('s', 't', 's', 'z'):
		case ATOM('s', 't', 't', 's'):
		case ATOM('s', 't', 's', 's'):
		case ATOM('s', 't', 's', 'd'):
		case ATOM('c', 't', 't', 's'):
		case ATOM('s', 't', 'c', 'o'):
		case ATOM('c', 'o', '6', '4'):
		case ATOM('s', 't', 's', 'c'):
		case ATOM('s', 'd', 't', 'p'):
			continue;
		}

		if (!(nsub = mp4_clone_atom(asub, dst_trak, pool)))
			return NULL;
		mp4mux_list_add_tail(&nsub->entry, &anew->atoms);
		if (dst_trak)
			switch(asub->hdr->type) {
			case ATOM('s', 't', 'b', 'l'): dst_trak->stbl = nsub; break;
			case ATOM('m', 'd', 'h', 'd'): dst_trak->mdhd = nsub; break;
			}
	}

	return anew;
}

static off_t mp4_build_atoms(mp4mux_list_t *list, ngx_log_t *log)
{
	off_t len = 0, n;
	mp4_atom_t *a;
	char atom_name[5] = {0,0,0,0,0};

	mp4mux_list_for_each_entry(a, list, entry) {
		memcpy(atom_name, &a->hdr->type, 4);

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
			"build atom: %s", atom_name);

		if (mp4mux_list_empty(&a->atoms))
			len += be32toh(a->hdr->size);
		else {
			n = (off_t)sizeof(mp4_atom_hdr_t) + mp4_build_atoms(&a->atoms, log);
			a->hdr->size = htobe32(n);
			len += n;
		}
	}

	return len;
}

static ngx_int_t mp4_build_chain_ex(ngx_http_mp4merge_ctx_t *ctx, mp4mux_list_t *list, ngx_chain_t **out, ngx_chain_t **last)
{
	mp4_atom_t *a;
	ngx_chain_t *tl;
	ngx_buf_t *b;
	char atom_name[5] = {0,0,0,0,0};

	mp4mux_list_for_each_entry(a, list, entry) {
		tl = ngx_alloc_chain_link(ctx->req->pool);//ngx_chain_get_free_buf(ctx->req->pool, &ctx->free);
		if (!tl) {
			return NGX_ERROR;
		}
		tl->next = NULL;
		if (!(tl->buf = ngx_calloc_buf(ctx->req->pool)))
			return NGX_ERROR;

		b = tl->buf;
		b->in_file = 0;
		b->memory = 1;
		b->flush = 0;
		b->start = (u_char *)a->hdr;
		b->pos = b->start;
		if (mp4mux_list_empty(&a->atoms) && a->hdr->type != ATOM('m', 'd', 'a', 't'))
			b->end = (u_char *)a->hdr + be32toh(a->hdr->size);
		else
			b->end = (u_char *)a->hdr + sizeof(mp4_atom_hdr_t) + ((be32toh(a->hdr->size) == 1 ? 8 : 0));
		b->last = b->end;

		memcpy(atom_name, &a->hdr->type, 4);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->req->connection->log, 0,
			"build_chain: %s %i", atom_name, ngx_buf_size(b));

		b->tag = (ngx_buf_tag_t) &ngx_http_mp4merge_module;

		if (*out)
			(*last)->next = tl;
		else
			*out = tl;
		*last = tl;

		if (!mp4mux_list_empty(&a->atoms)) {
			if (mp4_build_chain_ex(ctx, &a->atoms, out, last))
				return NGX_ERROR;
		}
	}

	return NGX_OK;
}

static ngx_chain_t *mp4_build_chain(ngx_http_mp4merge_ctx_t *ctx, mp4mux_list_t *list)
{
	ngx_chain_t *out = NULL, *last = NULL;

	if (mp4_build_chain_ex(ctx, list, &out, &last) != NGX_OK)
		return NULL;

	last->buf->flush = 1;

	return out;
}

static void *ngx_http_mp4merge_create_conf(ngx_conf_t *cf)
{
	   ngx_http_mp4merge_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mp4merge_conf_t));
	if (conf == NULL)
		return NULL;
	conf->move_meta = NGX_CONF_UNSET;

	return conf;
}

static char *ngx_http_mp4merge_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_mp4merge_conf_t *prev = parent;
	ngx_http_mp4merge_conf_t *conf = child;
	ngx_conf_merge_value(conf->move_meta, prev->move_meta, 1);

	return NGX_CONF_OK;
}
