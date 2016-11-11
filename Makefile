all: detect_black ngx_http_mp4merge_module.o
detect_black: CFLAGS=-g
detect_black: LDLIBS=-lavcodec -lavutil
detect_black: detect_black.c
detect_black.c: mp4.h

ngx_http_mp4merge_module.o: CFLAGS= -I../nginx/src/core/ -I../nginx/src/os/unix/ -I../nginx/src/http/ -I../nginx/src/http/modules/ -I../nginx/src/event/ -I../nginx/objs/
ngx_http_mp4merge_module.o: ngx_http_mp4merge_module.c
ngx_http_mp4merge_module.c: mp4.h
