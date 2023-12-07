/*
 * buffered I/O
 * Copyright (c) 2000,2001 Fabrice Bellard
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libavutil/bprint.h"
#include "libavutil/crc.h"
#include "libavutil/dict.h"
#include "libavutil/internal.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/log.h"
#include "libavutil/opt.h"
#include "libavutil/avassert.h"
#include "libavcodec/defs.h"
#include "avio.h"
#include "avio_internal.h"
#include "internal.h"
#include "url.h"
#include <stdarg.h>

#define IO_BUFFER_SIZE 32768

/**
 * Do seeks within this distance ahead of the current buffer by skipping
 * data instead of calling the protocol seek function, for seekable
 * protocols.
 */
#define SHORT_SEEK_THRESHOLD 32768

static void *ff_avio_child_next(void *obj, void *prev)
{
    AVIOContext *s = obj;
    return prev ? NULL : s->opaque;
}

static const AVClass *child_class_iterate(void **iter)
{
    const AVClass *c = *iter ? NULL : &ffurl_context_class;
    *iter = (void*)(uintptr_t)c;
    return c;
}

#define OFFSET(x) offsetof(AVIOContext,x)
#define E AV_OPT_FLAG_ENCODING_PARAM
#define D AV_OPT_FLAG_DECODING_PARAM
static const AVOption ff_avio_options[] = {
    {"protocol_whitelist", "List of protocols that are allowed to be used", OFFSET(protocol_whitelist), AV_OPT_TYPE_STRING, { .str = NULL },  0, 0, D },
    { NULL },
};

const AVClass ff_avio_class = {
    .class_name = "AVIOContext",
    .item_name  = av_default_item_name,
    .version    = LIBAVUTIL_VERSION_INT,
    .option     = ff_avio_options,
    .child_next = ff_avio_child_next,
    .child_class_iterate = child_class_iterate,
};

static void fill_buffer(AVIOContext *s);
static int url_resetbuf(AVIOContext *s, int flags);
/** @warning must be called before any I/O */
static int set_buf_size(AVIOContext *s, int buf_size);

void ffio_init_context(FFIOContext *ctx,
                  unsigned char *buffer,
                  int buffer_size,
                  int write_flag,
                  void *opaque,
                  int (*read_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int (*write_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int64_t (*seek)(void *opaque, int64_t offset, int whence))
{
    AVIOContext *const s = &ctx->pub;

    memset(ctx, 0, sizeof(*ctx));

    s->buffer      = buffer; //@wss add；指向buffer的指针，该成员持有当前使用的缓冲区，该缓冲区有可能会被其它缓冲区替换掉，但是buffer成员一定指向当前有效的缓冲区
    ctx->orig_buffer_size = //@wss add:缓冲区原始大小，此处设置为buffer_size，作用在于进行文件格式探测时，buffer_size大小会改变，文件格式探测结束后需要恢复原始的缓冲区大小，那么.orig_buffer_size就起作用了，因为其保存着该原始值。
    s->buffer_size = buffer_size; //@wss add:缓冲区大小
    s->buf_ptr     = buffer; //@wss add:buffer中的当前位置，在读写中均起作用
    s->buf_ptr_max = buffer; //@wss add:仅作用在写过程，保存着缓存中已经处理过的数据的位置，调用flush函数将使得buffer指针到buffer_ptr_max之前的内容被从缓冲区flush掉
    s->opaque      = opaque; //@wss add:在avio_read调用中，此处是文件数据
    s->direct      = 0;

    url_resetbuf(s, write_flag ? AVIO_FLAG_WRITE : AVIO_FLAG_READ);

    s->write_packet    = write_packet;
    s->read_packet     = read_packet;
    s->seek            = seek;
    s->pos             = 0;
    s->eof_reached     = 0;
    s->error           = 0;
    s->seekable        = seek ? AVIO_SEEKABLE_NORMAL : 0;
    s->min_packet_size = 0;
    s->max_packet_size = 0;
    s->update_checksum = NULL;
    ctx->short_seek_threshold = SHORT_SEEK_THRESHOLD;

    if (!read_packet && !write_flag) {
        s->pos     = buffer_size;
        s->buf_end = s->buffer + buffer_size;
    }
    s->read_pause = NULL;
    s->read_seek  = NULL;

    s->write_data_type       = NULL;
    s->ignore_boundary_point = 0;
    ctx->current_type        = AVIO_DATA_MARKER_UNKNOWN;
    ctx->last_time           = AV_NOPTS_VALUE;
    ctx->short_seek_get      = NULL;
#if FF_API_AVIOCONTEXT_WRITTEN
FF_DISABLE_DEPRECATION_WARNINGS
    s->written               = 0;
FF_ENABLE_DEPRECATION_WARNINGS
#endif
}

AVIOContext *avio_alloc_context(
                  unsigned char *buffer,
                  int buffer_size,
                  int write_flag,
                  void *opaque,
                  int (*read_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int (*write_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int64_t (*seek)(void *opaque, int64_t offset, int whence))
{
    FFIOContext *s = av_malloc(sizeof(*s));
    if (!s)
        return NULL;
    ffio_init_context(s, buffer, buffer_size, write_flag, opaque,
                  read_packet, write_packet, seek); //@wss add:给s->pub(AVIOontext)赋值
    return &s->pub;
}

void avio_context_free(AVIOContext **ps)
{
    av_freep(ps);
}

static void writeout(AVIOContext *s, const uint8_t *data, int len)
{
    FFIOContext *const ctx = ffiocontext(s);
    if (!s->error) {
        int ret = 0;
        if (s->write_data_type)
            ret = s->write_data_type(s->opaque, (uint8_t *)data,
                                     len,
                                     ctx->current_type,
                                     ctx->last_time);
        else if (s->write_packet)
            ret = s->write_packet(s->opaque, (uint8_t *)data, len);
        if (ret < 0) {
            s->error = ret;
        } else {
            ctx->bytes_written += len;
            s->bytes_written = ctx->bytes_written;

            if (s->pos + len > ctx->written_output_size) {
                ctx->written_output_size = s->pos + len;
#if FF_API_AVIOCONTEXT_WRITTEN
FF_DISABLE_DEPRECATION_WARNINGS
                s->written = ctx->written_output_size;
FF_ENABLE_DEPRECATION_WARNINGS
#endif
            }
        }
    }
    if (ctx->current_type == AVIO_DATA_MARKER_SYNC_POINT ||
        ctx->current_type == AVIO_DATA_MARKER_BOUNDARY_POINT) {
        ctx->current_type = AVIO_DATA_MARKER_UNKNOWN;
    }
    ctx->last_time = AV_NOPTS_VALUE;
    ctx->writeout_count++;
    s->pos += len;
}

static void flush_buffer(AVIOContext *s)
{
    s->buf_ptr_max = FFMAX(s->buf_ptr, s->buf_ptr_max);
    if (s->write_flag && s->buf_ptr_max > s->buffer) {
        writeout(s, s->buffer, s->buf_ptr_max - s->buffer);
        if (s->update_checksum) {
            s->checksum     = s->update_checksum(s->checksum, s->checksum_ptr,
                                                 s->buf_ptr_max - s->checksum_ptr);
            s->checksum_ptr = s->buffer;
        }
    }
    s->buf_ptr = s->buf_ptr_max = s->buffer;
    if (!s->write_flag)
        s->buf_end = s->buffer;
}

void avio_w8(AVIOContext *s, int b)
{
    av_assert2(b>=-128 && b<=255);
    *s->buf_ptr++ = b;
    if (s->buf_ptr >= s->buf_end)
        flush_buffer(s);
}

void ffio_fill(AVIOContext *s, int b, int64_t count)
{
    while (count > 0) {
        int len = FFMIN(s->buf_end - s->buf_ptr, count);
        memset(s->buf_ptr, b, len);
        s->buf_ptr += len;

        if (s->buf_ptr >= s->buf_end)
            flush_buffer(s);

        count -= len;
    }
}

void avio_write(AVIOContext *s, const unsigned char *buf, int size)
{
    if (size <= 0)
        return;
    if (s->direct && !s->update_checksum) {
        avio_flush(s);
        writeout(s, buf, size);
        return;
    }
    do {
        int len = FFMIN(s->buf_end - s->buf_ptr, size);
        memcpy(s->buf_ptr, buf, len);
        s->buf_ptr += len;

        if (s->buf_ptr >= s->buf_end)
            flush_buffer(s);

        buf += len;
        size -= len;
    } while (size > 0);
}

void avio_flush(AVIOContext *s)
{
    int seekback = s->write_flag ? FFMIN(0, s->buf_ptr - s->buf_ptr_max) : 0;
    flush_buffer(s);
    if (seekback)
        avio_seek(s, seekback, SEEK_CUR);
}

/*
    1.计算并返回按指定方式seek后，最终文件当前偏移量；
    2.保证最终的文件偏移量在AVIOContext内部缓冲区的覆盖范围内；
    3.保证AVIOContext中关于缓冲区的相关指针都正确赋值，尤其是s->buf_ptr指向"最终文件当前偏移量"在内部缓冲区的对应位置点；
*/
int64_t avio_seek(AVIOContext *s, int64_t offset, int whence)
{
    FFIOContext *const ctx = ffiocontext(s);
    int64_t offset1;
    int64_t pos;
    int force = whence & AVSEEK_FORCE;
    int buffer_size;
    int short_seek;
    whence &= ~AVSEEK_FORCE;

    if(!s) //@wss add:检查参数
        return AVERROR(EINVAL);

    if ((whence & AVSEEK_SIZE)) //@wss add:设置了AVSEEK_SIZE标志 应该是标志是否执行调用者定义的seek函数
        return s->seek ? s->seek(s->opaque, offset, AVSEEK_SIZE) : AVERROR(ENOSYS);
    //@wss add:读{buffer_size = 缓冲区中已消费数据 + 已读取等待被消费的数据}   写{buffer_size = 缓冲区中已被写入的数据 + 还可以被写入缓冲的数据}
    buffer_size = s->buf_end - s->buffer; //@wss add:此处buf_end,buffer定义，导到参数定义处观看一目了然
    // pos is the absolute position that the beginning of s->buffer corresponds to in the file
    pos = s->pos - (s->write_flag ? 0 : buffer_size); //@wss add:临时变量pos求取的是内部缓冲起始位置s->buffer对应文件中的位置

    if (whence != SEEK_CUR && whence != SEEK_SET) //@wss add:检查参数有效性
        return AVERROR(EINVAL);

    if (whence == SEEK_CUR) { //@wss add:如果是从当前位置计算seek，那么需要计算缓冲区当前所处理数据点，相对于文件的位置 即s->buf_ptr指针所对应的文件中位置
        offset1 = pos + (s->buf_ptr - s->buffer); //@wss add:计算offset1为s->buf_ptr指针所对应的文件中位置
        if (offset == 0) //@wss add:若输入偏移为0，直接返回offset1即可，内部缓冲的所有指针可不变动
            return offset1;
        if (offset > INT64_MAX - offset1) //@wss add:若输入偏移大于还可以进行的最大偏移，则输入偏移越界，返回错误信息
            return AVERROR(EINVAL);
        offset += offset1; //@wss add:计算出以当前偏移点为基础，最终对应的文件的偏移位置
    }
    if (offset < 0) //@wss add:若偏移<0,输入偏移参数越界，返回错误信息
        return AVERROR(EINVAL);
    //@wss add:计算跳转阈值 s->short_seek_get在ffio_fdopen函数创建AVIOContext对象时被赋值为io_short_seek函数，而s->short_seek_threshold被赋值为SHORT_SEEK_THREAD常量4096
    short_seek = ctx->short_seek_threshold;
    if (ctx->short_seek_get) {
        int tmp = ctx->short_seek_get(s->opaque);
        short_seek = FFMAX(tmp, short_seek);
    }
    //@wss add:计算offset1是目的offset与缓冲区首地址所对应偏移量之差
    offset1 = offset - pos; // "offset1" is the relative offset from the beginning of s->buffer
    s->buf_ptr_max = FFMAX(s->buf_ptr_max, s->buf_ptr); //@wss add:取两者较大值，由于有可能往前seek，向后seek导致s->buf_ptr变动
    //@wss add:下面是分类处理seek的各种情况
    //@wss add:情形1，读写，往前seek，不支持在文件中直接seek，文件偏移位置在buffer缓冲区有效范围以内(读:已读取的数据范围内，写:缓冲区大小范围内) 只需修改s->buf_ptr指针即可
    if ((!s->direct || !s->seek) &&
        offset1 >= 0 && offset1 <= (s->write_flag ? s->buf_ptr_max - s->buffer : buffer_size)) {
        /* can do the seek inside the buffer */
        s->buf_ptr = s->buffer + offset1;
    } else if ((!(s->seekable & AVIO_SEEKABLE_NORMAL) ||
               offset1 <= buffer_size + short_seek) &&
               !s->write_flag && offset1 >= 0 &&
               (!s->direct || !s->seek) &&
              (whence != SEEK_END || force)) {  //@wss add:情形2，读，往前seek，不支持在文件中直接seek，文件最终偏移不在当前缓冲区有效范围内，那么只能循环fill_buffer从文件读取数据到缓冲区，一直到目标偏移量offset在缓冲区内后，停止数据读取，修改s->buf_ptr指针
        while(s->pos < offset && !s->eof_reached)
            fill_buffer(s);
        if (s->eof_reached)
            return AVERROR_EOF;
        s->buf_ptr = s->buf_end - (s->pos - offset);
    } else if(!s->write_flag && offset1 < 0 && -offset1 < buffer_size>>1 && s->seek && offset > 0) { //@wss add:情形3，读，往后seek，往后seek大小小于buffer_size一半，支持在文件中直接seek，此时将保持缓冲区含有有效数据，修改s->buf_ptr指针指向offset对应位置
        int64_t res;

        pos -= FFMIN(buffer_size>>1, pos); //@wss add:计算直接seek后，缓冲起始位置对应的文件中的pos
        if ((res = s->seek(s->opaque, pos, SEEK_SET)) < 0) //@wss add:实际的文件seek
            return res;
        s->buf_end =
        s->buf_ptr = s->buffer;
        s->pos = pos;
        s->eof_reached = 0;
        fill_buffer(s); //@wss add:初始化所有指针，然后使用fill_buffer来读取数据填充内部缓冲
        return avio_seek(s, offset, SEEK_SET | force); //@wss add:递归调用avio_seek，下一步将进入情形1中修改buf_ptr指针
    } else { //@wss add:情形4，读写，支持文件中直接seek，此时，缓冲区中最终将不含有有效数据，修改s->buf_ptr指向缓冲区的起始位置，起始位置即为offset位置
        int64_t res;
        if (s->write_flag) {
            flush_buffer(s); //@wss add:写，先将缓冲区的有效数据写入文件
        }
        if (!s->seek) //@wss add:不存在seek函数，返回错误
            return AVERROR(EPIPE);
        if ((res = s->seek(s->opaque, offset, SEEK_SET)) < 0) //@wss add:直接在文件中seek，注意与情形3中seek函数设置的偏移量不同
            return res;
        ctx->seek_count++;
        if (!s->write_flag) //@wss add:设置缓冲区内部指针
            s->buf_end = s->buffer;
        s->buf_ptr = s->buf_ptr_max = s->buffer;
        s->pos = offset;
    }
    s->eof_reached = 0;
    return offset;
}

int64_t avio_skip(AVIOContext *s, int64_t offset)
{
    return avio_seek(s, offset, SEEK_CUR);
}

int64_t avio_size(AVIOContext *s)
{
    FFIOContext *const ctx = ffiocontext(s);
    int64_t size;

    if (!s)
        return AVERROR(EINVAL);

    if (ctx->written_output_size)
        return ctx->written_output_size;

    if (!s->seek)
        return AVERROR(ENOSYS);
    size = s->seek(s->opaque, 0, AVSEEK_SIZE);
    if (size < 0) {
        if ((size = s->seek(s->opaque, -1, SEEK_END)) < 0)
            return size;
        size++;
        s->seek(s->opaque, s->pos, SEEK_SET);
    }
    return size;
}

int avio_feof(AVIOContext *s)
{
    if(!s)
        return 0;
    if(s->eof_reached){
        s->eof_reached=0;
        fill_buffer(s);
    }
    return s->eof_reached;
}

void avio_wl32(AVIOContext *s, unsigned int val)
{
    avio_w8(s, (uint8_t) val       );
    avio_w8(s, (uint8_t)(val >> 8 ));
    avio_w8(s, (uint8_t)(val >> 16));
    avio_w8(s,           val >> 24 );
}

void avio_wb32(AVIOContext *s, unsigned int val)
{
    avio_w8(s,           val >> 24 );
    avio_w8(s, (uint8_t)(val >> 16));
    avio_w8(s, (uint8_t)(val >> 8 ));
    avio_w8(s, (uint8_t) val       );
}

int avio_put_str(AVIOContext *s, const char *str)
{
    int len = 1;
    if (str) {
        len += strlen(str);
        avio_write(s, (const unsigned char *) str, len);
    } else
        avio_w8(s, 0);
    return len;
}

static inline int put_str16(AVIOContext *s, const char *str, const int be)
{
    const uint8_t *q = str;
    int ret = 0;
    int err = 0;

    while (*q) {
        uint32_t ch;
        uint16_t tmp;

        GET_UTF8(ch, *q++, goto invalid;)
        PUT_UTF16(ch, tmp, be ? avio_wb16(s, tmp) : avio_wl16(s, tmp);
                  ret += 2;)
        continue;
invalid:
        av_log(s, AV_LOG_ERROR, "Invalid UTF8 sequence in avio_put_str16%s\n", be ? "be" : "le");
        err = AVERROR(EINVAL);
        if (!*(q-1))
            break;
    }
    if (be)
        avio_wb16(s, 0);
    else
        avio_wl16(s, 0);
    if (err)
        return err;
    ret += 2;
    return ret;
}

#define PUT_STR16(type, big_endian)                          \
int avio_put_str16 ## type(AVIOContext *s, const char *str)  \
{                                                            \
return put_str16(s, str, big_endian);                        \
}

PUT_STR16(le, 0)
PUT_STR16(be, 1)

#undef PUT_STR16

void avio_wl64(AVIOContext *s, uint64_t val)
{
    avio_wl32(s, (uint32_t)(val & 0xffffffff));
    avio_wl32(s, (uint32_t)(val >> 32));
}

void avio_wb64(AVIOContext *s, uint64_t val)
{
    avio_wb32(s, (uint32_t)(val >> 32));
    avio_wb32(s, (uint32_t)(val & 0xffffffff));
}

void avio_wl16(AVIOContext *s, unsigned int val)
{
    avio_w8(s, (uint8_t)val);
    avio_w8(s, (int)val >> 8);
}

void avio_wb16(AVIOContext *s, unsigned int val)
{
    avio_w8(s, (int)val >> 8);
    avio_w8(s, (uint8_t)val);
}

void avio_wl24(AVIOContext *s, unsigned int val)
{
    avio_wl16(s, val & 0xffff);
    avio_w8(s, (int)val >> 16);
}

void avio_wb24(AVIOContext *s, unsigned int val)
{
    avio_wb16(s, (int)val >> 8);
    avio_w8(s, (uint8_t)val);
}

void avio_write_marker(AVIOContext *s, int64_t time, enum AVIODataMarkerType type)
{
    FFIOContext *const ctx = ffiocontext(s);
    if (type == AVIO_DATA_MARKER_FLUSH_POINT) {
        if (s->buf_ptr - s->buffer >= s->min_packet_size)
            avio_flush(s);
        return;
    }
    if (!s->write_data_type)
        return;
    // If ignoring boundary points, just treat it as unknown
    if (type == AVIO_DATA_MARKER_BOUNDARY_POINT && s->ignore_boundary_point)
        type = AVIO_DATA_MARKER_UNKNOWN;
    // Avoid unnecessary flushes if we are already in non-header/trailer
    // data and setting the type to unknown
    if (type == AVIO_DATA_MARKER_UNKNOWN &&
        (ctx->current_type != AVIO_DATA_MARKER_HEADER &&
         ctx->current_type != AVIO_DATA_MARKER_TRAILER))
        return;

    switch (type) {
    case AVIO_DATA_MARKER_HEADER:
    case AVIO_DATA_MARKER_TRAILER:
        // For header/trailer, ignore a new marker of the same type;
        // consecutive header/trailer markers can be merged.
        if (type == ctx->current_type)
            return;
        break;
    }

    // If we've reached here, we have a new, noteworthy marker.
    // Flush the previous data and mark the start of the new data.
    avio_flush(s);
    ctx->current_type = type;
    ctx->last_time = time;
}

static int read_packet_wrapper(AVIOContext *s, uint8_t *buf, int size)
{
    int ret;

    if (!s->read_packet)
        return AVERROR(EINVAL);
    ret = s->read_packet(s->opaque, buf, size);//@wss add:s->opaque存储读取的文件数据，read_packet函数是协议自己定义的读取函数
    av_assert2(ret || s->max_packet_size);
    return ret;
}

/* Input stream */

static void fill_buffer(AVIOContext *s)
{
    FFIOContext *const ctx = (FFIOContext *)s;
    int max_buffer_size = s->max_packet_size ?
                          s->max_packet_size : IO_BUFFER_SIZE; //@wss add:获取最大buffer大小
    /*@wss add: 要读取数据存入的缓存起始点，为啥不直接就是s->buf_end？
                取值为s->buf_end的场景：当前缓冲区大小s->buffer_size非常大，达到从s->buf_end开始到往后的区域内比max_buffer_size还大
                取值为s->buffer的场景：当前缓冲区并非特别大时，直接读取数据到缓冲区开始位置
                需要理解一点是调用fill_buffer函数的前提是AVIOContext内部缓冲区的所有数据都已被消费完，否则将dst设为s->buffer这点就不好理解
    */
    uint8_t *dst        = s->buf_end - s->buffer + max_buffer_size <= s->buffer_size ?
                          s->buf_end : s->buffer;
    int len             = s->buffer_size - (dst - s->buffer); //@wss add:尧都区数据的长度

    /* can't fill the buffer without read_packet, just set EOF if appropriate */
    if (!s->read_packet && s->buf_ptr >= s->buf_end) //@wss add:判断是否可以继续读取数据
        s->eof_reached = 1;

    /* no need to do anything if EOF already reached */
    if (s->eof_reached)
        return;
    //@wss add:更新校验和
    if (s->update_checksum && dst == s->buffer) { //@wss add:此处计算校验和时机是在dst == s->buffer时,原因是如果此时还不更新校验和，读取的数据把AVIOContext内部的数据冲掉，后续检验和更新就会有问题
        if (s->buf_end > s->checksum_ptr)
            s->checksum = s->update_checksum(s->checksum, s->checksum_ptr,
                                             s->buf_end - s->checksum_ptr); //@wss add:检验和更新，传入的参数包括之前的校验和值，参与检验和计算的起始位置，参与检验和计算的数据长度
        s->checksum_ptr = s->buffer; //@wss add:更新校验和后，更新检验和指针，以便指向下次参与检验和更新的缓冲起始位置
    }
    //@wss add:如果因为格式探测扩展了缓冲区，那么此处先将缓冲区缩回到orig_buffer_size
    /* make buffer smaller in case it ended up large after probing */
    if (s->read_packet && ctx->orig_buffer_size &&
        s->buffer_size > ctx->orig_buffer_size  && len >= ctx->orig_buffer_size) {
        if (dst == s->buffer && s->buf_ptr != dst) {
            int ret = set_buf_size(s, ctx->orig_buffer_size);
            if (ret < 0)
                av_log(s, AV_LOG_WARNING, "Failed to decrease buffer size\n");

            s->checksum_ptr = dst = s->buffer;
        }
        len = ctx->orig_buffer_size;
    }

    len = read_packet_wrapper(s, dst, len); //@wss add:读数据，只读一次，读取len字节到dst指向的缓冲区，所以此处buf_end+len
    if (len == AVERROR_EOF) { //@wss add:读到eof，设置标志位
        /* do not modify buffer if EOF reached so that a seek back can
           be done without rereading data */
        s->eof_reached = 1;
    } else if (len < 0) { //@wss add:读取出错，设置标志位
        s->eof_reached = 1;
        s->error= len;
    } else { //@wss add:正常读取数据，更新内部缓冲区指针
        s->pos += len;
        s->buf_ptr = dst;
        s->buf_end = dst + len;
        ffiocontext(s)->bytes_read += len;
        s->bytes_read = ffiocontext(s)->bytes_read;
    }
}

unsigned long ff_crc04C11DB7_update(unsigned long checksum, const uint8_t *buf,
                                    unsigned int len)
{
    return av_crc(av_crc_get_table(AV_CRC_32_IEEE), checksum, buf, len);
}

unsigned long ff_crcEDB88320_update(unsigned long checksum, const uint8_t *buf,
                                    unsigned int len)
{
    return av_crc(av_crc_get_table(AV_CRC_32_IEEE_LE), checksum, buf, len);
}

unsigned long ff_crcA001_update(unsigned long checksum, const uint8_t *buf,
                                unsigned int len)
{
    return av_crc(av_crc_get_table(AV_CRC_16_ANSI_LE), checksum, buf, len);
}

unsigned long ffio_get_checksum(AVIOContext *s)
{
    s->checksum = s->update_checksum(s->checksum, s->checksum_ptr,
                                     s->buf_ptr - s->checksum_ptr);
    s->update_checksum = NULL;
    return s->checksum;
}

void ffio_init_checksum(AVIOContext *s,
                   unsigned long (*update_checksum)(unsigned long c, const uint8_t *p, unsigned int len),
                   unsigned long checksum)
{
    s->update_checksum = update_checksum;
    if (s->update_checksum) {
        s->checksum     = checksum;
        s->checksum_ptr = s->buf_ptr;
    }
}

/* XXX: put an inline version */
int avio_r8(AVIOContext *s)
{
    if (s->buf_ptr >= s->buf_end)
        fill_buffer(s);
    if (s->buf_ptr < s->buf_end)
        return *s->buf_ptr++;
    return 0;
}

int avio_read(AVIOContext *s, unsigned char *buf, int size)
{
    int len, size1;

    size1 = size; //@wss add:size1记录要读取的字节数
    while (size > 0) { //@wss add:size记录还需要读取的字节数
        len = FFMIN(s->buf_end - s->buf_ptr, size); //@wss add:len记录本地可读取的字节数或者还需要读取的字节数
        if (len == 0 || s->write_flag) { //@wss add:没有数据，或者缓冲区可写(判断缓冲区是否可写的原因是因为AVIOContext的缓冲区是读写复用的，在写的时候缓冲区相关字段有不同含义，要做区分)
            if((s->direct || size > s->buffer_size) && !s->update_checksum && s->read_packet) { //@wss add:如果direct标志置位，或者要读取的字节大小比缓冲区大小还大，并且不存在更新数据校验和的函数(用于验证数据是否正确，传输中是否被篡改)，并且read_packet函数可用，直接读取数据到目标缓冲区
                // bypass the buffer and read data directly into buf
                len = read_packet_wrapper(s, buf, size); //@wss add:绕过AVIOContext缓冲区，直接读size数据到目标缓冲区buf，当传入的size参数为0时，返回AVERROR_EOF
                if (len == AVERROR_EOF) { //@wss add:读取数据长度匹配文件尾
                    /* do not modify buffer if EOF reached so that a seek back can
                    be done without rereading data */
                    s->eof_reached = 1;
                    break; //@wss add:注意这里退出条件
                } else if (len < 0) { //@wss add:读取数据长度 < 0，出错eof标志位置位
                    s->eof_reached = 1;
                    s->error= len;
                    break;
                } else { //@wss add:读取数据正确 因为没有把数据读取到AVIOContext内部缓冲区，但是从文件中读取数据是真实存在的，因此，pos和bytes_read这两个字段必须要修改
                    s->pos += len; //@wss add:AVIOContext.pos表征文件中的偏移，+=len
                    ffiocontext(s)->bytes_read += len; //@wss add:AVIOContext.bytes_read表征已经从文件中读取的字节数，+=len
                    s->bytes_read = ffiocontext(s)->bytes_read;
                    size -= len; //@wss add:还需读取数据，-=len，size持续更新
                    buf += len; //@wss add:移动目标缓冲区指针
                    // reset the buffer
                    s->buf_ptr = s->buffer; //@wss add:重置内部buffer的指针
                    s->buf_end = s->buffer/* + len*/; //@wss add:没+len的原因可能是在while结束时能一直走此处流程
                }
            } else {
                fill_buffer(s); //@wss add:如果size小或者其他不满足上述条件情况，先做一些参数设置，再读数据填充AVIOContext内部缓冲区
                len = s->buf_end - s->buf_ptr;
                if (len == 0) //@wss add:如果没有读取到数据则退出循环，此处退出意味着读取到的字节数可能小于期望的字节数
                    break;
            }
        } else { //@wss add:AVIOContext可读取len字节
            memcpy(buf, s->buf_ptr, len); //@wss add:从该内部缓冲区直接读取len个字节copy到目标缓冲区
            buf += len; //@wss add:修改目标缓冲区指针
            s->buf_ptr += len; //@wss add:修改内部缓冲区指针
            size -= len; //@wss add:修改size为剩余需要读取的字节数
        }
    }
    if (size1 == size) { //@wss add:没有读到数据 有三种情况，均发生在第一次循环读取内部缓冲区为0的情况 1.read_packet_wrapper返回AVERROR_EOF；2.read_packet_wrapper返回负值；3.fill_buffer也没读到数据到内部缓冲；
        if (s->error)      return s->error;
        if (avio_feof(s))  return AVERROR_EOF;
    }
    return size1 - size; //@wss add:返回实际读到的字节数
}

int ffio_read_size(AVIOContext *s, unsigned char *buf, int size)
{
    int ret = avio_read(s, buf, size);
    if (ret == size)
        return ret;
    if (ret < 0 && ret != AVERROR_EOF)
        return ret;
    return AVERROR_INVALIDDATA;
}

int ffio_read_indirect(AVIOContext *s, unsigned char *buf, int size, const unsigned char **data)
{
    if (s->buf_end - s->buf_ptr >= size && !s->write_flag) {
        *data = s->buf_ptr;
        s->buf_ptr += size;
        return size;
    } else {
        *data = buf;
        return avio_read(s, buf, size);
    }
}

int avio_read_partial(AVIOContext *s, unsigned char *buf, int size)
{
    int len;

    if (size < 0)
        return AVERROR(EINVAL);

    if (s->read_packet && s->write_flag) {
        len = read_packet_wrapper(s, buf, size);
        if (len > 0)
            s->pos += len;
        return len;
    }

    len = s->buf_end - s->buf_ptr;
    if (len == 0) {
        fill_buffer(s);
        len = s->buf_end - s->buf_ptr;
    }
    if (len > size)
        len = size;
    memcpy(buf, s->buf_ptr, len);
    s->buf_ptr += len;
    if (!len) {
        if (s->error)      return s->error;
        if (avio_feof(s))  return AVERROR_EOF;
    }
    return len;
}

unsigned int avio_rl16(AVIOContext *s)
{
    unsigned int val;
    val = avio_r8(s);
    val |= avio_r8(s) << 8;
    return val;
}

unsigned int avio_rl24(AVIOContext *s)
{
    unsigned int val;
    val = avio_rl16(s);
    val |= avio_r8(s) << 16;
    return val;
}

unsigned int avio_rl32(AVIOContext *s)
{
    unsigned int val;
    val = avio_rl16(s);
    val |= avio_rl16(s) << 16;
    return val;
}

uint64_t avio_rl64(AVIOContext *s)
{
    uint64_t val;
    val = (uint64_t)avio_rl32(s);
    val |= (uint64_t)avio_rl32(s) << 32;
    return val;
}

unsigned int avio_rb16(AVIOContext *s)
{
    unsigned int val;
    val = avio_r8(s) << 8;
    val |= avio_r8(s);
    return val;
}

unsigned int avio_rb24(AVIOContext *s)
{
    unsigned int val;
    val = avio_rb16(s) << 8;
    val |= avio_r8(s);
    return val;
}
unsigned int avio_rb32(AVIOContext *s)
{
    unsigned int val;
    val = avio_rb16(s) << 16;
    val |= avio_rb16(s);
    return val;
}

int ff_get_line(AVIOContext *s, char *buf, int maxlen)
{
    int i = 0;
    char c;

    do {
        c = avio_r8(s);
        if (c && i < maxlen-1)
            buf[i++] = c;
    } while (c != '\n' && c != '\r' && c);
    if (c == '\r' && avio_r8(s) != '\n' && !avio_feof(s))
        avio_skip(s, -1);

    buf[i] = 0;
    return i;
}

int ff_get_chomp_line(AVIOContext *s, char *buf, int maxlen)
{
    int len = ff_get_line(s, buf, maxlen);
    while (len > 0 && av_isspace(buf[len - 1]))
        buf[--len] = '\0';
    return len;
}

typedef enum FFBPrintReadStringMode {
    FFBPrintReadString = 0,
    FFBPrintReadLine   = 1,
} FFBPrintReadStringMode;

static int64_t read_string_to_bprint(AVIOContext *s, AVBPrint *bp,
                                     FFBPrintReadStringMode mode,
                                     int64_t max_len)
{
    int len, end;
    int64_t read = 0;
    char tmp[1024];
    char c;

    if (!max_len)
        return 0;

    do {
        len = 0;
        do {
            c = avio_r8(s);
            end = ((mode == FFBPrintReadLine && (c == '\r' || c == '\n')) ||
                   c == '\0');
            if (!end)
                tmp[len++] = c;
        } while (!end && len < sizeof(tmp) &&
                 ((max_len < 0) || (read + len < max_len)));
        av_bprint_append_data(bp, tmp, len);
        read += len;
    } while (!end && ((max_len < 0) || (read < max_len)));

    if (mode == FFBPrintReadLine &&
        c == '\r' && avio_r8(s) != '\n' && !avio_feof(s))
        avio_skip(s, -1);

    if (!c && s->error)
        return s->error;

    if (!c && !read && avio_feof(s))
        return AVERROR_EOF;

    return read;
}

static int64_t read_string_to_bprint_overwrite(AVIOContext *s, AVBPrint *bp,
                                               FFBPrintReadStringMode mode,
                                               int64_t max_len)
{
    int64_t ret;

    av_bprint_clear(bp);
    ret = read_string_to_bprint(s, bp, mode, max_len);
    if (ret < 0)
        return ret;

    if (!av_bprint_is_complete(bp))
        return AVERROR(ENOMEM);

    return bp->len;
}

int64_t ff_read_line_to_bprint_overwrite(AVIOContext *s, AVBPrint *bp)
{
    return read_string_to_bprint_overwrite(s, bp, FFBPrintReadLine, -1);
}

int64_t ff_read_string_to_bprint_overwrite(AVIOContext *s, AVBPrint *bp,
                                           int64_t max_len)
{
    return read_string_to_bprint_overwrite(s, bp, FFBPrintReadString, max_len);
}

int avio_get_str(AVIOContext *s, int maxlen, char *buf, int buflen)
{
    int i;

    if (buflen <= 0)
        return AVERROR(EINVAL);
    // reserve 1 byte for terminating 0
    buflen = FFMIN(buflen - 1, maxlen);
    for (i = 0; i < buflen; i++)
        if (!(buf[i] = avio_r8(s)))
            return i + 1;
    buf[i] = 0;
    for (; i < maxlen; i++)
        if (!avio_r8(s))
            return i + 1;
    return maxlen;
}

#define GET_STR16(type, read) \
    int avio_get_str16 ##type(AVIOContext *pb, int maxlen, char *buf, int buflen)\
{\
    char* q = buf;\
    int ret = 0;\
    if (buflen <= 0) \
        return AVERROR(EINVAL); \
    while (ret + 1 < maxlen) {\
        uint8_t tmp;\
        uint32_t ch;\
        GET_UTF16(ch, (ret += 2) <= maxlen ? read(pb) : 0, break;)\
        if (!ch)\
            break;\
        PUT_UTF8(ch, tmp, if (q - buf < buflen - 1) *q++ = tmp;)\
    }\
    *q = 0;\
    return ret;\
}\

GET_STR16(le, avio_rl16)
GET_STR16(be, avio_rb16)

#undef GET_STR16

uint64_t avio_rb64(AVIOContext *s)
{
    uint64_t val;
    val = (uint64_t)avio_rb32(s) << 32;
    val |= (uint64_t)avio_rb32(s);
    return val;
}

uint64_t ffio_read_varlen(AVIOContext *bc){
    uint64_t val = 0;
    int tmp;

    do{
        tmp = avio_r8(bc);
        val= (val<<7) + (tmp&127);
    }while(tmp&128);
    return val;
}

int ffio_fdopen(AVIOContext **s, URLContext *h)
{
    uint8_t *buffer = NULL;
    int buffer_size, max_packet_size;

    max_packet_size = h->max_packet_size;
    if (max_packet_size) {
        buffer_size = max_packet_size; /* no need to bufferize more than one packet */
    } else {
        buffer_size = IO_BUFFER_SIZE; //@wss add:默认32768字节 linux系统blocksize一般为4096，缓冲区32768 = 8 * blocksize。创建这个大小的缓冲区可达到比较高效的读写性能
    }
    if (!(h->flags & AVIO_FLAG_WRITE) && h->is_streamed) {
        if (buffer_size > INT_MAX/2)
            return AVERROR(EINVAL);
        buffer_size *= 2; //@wss add:如果没有设置写标志且是stream, buffer_size扩展2x
    }
    buffer = av_malloc(buffer_size);
    if (!buffer)
        return AVERROR(ENOMEM);

    *s = avio_alloc_context(buffer, buffer_size, h->flags & AVIO_FLAG_WRITE, h,
                            (int (*)(void *, uint8_t *, int))  ffurl_read,
                            (int (*)(void *, uint8_t *, int))  ffurl_write,
                            (int64_t (*)(void *, int64_t, int))ffurl_seek); //@wss add:初始化一个AVIOContext并返回
    if (!*s) {
        av_freep(&buffer);
        return AVERROR(ENOMEM);
    }
    (*s)->protocol_whitelist = av_strdup(h->protocol_whitelist);
    if (!(*s)->protocol_whitelist && h->protocol_whitelist) {
        avio_closep(s);
        return AVERROR(ENOMEM);
    }
    (*s)->protocol_blacklist = av_strdup(h->protocol_blacklist);
    if (!(*s)->protocol_blacklist && h->protocol_blacklist) {
        avio_closep(s);
        return AVERROR(ENOMEM);
    }
    //@wss add:direct值取决于flags，这个flags参数是由一开始的io_open_default函数一路传递进来的赋值给URLContext构造函数的
    (*s)->direct = h->flags & AVIO_FLAG_DIRECT; //@wss add:是否直接调用底层接口而不使用buffer 该字段会影响avio_read，avio_write，avio_seek函数，使得这三个函数不适用AVIOContext内部缓冲区，并且avio_seek将直接调用底层seek函数而不再再AVIOContext的buffer中seek

    (*s)->seekable = h->is_streamed ? 0 : AVIO_SEEKABLE_NORMAL; //@wss add:根据URLContext.is_streamed来判定是否支持seek操作，注意AVIO_SEEKABLE_NORMAL表征的是可以像本地文件那样按字节seek AVIO_SEEKABLE_TIME表征可以按照时间戳seek
    (*s)->max_packet_size = max_packet_size; //@wss add:设置包最大值和最小值
    (*s)->min_packet_size = h->min_packet_size;
    if(h->prot) { //@wss add:如果URLProtocol存在，那么给如下几个函数指针赋值
        (*s)->read_pause = (int (*)(void *, int))h->prot->url_read_pause;
        (*s)->read_seek  =
            (int64_t (*)(void *, int, int64_t, int))h->prot->url_read_seek;

        if (h->prot->url_read_seek) //@wss add:当url_read_seek存在，那么说明可以按照时间戳seek，因此seekable加上AVIO_SEEKABLE_TIME标志
            (*s)->seekable |= AVIO_SEEKABLE_TIME;
    }
    ((FFIOContext*)(*s))->short_seek_get = (int (*)(void *))ffurl_get_short_seek; //@wss add:设置short_seek回调
    (*s)->av_class = &ff_avio_class;
    return 0;
}

URLContext* ffio_geturlcontext(AVIOContext *s)
{
    if (!s)
        return NULL;

    if (s->opaque && s->read_packet == (int (*)(void *, uint8_t *, int))ffurl_read)
        return s->opaque;
    else
        return NULL;
}

int ffio_copy_url_options(AVIOContext* pb, AVDictionary** avio_opts)
{
    const char *opts[] = {
        "headers", "user_agent", "cookies", "http_proxy", "referer", "rw_timeout", "icy", NULL };
    const char **opt = opts;
    uint8_t *buf = NULL;
    int ret = 0;

    while (*opt) {
        if (av_opt_get(pb, *opt, AV_OPT_SEARCH_CHILDREN, &buf) >= 0) {
            if (buf[0] != '\0') {
                ret = av_dict_set(avio_opts, *opt, buf, AV_DICT_DONT_STRDUP_VAL);
                if (ret < 0)
                    return ret;
            } else {
                av_freep(&buf);
            }
        }
        opt++;
    }

    return ret;
}

static void update_checksum(AVIOContext *s)
{
    if (s->update_checksum && s->buf_ptr > s->checksum_ptr) {
        s->checksum = s->update_checksum(s->checksum, s->checksum_ptr,
                                         s->buf_ptr - s->checksum_ptr);
    }
}

int ffio_ensure_seekback(AVIOContext *s, int64_t buf_size)
{
    uint8_t *buffer;
    int max_buffer_size = s->max_packet_size ?
                          s->max_packet_size : IO_BUFFER_SIZE;
    ptrdiff_t filled = s->buf_end - s->buf_ptr;

    if (buf_size <= s->buf_end - s->buf_ptr)
        return 0;

    if (buf_size > INT_MAX - max_buffer_size)
        return AVERROR(EINVAL);

    buf_size += max_buffer_size - 1;

    if (buf_size + s->buf_ptr - s->buffer <= s->buffer_size || s->seekable || !s->read_packet)
        return 0;
    av_assert0(!s->write_flag);

    if (buf_size <= s->buffer_size) {
        update_checksum(s);
        memmove(s->buffer, s->buf_ptr, filled);
    } else {
        buffer = av_malloc(buf_size);
        if (!buffer)
            return AVERROR(ENOMEM);
        update_checksum(s);
        memcpy(buffer, s->buf_ptr, filled);
        av_free(s->buffer);
        s->buffer = buffer;
        s->buffer_size = buf_size;
    }
    s->buf_ptr = s->buffer;
    s->buf_end = s->buffer + filled;
    s->checksum_ptr = s->buffer;
    return 0;
}

int ffio_limit(AVIOContext *s, int size)
{
    FFIOContext *const ctx = ffiocontext(s);
    if (ctx->maxsize >= 0) {
        int64_t pos = avio_tell(s);
        int64_t remaining = ctx->maxsize - pos;
        if (remaining < size) {
            int64_t newsize = avio_size(s);
            if (!ctx->maxsize || ctx->maxsize < newsize)
                ctx->maxsize = newsize - !newsize;
            if (pos > ctx->maxsize && ctx->maxsize >= 0)
                ctx->maxsize = AVERROR(EIO);
            if (ctx->maxsize >= 0)
                remaining = ctx->maxsize - pos;
        }

        if (ctx->maxsize >= 0 && remaining < size && size > 1) {
            av_log(NULL, remaining ? AV_LOG_ERROR : AV_LOG_DEBUG,
                   "Truncating packet of size %d to %"PRId64"\n",
                   size, remaining + !remaining);
            size = remaining + !remaining;
        }
    }
    return size;
}

static int set_buf_size(AVIOContext *s, int buf_size)
{
    uint8_t *buffer;
    buffer = av_malloc(buf_size);
    if (!buffer)
        return AVERROR(ENOMEM);

    av_free(s->buffer);
    s->buffer = buffer;
    ffiocontext(s)->orig_buffer_size =
    s->buffer_size = buf_size;
    s->buf_ptr = s->buf_ptr_max = buffer;
    url_resetbuf(s, s->write_flag ? AVIO_FLAG_WRITE : AVIO_FLAG_READ);
    return 0;
}

int ffio_realloc_buf(AVIOContext *s, int buf_size)
{
    uint8_t *buffer;
    int data_size;

    if (!s->buffer_size)
        return set_buf_size(s, buf_size);

    if (buf_size <= s->buffer_size)
        return 0;

    buffer = av_malloc(buf_size);
    if (!buffer)
        return AVERROR(ENOMEM);

    data_size = s->write_flag ? (s->buf_ptr - s->buffer) : (s->buf_end - s->buf_ptr);
    if (data_size > 0)
        memcpy(buffer, s->write_flag ? s->buffer : s->buf_ptr, data_size);
    av_free(s->buffer);
    s->buffer = buffer;
    ffiocontext(s)->orig_buffer_size = buf_size;
    s->buffer_size = buf_size;
    s->buf_ptr = s->write_flag ? (s->buffer + data_size) : s->buffer;
    if (s->write_flag)
        s->buf_ptr_max = s->buffer + data_size;

    s->buf_end = s->write_flag ? (s->buffer + s->buffer_size) : (s->buf_ptr + data_size);

    return 0;
}

static int url_resetbuf(AVIOContext *s, int flags)
{
    av_assert1(flags == AVIO_FLAG_WRITE || flags == AVIO_FLAG_READ);

    if (flags & AVIO_FLAG_WRITE) {
        s->buf_end = s->buffer + s->buffer_size;
        s->write_flag = 1;
    } else {
        s->buf_end = s->buffer;
        s->write_flag = 0;
    }
    return 0;
}

int ffio_rewind_with_probe_data(AVIOContext *s, unsigned char **bufp, int buf_size)
{
    int64_t buffer_start;
    int buffer_size;
    int overlap, new_size, alloc_size;
    uint8_t *buf = *bufp;

    if (s->write_flag) {
        av_freep(bufp);
        return AVERROR(EINVAL);
    }

    buffer_size = s->buf_end - s->buffer;

    /* the buffers must touch or overlap */
    if ((buffer_start = s->pos - buffer_size) > buf_size) {
        av_freep(bufp);
        return AVERROR(EINVAL);
    }

    overlap = buf_size - buffer_start;
    new_size = buf_size + buffer_size - overlap;

    alloc_size = FFMAX(s->buffer_size, new_size);
    if (alloc_size > buf_size)
        if (!(buf = (*bufp) = av_realloc_f(buf, 1, alloc_size)))
            return AVERROR(ENOMEM);

    if (new_size > buf_size) {
        memcpy(buf + buf_size, s->buffer + overlap, buffer_size - overlap);
        buf_size = new_size;
    }

    av_free(s->buffer);
    s->buf_ptr = s->buffer = buf;
    s->buffer_size = alloc_size;
    s->pos = buf_size;
    s->buf_end = s->buf_ptr + buf_size;
    s->eof_reached = 0;

    return 0;
}

int avio_open(AVIOContext **s, const char *filename, int flags)
{
    return avio_open2(s, filename, flags, NULL, NULL);
}

int ffio_open_whitelist(AVIOContext **s, const char *filename, int flags,
                         const AVIOInterruptCB *int_cb, AVDictionary **options,
                         const char *whitelist, const char *blacklist
                        )
{
    URLContext *h;
    int err;

    *s = NULL;

    err = ffurl_open_whitelist(&h, filename, flags, int_cb, options, whitelist, blacklist, NULL);//@wss add:初始化URLContext 并打开URLProtocol
    if (err < 0)
        return err;
    err = ffio_fdopen(s, h); //@wss add:根据URLContext初始化AVIOContext
    if (err < 0) {
        ffurl_close(h);
        return err;
    }
    return 0;
}

int avio_open2(AVIOContext **s, const char *filename, int flags,
               const AVIOInterruptCB *int_cb, AVDictionary **options)
{
    return ffio_open_whitelist(s, filename, flags, int_cb, options, NULL, NULL);
}

int avio_close(AVIOContext *s)
{
    FFIOContext *const ctx = ffiocontext(s);
    URLContext *h;
    int ret, error;

    if (!s)
        return 0;

    avio_flush(s);
    h         = s->opaque;
    s->opaque = NULL;

    av_freep(&s->buffer);
    if (s->write_flag)
        av_log(s, AV_LOG_VERBOSE,
               "Statistics: %"PRId64" bytes written, %d seeks, %d writeouts\n",
               ctx->bytes_written, ctx->seek_count, ctx->writeout_count);
    else
        av_log(s, AV_LOG_VERBOSE, "Statistics: %"PRId64" bytes read, %d seeks\n",
               ctx->bytes_read, ctx->seek_count);
    av_opt_free(s);

    error = s->error;
    avio_context_free(&s);

    ret = ffurl_close(h);
    if (ret < 0)
        return ret;

    return error;
}

int avio_closep(AVIOContext **s)
{
    int ret = avio_close(*s);
    *s = NULL;
    return ret;
}

int avio_vprintf(AVIOContext *s, const char *fmt, va_list ap)
{
    AVBPrint bp;

    av_bprint_init(&bp, 0, INT_MAX);
    av_vbprintf(&bp, fmt, ap);
    if (!av_bprint_is_complete(&bp)) {
        av_bprint_finalize(&bp, NULL);
        s->error = AVERROR(ENOMEM);
        return AVERROR(ENOMEM);
    }
    avio_write(s, bp.str, bp.len);
    av_bprint_finalize(&bp, NULL);
    return bp.len;
}

int avio_printf(AVIOContext *s, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = avio_vprintf(s, fmt, ap);
    va_end(ap);

    return ret;
}

void avio_print_string_array(AVIOContext *s, const char *strings[])
{
    for(; *strings; strings++)
        avio_write(s, (const unsigned char *)*strings, strlen(*strings));
}

int avio_pause(AVIOContext *s, int pause)
{
    if (!s->read_pause)
        return AVERROR(ENOSYS);
    return s->read_pause(s->opaque, pause);
}

int64_t avio_seek_time(AVIOContext *s, int stream_index,
                       int64_t timestamp, int flags)
{
    int64_t ret;
    if (!s->read_seek)
        return AVERROR(ENOSYS);
    ret = s->read_seek(s->opaque, stream_index, timestamp, flags);
    if (ret >= 0) {
        int64_t pos;
        s->buf_ptr = s->buf_end; // Flush buffer
        pos = s->seek(s->opaque, 0, SEEK_CUR);
        if (pos >= 0)
            s->pos = pos;
        else if (pos != AVERROR(ENOSYS))
            ret = pos;
    }
    return ret;
}

int avio_read_to_bprint(AVIOContext *h, AVBPrint *pb, size_t max_size)
{
    int ret;
    char buf[1024];
    while (max_size) {
        ret = avio_read(h, buf, FFMIN(max_size, sizeof(buf)));
        if (ret == AVERROR_EOF)
            return 0;
        if (ret <= 0)
            return ret;
        av_bprint_append_data(pb, buf, ret);
        if (!av_bprint_is_complete(pb))
            return AVERROR(ENOMEM);
        max_size -= ret;
    }
    return 0;
}

int avio_accept(AVIOContext *s, AVIOContext **c)
{
    int ret;
    URLContext *sc = s->opaque;
    URLContext *cc = NULL;
    ret = ffurl_accept(sc, &cc);
    if (ret < 0)
        return ret;
    return ffio_fdopen(c, cc);
}

int avio_handshake(AVIOContext *c)
{
    URLContext *cc = c->opaque;
    return ffurl_handshake(cc);
}

/* output in a dynamic buffer */

typedef struct DynBuffer {
    int pos, size, allocated_size;
    uint8_t *buffer;
    int io_buffer_size;
    uint8_t io_buffer[1];
} DynBuffer;

static int dyn_buf_write(void *opaque, uint8_t *buf, int buf_size)
{
    DynBuffer *d = opaque;
    unsigned new_size;

    /* reallocate buffer if needed */
    new_size = (unsigned)d->pos + buf_size;
    if (new_size < d->pos || new_size > INT_MAX)
        return AVERROR(ERANGE);
    if (new_size > d->allocated_size) {
        unsigned new_allocated_size = d->allocated_size ? d->allocated_size
                                                        : new_size;
        int err;
        while (new_size > new_allocated_size)
            new_allocated_size += new_allocated_size / 2 + 1;

        new_allocated_size = FFMIN(new_allocated_size, INT_MAX);

        if ((err = av_reallocp(&d->buffer, new_allocated_size)) < 0) {
            d->allocated_size = 0;
            d->size = 0;
            return err;
        }
        d->allocated_size = new_allocated_size;
    }
    memcpy(d->buffer + d->pos, buf, buf_size);
    d->pos = new_size;
    if (d->pos > d->size)
        d->size = d->pos;
    return buf_size;
}

static int dyn_packet_buf_write(void *opaque, uint8_t *buf, int buf_size)
{
    unsigned char buf1[4];
    int ret;

    /* packetized write: output the header */
    AV_WB32(buf1, buf_size);
    ret = dyn_buf_write(opaque, buf1, 4);
    if (ret < 0)
        return ret;

    /* then the data */
    return dyn_buf_write(opaque, buf, buf_size);
}

static int64_t dyn_buf_seek(void *opaque, int64_t offset, int whence)
{
    DynBuffer *d = opaque;

    if (whence == SEEK_CUR)
        offset += d->pos;
    else if (whence == SEEK_END)
        offset += d->size;
    if (offset < 0)
        return AVERROR(EINVAL);
    if (offset > INT_MAX)
        return AVERROR(ERANGE);
    d->pos = offset;
    return 0;
}

static int url_open_dyn_buf_internal(AVIOContext **s, int max_packet_size)
{
    struct { FFIOContext pb; DynBuffer d; } *ret;
    DynBuffer *d;
    unsigned io_buffer_size = max_packet_size ? max_packet_size : 1024;

    if (sizeof(*ret) + io_buffer_size < io_buffer_size)
        return AVERROR(ERANGE);
    ret = av_mallocz(sizeof(*ret) + io_buffer_size);
    if (!ret)
        return AVERROR(ENOMEM);
    d = &ret->d;
    d->io_buffer_size = io_buffer_size;
    ffio_init_context(&ret->pb, d->io_buffer, d->io_buffer_size, 1, d, NULL,
                      max_packet_size ? dyn_packet_buf_write : dyn_buf_write,
                      max_packet_size ? NULL : dyn_buf_seek);
    *s = &ret->pb.pub;
    (*s)->max_packet_size = max_packet_size;
    return 0;
}

int avio_open_dyn_buf(AVIOContext **s)
{
    return url_open_dyn_buf_internal(s, 0);
}

int ffio_open_dyn_packet_buf(AVIOContext **s, int max_packet_size)
{
    if (max_packet_size <= 0)
        return AVERROR(EINVAL);
    return url_open_dyn_buf_internal(s, max_packet_size);
}

int avio_get_dyn_buf(AVIOContext *s, uint8_t **pbuffer)
{
    DynBuffer *d;

    if (!s) {
        *pbuffer = NULL;
        return 0;
    }
    d = s->opaque;

    if (!s->error && !d->size) {
        *pbuffer = d->io_buffer;
        return FFMAX(s->buf_ptr, s->buf_ptr_max) - s->buffer;
    }

    avio_flush(s);

    *pbuffer = d->buffer;

    return d->size;
}

void ffio_reset_dyn_buf(AVIOContext *s)
{
    DynBuffer *d = s->opaque;
    int max_packet_size = s->max_packet_size;

    ffio_init_context(ffiocontext(s), d->io_buffer, d->io_buffer_size,
                      1, d, NULL, s->write_packet, s->seek);
    s->max_packet_size = max_packet_size;
    d->pos = d->size = 0;
}

int avio_close_dyn_buf(AVIOContext *s, uint8_t **pbuffer)
{
    DynBuffer *d;
    int size;
    int padding = 0;

    if (!s) {
        *pbuffer = NULL;
        return 0;
    }

    /* don't attempt to pad fixed-size packet buffers */
    if (!s->max_packet_size) {
        ffio_fill(s, 0, AV_INPUT_BUFFER_PADDING_SIZE);
        padding = AV_INPUT_BUFFER_PADDING_SIZE;
    }

    avio_flush(s);

    d = s->opaque;
    *pbuffer = d->buffer;
    size = d->size;

    avio_context_free(&s);

    return size - padding;
}

void ffio_free_dyn_buf(AVIOContext **s)
{
    DynBuffer *d;

    if (!*s)
        return;

    d = (*s)->opaque;
    av_free(d->buffer);
    avio_context_free(s);
}

static int null_buf_write(void *opaque, uint8_t *buf, int buf_size)
{
    DynBuffer *d = opaque;

    d->pos += buf_size;
    if (d->pos > d->size)
        d->size = d->pos;
    return buf_size;
}

int ffio_open_null_buf(AVIOContext **s)
{
    int ret = url_open_dyn_buf_internal(s, 0);
    if (ret >= 0) {
        AVIOContext *pb = *s;
        pb->write_packet = null_buf_write;
    }
    return ret;
}

int ffio_close_null_buf(AVIOContext *s)
{
    DynBuffer *d = s->opaque;
    int size;

    avio_flush(s);

    size = d->size;

    avio_context_free(&s);

    return size;
}
