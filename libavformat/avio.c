/*
 * unbuffered I/O
 * Copyright (c) 2001 Fabrice Bellard
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

#include "libavutil/avstring.h"
#include "libavutil/dict.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/avassert.h"
#include "os_support.h"
#include "avformat.h"
#include "internal.h"
#if CONFIG_NETWORK
#include "network.h"
#endif
#include "url.h"

/** @name Logging context. */
/*@{*/
static const char *urlcontext_to_name(void *ptr)
{
    URLContext *h = (URLContext *)ptr;
    if (h->prot)
        return h->prot->name;
    else
        return "NULL";
}

static void *urlcontext_child_next(void *obj, void *prev)
{
    URLContext *h = obj;
    if (!prev && h->priv_data && h->prot->priv_data_class)
        return h->priv_data;
    return NULL;
}

#define OFFSET(x) offsetof(URLContext,x)
#define E AV_OPT_FLAG_ENCODING_PARAM
#define D AV_OPT_FLAG_DECODING_PARAM
static const AVOption options[] = {
    {"protocol_whitelist", "List of protocols that are allowed to be used", OFFSET(protocol_whitelist), AV_OPT_TYPE_STRING, { .str = NULL },  0, 0, D },
    {"protocol_blacklist", "List of protocols that are not allowed to be used", OFFSET(protocol_blacklist), AV_OPT_TYPE_STRING, { .str = NULL },  0, 0, D },
    {"rw_timeout", "Timeout for IO operations (in microseconds)", offsetof(URLContext, rw_timeout), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, AV_OPT_FLAG_ENCODING_PARAM | AV_OPT_FLAG_DECODING_PARAM },
    { NULL }
};

const AVClass ffurl_context_class = {
    .class_name       = "URLContext",
    .item_name        = urlcontext_to_name,
    .option           = options,
    .version          = LIBAVUTIL_VERSION_INT,
    .child_next       = urlcontext_child_next,
    .child_class_iterate = ff_urlcontext_child_class_iterate,
};
/*@}*/
//@wss add:检查指定flag是否设置，设置则检查条件是否满足 检查无误后为URLContext分配内存，然后赋值
static int url_alloc_for_protocol(URLContext **puc, const URLProtocol *up,
                                  const char *filename, int flags,
                                  const AVIOInterruptCB *int_cb)
{
    URLContext *uc;
    int err;
//@wss add:ffmpeg配置需要网络，进行如下判断，若协议是需要网络的，但是网络库初始化失败，返回失败码
#if CONFIG_NETWORK
    if (up->flags & URL_PROTOCOL_FLAG_NETWORK && !ff_network_init())
        return AVERROR(EIO);
#endif
    if ((flags & AVIO_FLAG_READ) && !up->url_read) { //@wss add:读协议，但是url_read为NULL
        av_log(NULL, AV_LOG_ERROR,
               "Impossible to open the '%s' protocol for reading\n", up->name);
        return AVERROR(EIO);
    }
    if ((flags & AVIO_FLAG_WRITE) && !up->url_write) { //@wss add:写协议，但是url_write为NULL
        av_log(NULL, AV_LOG_ERROR,
               "Impossible to open the '%s' protocol for writing\n", up->name);
        return AVERROR(EIO);
    }
    uc = av_mallocz(sizeof(URLContext) + strlen(filename) + 1); //@wss add:为URLContext对象分配内存，size不是sizeof(URLContext)，为的是将filename这个字符串直接拷贝到紧挨着的URLContext后续内存中去
    if (!uc) {
        err = AVERROR(ENOMEM);
        goto fail;
    }
    uc->av_class = &ffurl_context_class;
    uc->filename = (char *)&uc[1]; //@wss add:这里将filename指向(char *)&uc[1]，这个操作指向uc之后的空间，然后拷贝filename字符串到这，对应了上面的内存分配
    strcpy(uc->filename, filename);
    uc->prot            = up; //@wss add；将之前查找的URLPortocol对象挂在这，使得URLContext上下文持有URLProtocol对象
    uc->flags           = flags;
    uc->is_streamed     = 0; /* default = not streamed */
    uc->max_packet_size = 0; /* default: stream file */
    if (up->priv_data_size) { //@wss add:私有数据，这里注意up和uc
        uc->priv_data = av_mallocz(up->priv_data_size); //@wss add:URLContext.priv_data空间大小取决于URLProtocol.priv_data_size字段
        if (!uc->priv_data) {
            err = AVERROR(ENOMEM);
            goto fail;
        }
        if (up->priv_data_class) {
            char *start;
            *(const AVClass **)uc->priv_data = up->priv_data_class; //@wss add:等价于uc->priv_data->av_class = up->priv_data_class 具体定义可以查看libavformat/subfile.c
            av_opt_set_defaults(uc->priv_data);
            //@wss add:这里是对subfile协议的特例处理 subfile,,start,32815239,end,0,,:video.ts
            if (av_strstart(uc->filename, up->name, (const char**)&start) && *start == ',') { //@wss add:过滤开始filename和name中相同字段，此处过滤出subfile，start=“，”
                int ret= 0;
                char *p= start;
                char sep= *++p;
                char *key, *val;
                p++;

                if (strcmp(up->name, "subfile"))
                    ret = AVERROR(EINVAL);

                while(ret >= 0 && (key= strchr(p, sep)) && p<key && (val = strchr(key+1, sep))){ //@wss add:提取start和end的值，分别为32815239和0
                    *val= *key= 0;
                    if (strcmp(p, "start") && strcmp(p, "end")) {
                        ret = AVERROR_OPTION_NOT_FOUND;
                    } else //@wss add:下面uc->priv_data字段是一个void*类型，但是代表了一个具体的结构体，这里定义为void*是为了让priv_data字段根据不同情形成为不同的结构体类型
                        ret= av_opt_set(uc->priv_data, p, key+1, 0); //@wss add:将start和end的值赋值给priv_data字段所代表的结构体的start成员字段和end成员字段
                    if (ret == AVERROR_OPTION_NOT_FOUND)
                        av_log(uc, AV_LOG_ERROR, "Key '%s' not found.\n", p);
                    *val= *key= sep;
                    p= val+1;
                }
                if(ret<0 || p!=key){
                    av_log(uc, AV_LOG_ERROR, "Error parsing options string %s\n", start);
                    av_freep(&uc->priv_data);
                    av_freep(&uc);
                    err = AVERROR(EINVAL);
                    goto fail;
                }
                memmove(start, key+1, strlen(key));
            }
        }
    }
    if (int_cb)
        uc->interrupt_callback = *int_cb;

    *puc = uc;
    return 0;
fail:
    *puc = NULL;
    if (uc)
        av_freep(&uc->priv_data);
    av_freep(&uc);
#if CONFIG_NETWORK
    if (up->flags & URL_PROTOCOL_FLAG_NETWORK)
        ff_network_close();
#endif
    return err;
}

int ffurl_connect(URLContext *uc, AVDictionary **options)
{
    int err;
    AVDictionary *tmp_opts = NULL;
    AVDictionaryEntry *e;

    if (!options)
        options = &tmp_opts;

    // Check that URLContext was initialized correctly and lists are matching if set
    av_assert0(!(e=av_dict_get(*options, "protocol_whitelist", NULL, 0)) ||
               (uc->protocol_whitelist && !strcmp(uc->protocol_whitelist, e->value)));
    av_assert0(!(e=av_dict_get(*options, "protocol_blacklist", NULL, 0)) ||
               (uc->protocol_blacklist && !strcmp(uc->protocol_blacklist, e->value)));

    if (uc->protocol_whitelist && av_match_list(uc->prot->name, uc->protocol_whitelist, ',') <= 0) {
        av_log(uc, AV_LOG_ERROR, "Protocol '%s' not on whitelist '%s'!\n", uc->prot->name, uc->protocol_whitelist);
        return AVERROR(EINVAL);
    }

    if (uc->protocol_blacklist && av_match_list(uc->prot->name, uc->protocol_blacklist, ',') > 0) {
        av_log(uc, AV_LOG_ERROR, "Protocol '%s' on blacklist '%s'!\n", uc->prot->name, uc->protocol_blacklist);
        return AVERROR(EINVAL);
    }

    if (!uc->protocol_whitelist && uc->prot->default_whitelist) {
        av_log(uc, AV_LOG_DEBUG, "Setting default whitelist '%s'\n", uc->prot->default_whitelist);
        uc->protocol_whitelist = av_strdup(uc->prot->default_whitelist);
        if (!uc->protocol_whitelist) {
            return AVERROR(ENOMEM);
        }
    } else if (!uc->protocol_whitelist)
        av_log(uc, AV_LOG_DEBUG, "No default whitelist set\n"); // This should be an error once all declare a default whitelist

    if ((err = av_dict_set(options, "protocol_whitelist", uc->protocol_whitelist, 0)) < 0)
        return err;
    if ((err = av_dict_set(options, "protocol_blacklist", uc->protocol_blacklist, 0)) < 0)
        return err;
    /*@wss add:该函数最重要的就是这一句代码 如果设置里url_open2函数就调用此函数，否则调用url_open函数 
               此处函数是根据协议确认的，比如file协议则调用的是file_open(file.c), RTMP 协议则调用的是rtmp_open(rtmp_proto.c)函数*/
    err =
        uc->prot->url_open2 ? uc->prot->url_open2(uc,
                                                  uc->filename,
                                                  uc->flags,
                                                  options) :
        uc->prot->url_open(uc, uc->filename, uc->flags); 

    av_dict_set(options, "protocol_whitelist", NULL, 0);
    av_dict_set(options, "protocol_blacklist", NULL, 0);

    if (err)
        return err;
    uc->is_connected = 1; //@wss add:open成功表示已连上，设置标志位
    /* We must be careful here as ffurl_seek() could be slow,
     * for example for http @wss add:如果协议支持写入或者协议是file协议，即本地文件*/
    if ((uc->flags & AVIO_FLAG_WRITE) || !strcmp(uc->prot->name, "file"))
        if (!uc->is_streamed && ffurl_seek(uc, 0, SEEK_SET) < 0) //@wss add:协议是非流协议并且不能按字节seek，也当作流协议来处理
            uc->is_streamed = 1;
    return 0;
}

int ffurl_accept(URLContext *s, URLContext **c)
{
    av_assert0(!*c);
    if (s->prot->url_accept)
        return s->prot->url_accept(s, c);
    return AVERROR(EBADF);
}

int ffurl_handshake(URLContext *c)
{
    int ret;
    if (c->prot->url_handshake) {
        ret = c->prot->url_handshake(c); //@wss add:调用底层协议的handshake函数
        if (ret)
            return ret;
    }
    c->is_connected = 1; //@wss add:握手成功，is_connected标志位置1
    return 0;
}

#define URL_SCHEME_CHARS                        \
    "abcdefghijklmnopqrstuvwxyz"                \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"                \
    "0123456789+-."

static const struct URLProtocol *url_find_protocol(const char *filename) //@wss add:根据文件路径猜测协议
{
    const URLProtocol **protocols;
    char proto_str[128], proto_nested[128], *ptr;
    size_t proto_len = strspn(filename, URL_SCHEME_CHARS);//@wss add:找到字符串中第一个非字母或数字的位置，保存到proto_len中
    int i;
    //@wss add:绝大多数协议URL中都是包含:的，比如rtmp://..., http://..., udp://... etc。 proto_len就代表:前面字符个数
    /*
     *  对于windows系统dos盘符 C:\Butel\ButelMedicalPRO\LOG\MediaFrameworkLog等，使用is_dos_path函数检测是否为本地路径
     *  对于类unix系统的绝对路径和相对路径，./media/video.mp4  ../media/video.mp4 由于该URL不包含字符 : 所以语句filename[proto_len] != ':'和!strchr(filename + proto_len + 1, ':')都成立，从而判定为本地文件
     *  需要注意的是subfile协议，其URL形式类似为 subfile,,start,32815239,end,0,,:video.ts  因此通过strncmp(filename, "subfile,", 8)来将其排除在file协议之外
    */
    if (filename[proto_len] != ':' &&
        (strncmp(filename, "subfile,", 8) || !strchr(filename + proto_len + 1, ':')) ||
        is_dos_path(filename)) //@wss add:本地文件路径，ffmpeg认为文件也是协议，并且以file://开头，但是不符合正常的用法，||前面部分用于判断相对路径，后面用于判断绝对路径
        strcpy(proto_str, "file");//@wss add:是文件的话，就copy file字符进缓冲区
    else
        av_strlcpy(proto_str, filename,
                   FFMIN(proto_len + 1, sizeof(proto_str))); //@wss add:把proto_len字符copy到缓冲区 如RTMP,HTTP等

    av_strlcpy(proto_nested, proto_str, sizeof(proto_nested)); //@wss add:proto_nested协议字符串可能嵌套的协议串 如hls协议，其nested形式为 hls+http://host/path/to/remote/resource.m3u8 和 hls+file://path/to/local/resource.m3u8
    if ((ptr = strchr(proto_nested, '+'))) //@wss add:搜索在proto_nested中第一次出现+的位置
        *ptr = '\0';

    protocols = ffurl_get_protocols(NULL, NULL); //@wss add:获取协议列表
    if (!protocols)
        return NULL;
    for (i = 0; protocols[i]; i++) {
        const URLProtocol *up = protocols[i];
        if (!strcmp(proto_str, up->name)) { //@wss add:在协议列表中找到
            av_freep(&protocols);
            return up;
        }
        if (up->flags & URL_PROTOCOL_FLAG_NESTED_SCHEME &&
            !strcmp(proto_nested, up->name)) {
            av_freep(&protocols);
            return up;
        }
    }
    av_freep(&protocols);
    if (av_strstart(filename, "https:", NULL) || av_strstart(filename, "tls:", NULL))
        av_log(NULL, AV_LOG_WARNING, "https protocol not found, recompile FFmpeg with "
                                     "openssl, gnutls or securetransport enabled.\n");

    return NULL;
}

int ffurl_alloc(URLContext **puc, const char *filename, int flags,
                const AVIOInterruptCB *int_cb)
{
    const URLProtocol *p = NULL;

    p = url_find_protocol(filename); //@wss add:猜测协议，返回找到的协议
    if (p)
       return url_alloc_for_protocol(puc, p, filename, flags, int_cb); //@wss add:为URLContext分配内存并赋值

    *puc = NULL;
    return AVERROR_PROTOCOL_NOT_FOUND;
}

int ffurl_open_whitelist(URLContext **puc, const char *filename, int flags,
                         const AVIOInterruptCB *int_cb, AVDictionary **options,
                         const char *whitelist, const char* blacklist,
                         URLContext *parent)
{
    AVDictionary *tmp_opts = NULL;
    AVDictionaryEntry *e;
    int ret = ffurl_alloc(puc, filename, flags, int_cb); //@wss add:为URLContext分配内存，执行初始化
    if (ret < 0)
        return ret;
    if (parent) {
        ret = av_opt_copy(*puc, parent);//@wss add:把parent设置的opt copy到puc
        if (ret < 0)
            goto fail;
    }
    if (options &&
        (ret = av_opt_set_dict(*puc, options)) < 0) //@wss add:设置option 如果指定了的话
        goto fail;
    if (options && (*puc)->prot->priv_data_class &&
        (ret = av_opt_set_dict((*puc)->priv_data, options)) < 0) //@wss add:上一步中的option含有非URLContext类的直接选项信息，则设置用户传入的选项到priv_data中 priv_data 私有数据，实现封装和隐藏
        goto fail;
    //@wss add:传入的options为NULL，options指向内部临时变量，后续操作黑白名单需要用到此选项    此处操作就是为了不论用户是否传入options，还是传入NULL，后续操作使用统一变量
    if (!options)
        options = &tmp_opts;

    av_assert0(!whitelist ||
               !(e=av_dict_get(*options, "protocol_whitelist", NULL, 0)) ||
               !strcmp(whitelist, e->value));
    av_assert0(!blacklist ||
               !(e=av_dict_get(*options, "protocol_blacklist", NULL, 0)) ||
               !strcmp(blacklist, e->value));

    if ((ret = av_dict_set(options, "protocol_whitelist", whitelist, 0)) < 0)
        goto fail;

    if ((ret = av_dict_set(options, "protocol_blacklist", blacklist, 0)) < 0)
        goto fail;

    if ((ret = av_opt_set_dict(*puc, options)) < 0) //@wss add:上面把黑名单白名单设置到option，这里把option设置到puc结构体中
        goto fail;

    ret = ffurl_connect(*puc, options); //@wss add:打开URLProtocol

    if (!ret)
        return 0;
fail:
    ffurl_closep(puc);
    return ret;
}

static inline int retry_transfer_wrapper(URLContext *h, uint8_t *buf,
                                         int size, int size_min,
                                         int (*transfer_func)(URLContext *h,
                                                              uint8_t *buf,
                                                              int size))
{
    int ret, len;
    int fast_retries = 5;
    int64_t wait_since = 0;

    len = 0;
    while (len < size_min) {
        if (ff_check_interrupt(&h->interrupt_callback))
            return AVERROR_EXIT;
        ret = transfer_func(h, buf + len, size - len); //@wss add:调用协议自己的url_read或者url_write函数读写数据
        if (ret == AVERROR(EINTR))
            continue;
        if (h->flags & AVIO_FLAG_NONBLOCK)
            return ret;
        if (ret == AVERROR(EAGAIN)) {
            ret = 0;
            if (fast_retries) {
                fast_retries--;
            } else {
                if (h->rw_timeout) {
                    if (!wait_since)
                        wait_since = av_gettime_relative();
                    else if (av_gettime_relative() > wait_since + h->rw_timeout)
                        return AVERROR(EIO);
                }
                av_usleep(1000);
            }
        } else if (ret == AVERROR_EOF)
            return (len > 0) ? len : AVERROR_EOF;
        else if (ret < 0)
            return ret;
        if (ret) {
            fast_retries = FFMAX(fast_retries, 2);
            wait_since = 0;
        }
        len += ret;
    }
    return len;
}

int ffurl_read(URLContext *h, unsigned char *buf, int size)
{
    if (!(h->flags & AVIO_FLAG_READ))
        return AVERROR(EIO);
    return retry_transfer_wrapper(h, buf, size, 1, h->prot->url_read); //@wss add:h->prot->url_read是函数指针，实际调用的是不同protocol的url_read函数
}

int ffurl_read_complete(URLContext *h, unsigned char *buf, int size)
{
    if (!(h->flags & AVIO_FLAG_READ))
        return AVERROR(EIO);
    return retry_transfer_wrapper(h, buf, size, size, h->prot->url_read);
}

int ffurl_write(URLContext *h, const unsigned char *buf, int size)
{
    if (!(h->flags & AVIO_FLAG_WRITE))
        return AVERROR(EIO);
    /* avoid sending too big packets */
    if (h->max_packet_size && size > h->max_packet_size)
        return AVERROR(EIO);

    return retry_transfer_wrapper(h, (unsigned char *)buf, size, size,
                                  (int (*)(struct URLContext *, uint8_t *, int))
                                  h->prot->url_write);
}

int64_t ffurl_seek(URLContext *h, int64_t pos, int whence)
{
    int64_t ret;

    if (!h->prot->url_seek)
        return AVERROR(ENOSYS);
    ret = h->prot->url_seek(h, pos, whence & ~AVSEEK_FORCE);
    return ret;
}

int ffurl_closep(URLContext **hh)
{
    URLContext *h= *hh;
    int ret = 0;
    if (!h)
        return 0;     /* can happen when ffurl_open fails */

    if (h->is_connected && h->prot->url_close)
        ret = h->prot->url_close(h);
#if CONFIG_NETWORK
    if (h->prot->flags & URL_PROTOCOL_FLAG_NETWORK)
        ff_network_close();
#endif
    if (h->prot->priv_data_size) {
        if (h->prot->priv_data_class)
            av_opt_free(h->priv_data);
        av_freep(&h->priv_data);
    }
    av_opt_free(h);
    av_freep(hh);
    return ret;
}

int ffurl_close(URLContext *h)
{
    return ffurl_closep(&h);
}


const char *avio_find_protocol_name(const char *url)
{
    const URLProtocol *p = url_find_protocol(url);

    return p ? p->name : NULL;
}

int avio_check(const char *url, int flags)
{
    URLContext *h;
    int ret = ffurl_alloc(&h, url, flags, NULL);
    if (ret < 0)
        return ret;

    if (h->prot->url_check) {
        ret = h->prot->url_check(h, flags);
    } else {
        ret = ffurl_connect(h, NULL);
        if (ret >= 0)
            ret = flags;
    }

    ffurl_close(h);
    return ret;
}

int ffurl_move(const char *url_src, const char *url_dst)
{
    URLContext *h_src, *h_dst;
    int ret = ffurl_alloc(&h_src, url_src, AVIO_FLAG_READ_WRITE, NULL);
    if (ret < 0)
        return ret;
    ret = ffurl_alloc(&h_dst, url_dst, AVIO_FLAG_WRITE, NULL);
    if (ret < 0) {
        ffurl_close(h_src);
        return ret;
    }

    if (h_src->prot == h_dst->prot && h_src->prot->url_move)
        ret = h_src->prot->url_move(h_src, h_dst);
    else
        ret = AVERROR(ENOSYS);

    ffurl_close(h_src);
    ffurl_close(h_dst);
    return ret;
}

int ffurl_delete(const char *url)
{
    URLContext *h;
    int ret = ffurl_alloc(&h, url, AVIO_FLAG_WRITE, NULL);
    if (ret < 0)
        return ret;

    if (h->prot->url_delete)
        ret = h->prot->url_delete(h);
    else
        ret = AVERROR(ENOSYS);

    ffurl_close(h);
    return ret;
}

#if !FF_API_AVIODIRCONTEXT
struct AVIODirContext {
    struct URLContext *url_context;
};
#endif

int avio_open_dir(AVIODirContext **s, const char *url, AVDictionary **options)
{
    URLContext *h = NULL;
    AVIODirContext *ctx = NULL;
    int ret;
    av_assert0(s);

    ctx = av_mallocz(sizeof(*ctx));
    if (!ctx) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    if ((ret = ffurl_alloc(&h, url, AVIO_FLAG_READ, NULL)) < 0)
        goto fail;

    if (h->prot->url_open_dir && h->prot->url_read_dir && h->prot->url_close_dir) {
        if (options && h->prot->priv_data_class &&
            (ret = av_opt_set_dict(h->priv_data, options)) < 0)
            goto fail;
        ret = h->prot->url_open_dir(h);
    } else
        ret = AVERROR(ENOSYS);
    if (ret < 0)
        goto fail;

    h->is_connected = 1;
    ctx->url_context = h;
    *s = ctx;
    return 0;

  fail:
    av_free(ctx);
    *s = NULL;
    ffurl_close(h);
    return ret;
}

int avio_read_dir(AVIODirContext *s, AVIODirEntry **next)
{
    URLContext *h;
    int ret;

    if (!s || !s->url_context)
        return AVERROR(EINVAL);
    h = s->url_context;
    if ((ret = h->prot->url_read_dir(h, next)) < 0)
        avio_free_directory_entry(next);
    return ret;
}

int avio_close_dir(AVIODirContext **s)
{
    URLContext *h;

    av_assert0(s);
    if (!(*s) || !(*s)->url_context)
        return AVERROR(EINVAL);
    h = (*s)->url_context;
    h->prot->url_close_dir(h);
    ffurl_close(h);
    av_freep(s);
    *s = NULL;
    return 0;
}

void avio_free_directory_entry(AVIODirEntry **entry)
{
    if (!entry || !*entry)
        return;
    av_free((*entry)->name);
    av_freep(entry);
}

int64_t ffurl_size(URLContext *h)
{
    int64_t pos, size;

    size = ffurl_seek(h, 0, AVSEEK_SIZE);
    if (size < 0) {
        pos = ffurl_seek(h, 0, SEEK_CUR);
        if ((size = ffurl_seek(h, -1, SEEK_END)) < 0)
            return size;
        size++;
        ffurl_seek(h, pos, SEEK_SET);
    }
    return size;
}

int ffurl_get_file_handle(URLContext *h)
{
    if (!h || !h->prot || !h->prot->url_get_file_handle)
        return -1;
    return h->prot->url_get_file_handle(h);
}

int ffurl_get_multi_file_handle(URLContext *h, int **handles, int *numhandles)
{
    if (!h || !h->prot)
        return AVERROR(ENOSYS);
    if (!h->prot->url_get_multi_file_handle) {
        if (!h->prot->url_get_file_handle)
            return AVERROR(ENOSYS);
        *handles = av_malloc(sizeof(**handles));
        if (!*handles)
            return AVERROR(ENOMEM);
        *numhandles = 1;
        *handles[0] = h->prot->url_get_file_handle(h);
        return 0;
    }
    return h->prot->url_get_multi_file_handle(h, handles, numhandles);
}

int ffurl_get_short_seek(URLContext *h)
{
    if (!h || !h->prot || !h->prot->url_get_short_seek)
        return AVERROR(ENOSYS);
    return h->prot->url_get_short_seek(h);
}

int ffurl_shutdown(URLContext *h, int flags)
{
    if (!h || !h->prot || !h->prot->url_shutdown)
        return AVERROR(ENOSYS);
    return h->prot->url_shutdown(h, flags);
}

int ff_check_interrupt(AVIOInterruptCB *cb)
{
    if (cb && cb->callback)
        return cb->callback(cb->opaque);
    return 0;
}

int ff_rename(const char *url_src, const char *url_dst, void *logctx)
{
    int ret = ffurl_move(url_src, url_dst);
    if (ret < 0)
        av_log(logctx, AV_LOG_ERROR, "failed to rename file %s to %s: %s\n", url_src, url_dst, av_err2str(ret));
    return ret;
}
