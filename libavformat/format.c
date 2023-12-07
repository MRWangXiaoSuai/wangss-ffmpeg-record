/*
 * Format register and lookup
 * Copyright (c) 2000, 2001, 2002 Fabrice Bellard
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

#include "config_components.h"

#include "libavutil/avstring.h"
#include "libavutil/bprint.h"
#include "libavutil/opt.h"
#include "libavutil/thread.h"

#include "avio_internal.h"
#include "avformat.h"
#include "id3v2.h"
#include "internal.h"


/**
 * @file
 * Format register and lookup
 */

int av_match_ext(const char *filename, const char *extensions)
{
    const char *ext;

    if (!filename)
        return 0;

    ext = strrchr(filename, '.'); //@wss add:搜索 . 最后一次出现的位置
    if (ext)
        return av_match_name(ext + 1, extensions);
    return 0;
}

const AVOutputFormat *av_guess_format(const char *short_name, const char *filename,
                                      const char *mime_type)
{
    const AVOutputFormat *fmt = NULL;
    const AVOutputFormat *fmt_found = NULL;
    void *i = 0;
    int score_max, score;

    /* specific test for image sequences */
#if CONFIG_IMAGE2_MUXER
    if (!short_name && filename &&
        av_filename_number_test(filename) &&
        ff_guess_image2_codec(filename) != AV_CODEC_ID_NONE) {
        return av_guess_format("image2", NULL, NULL);
    }
#endif
    /* Find the proper file type. */
    score_max = 0;
    while ((fmt = av_muxer_iterate(&i))) {
        score = 0;
        if (fmt->name && short_name && av_match_name(short_name, fmt->name))
            score += 100;
        if (fmt->mime_type && mime_type && !strcmp(fmt->mime_type, mime_type))
            score += 10;
        if (filename && fmt->extensions &&
            av_match_ext(filename, fmt->extensions)) {
            score += 5;
        }
        if (score > score_max) {
            score_max = score;
            fmt_found = fmt;
        }
    }
    return fmt_found;
}

enum AVCodecID av_guess_codec(const AVOutputFormat *fmt, const char *short_name,
                              const char *filename, const char *mime_type,
                              enum AVMediaType type)
{
    if (av_match_name("segment", fmt->name) || av_match_name("ssegment", fmt->name)) {
        const AVOutputFormat *fmt2 = av_guess_format(NULL, filename, NULL);
        if (fmt2)
            fmt = fmt2;
    }

    if (type == AVMEDIA_TYPE_VIDEO) {
        enum AVCodecID codec_id = AV_CODEC_ID_NONE;

#if CONFIG_IMAGE2_MUXER || CONFIG_IMAGE2PIPE_MUXER
        if (!strcmp(fmt->name, "image2") || !strcmp(fmt->name, "image2pipe")) {
            codec_id = ff_guess_image2_codec(filename);
        }
#endif
        if (codec_id == AV_CODEC_ID_NONE)
            codec_id = fmt->video_codec;
        return codec_id;
    } else if (type == AVMEDIA_TYPE_AUDIO)
        return fmt->audio_codec;
    else if (type == AVMEDIA_TYPE_SUBTITLE)
        return fmt->subtitle_codec;
    else if (type == AVMEDIA_TYPE_DATA)
        return fmt->data_codec;
    else
        return AV_CODEC_ID_NONE;
}

const AVInputFormat *av_find_input_format(const char *short_name)
{
    const AVInputFormat *fmt = NULL;
    void *i = 0;
    while ((fmt = av_demuxer_iterate(&i)))
        if (av_match_name(short_name, fmt->name))
            return fmt;
    return NULL;
}

const AVInputFormat *av_probe_input_format3(const AVProbeData *pd,
                                            int is_opened, int *score_ret)
{
    AVProbeData lpd = *pd; //@wss add:pd.buf存储读取数据
    const AVInputFormat *fmt1 = NULL;
    const AVInputFormat *fmt = NULL;
    int score, score_max = 0;
    void *i = 0;
    const static uint8_t zerobuffer[AVPROBE_PADDING_SIZE];
    enum nodat {
        NO_ID3,
        ID3_ALMOST_GREATER_PROBE,
        ID3_GREATER_PROBE,
        ID3_GREATER_MAX_PROBE,
    } nodat = NO_ID3;

    if (!lpd.buf) //@wss add:检查参数有效性，必须保证buf的最尾部有32字节的0。buf为NULL，则提供一个栈上的32字节0数组
        lpd.buf = (unsigned char *) zerobuffer;
    //@wss add:ID3指的是MP3曲目标签，v2是版本，v2版本在MP3开头存储歌词专辑封面等大容量信息 ID3头部10字节长，分析文件前10个字节是否存在ID3
    if (lpd.buf_size > 10 && ff_id3v2_match(lpd.buf, ID3v2_DEFAULT_MAGIC)) {
        int id3len = ff_id3v2_tag_len(lpd.buf); //@wss add:分析ID3头，获取ID3头部长度 将ID3长度与缓冲区长度比较
        if (lpd.buf_size > id3len + 16) { //@wss add:id3长度小于探测缓冲区长度
            if (lpd.buf_size < 2LL*id3len + 16) //@wss add:id3长度小于探测缓冲区长度，但差不多要大于了
                nodat = ID3_ALMOST_GREATER_PROBE;
            lpd.buf      += id3len; //@wss add:跳过id3 tag信息
            lpd.buf_size -= id3len;
        } else if (id3len >= PROBE_BUF_MAX) { //@wss add:ID3长度大于探测缓冲区的最大值
            nodat = ID3_GREATER_MAX_PROBE;
        } else //@wss add:ID3长度大于探测缓冲区
            nodat = ID3_GREATER_PROBE;
    }

    while ((fmt1 = av_demuxer_iterate(&i))) { //@wss add:从媒体类型列表中循环获取媒体类型 并更新i 这里是判断每种媒体类型获得的分数 并保留最大值
        if (fmt1->flags & AVFMT_EXPERIMENTAL) //@wss add:媒体类型处于试验阶段 不做判断
            continue;
        if (!is_opened == !(fmt1->flags & AVFMT_NOFILE) && strcmp(fmt1->name, "image2")) //@wss add:过滤掉一些格式,IO层已打开，不需要读取文件的都过滤掉；IO层未打开，需要读取文件的都过滤掉
            continue;
        score = 0;
        if (fmt1->read_probe) { //@wss add:如果InputFormat中包含read_probe，优先调用read_probe函数获取匹配分数
            score = fmt1->read_probe(&lpd); //@wss add:不同封装格式包含不同实现函数，比如flv的实现函数为flv_prob，匹配的话一般会获得最大分值100
            if (score)
                av_log(NULL, AV_LOG_TRACE, "Probing %s score:%d size:%d\n", fmt1->name, score, lpd.buf_size);
            if (fmt1->extensions && av_match_ext(lpd.filename, fmt1->extensions)) { //@wss add:综合考虑计算得分与媒体扩展名匹配得分
                switch (nodat) { //@wss add:根据id3 tag信息，更新分数
                case NO_ID3:
                    score = FFMAX(score, 1);
                    break;
                case ID3_GREATER_PROBE:
                case ID3_ALMOST_GREATER_PROBE:
                    score = FFMAX(score, AVPROBE_SCORE_EXTENSION / 2 - 1); //@wss add:最低分24
                    break;
                case ID3_GREATER_MAX_PROBE:
                    score = FFMAX(score, AVPROBE_SCORE_EXTENSION); //@wss add:最低分50
                    break;
                }
            }
        } else if (fmt1->extensions) { //@wss add:不存在read_probe，但存在扩展名，调用av_match_ext函数获取媒体扩展名和AVInputFormat的扩展名是否匹配(内里调用的其实是av_match_name函数) 文件扩展名谁都可以修改，因此没那么可信
            if (av_match_ext(lpd.filename, fmt1->extensions))
                score = AVPROBE_SCORE_EXTENSION; //@wss add:扩展名匹配，获得分数50
        }
        if (av_match_name(lpd.mime_type, fmt1->mime_type)) { //@wss add:调用av_match_name匹配输入媒体的mime_type和AVInputFormat的mime_type是否匹配
            if (AVPROBE_SCORE_MIME > score) {
                av_log(NULL, AV_LOG_DEBUG, "Probing %s score:%d increased to %d due to MIME type\n", fmt1->name, score, AVPROBE_SCORE_MIME);
                score = AVPROBE_SCORE_MIME; //@wss add:mime_type匹配，获得分数75
            }
        }
        if (score > score_max) { //@wss add:当前格式得分更高，更新分数和格式
            score_max = score;
            fmt       = fmt1;
        } else if (score == score_max) //@wss add:前后两种格式获得分数相同，则此时无法判断具体是哪种格式，fmt置NULL
            fmt = NULL;
    }
    if (nodat == ID3_GREATER_PROBE) //@wss add:这种情况期待读取更多数据进行判断
        score_max = FFMIN(AVPROBE_SCORE_EXTENSION / 2 - 1, score_max); //@wss add:这种情况最高得分24
    *score_ret = score_max; //@wss add:循环完，获得最匹配的分数，更新分数

    return fmt; //@wss add:返回分数对应的格式
}
//@wss add:is_opend表征文件是否被打开，在没打开情形下，绝大情况下返回NULL
const AVInputFormat *av_probe_input_format2(const AVProbeData *pd,
                                            int is_opened, int *score_max)
{
    int score_ret;
    const AVInputFormat *fmt = av_probe_input_format3(pd, is_opened, &score_ret); //@wss add:获取最匹配的格式以及分数
    if (score_ret > *score_max) { //@wss add:最低得分25，低于25分返回NULL
        *score_max = score_ret;
        return fmt;
    } else
        return NULL;
}

const AVInputFormat *av_probe_input_format(const AVProbeData *pd, int is_opened)
{
    int score = 0;
    return av_probe_input_format2(pd, is_opened, &score);
}

int av_probe_input_buffer2(AVIOContext *pb, const AVInputFormat **fmt,
                           const char *filename, void *logctx,
                           unsigned int offset, unsigned int max_probe_size)
{
    AVProbeData pd = { filename ? filename : "" };
    uint8_t *buf = NULL;
    int ret = 0, probe_size, buf_offset = 0;
    int score = 0;
    int ret2;

    if (!max_probe_size)
        max_probe_size = PROBE_BUF_MAX; //@wss add:探测缓冲区最大长度默认1MB
    else if (max_probe_size < PROBE_BUF_MIN) {
        av_log(logctx, AV_LOG_ERROR,
               "Specified probe size value %u cannot be < %u\n", max_probe_size, PROBE_BUF_MIN);
        return AVERROR(EINVAL);
    }

    if (offset >= max_probe_size) //@wss add:offset 开始推测AVInputFormat的偏移量
        return AVERROR(EINVAL);
    //@wss add:一些mime_type例子，.gif image/gif   .ipeg,.jpg image/jpeg etc.只有http协议会用到mime_type
    if (pb->av_class) { //@wss add:AVClass存储了option，获取key为mime_type(标准中指定的一些格式)的val，mime_type可用于确定媒体类型(可能出现一个复用器多个mime_type)
        uint8_t *mime_type_opt = NULL;
        char *semi;
        av_opt_get(pb, "mime_type", AV_OPT_SEARCH_CHILDREN, &mime_type_opt); //@wss add:获取mime_type信息
        pd.mime_type = (const char *)mime_type_opt;
        semi = pd.mime_type ? strchr(pd.mime_type, ';') : NULL; //@wss add:存在多个，以 ;隔开，截断取第一个
        if (semi) {
            *semi = '\0';
        }
    }
    //@wss add:从最小buffer 2048字节开始查找，每查找一次数据量以2的次方更新，直到探测到iformat或者总字节达到1MB，大部分格式都不需要1M的数据就可以推测出来
    for (probe_size = PROBE_BUF_MIN; probe_size <= max_probe_size && !*fmt;
         probe_size = FFMIN(probe_size << 1,
                            FFMAX(max_probe_size, probe_size + 1))) {
        score = probe_size < max_probe_size ? AVPROBE_SCORE_RETRY : 0; //@wss add:初始分 25 每次循环重置

        /* Read probe data. */
        if ((ret = av_reallocp(&buf, probe_size + AVPROBE_PADDING_SIZE)) < 0) //@wss add:为什么要加AVPROBE_PADDING_SIZE？使用av_reallocp而不是av_malloc是为了保存上次读取的数据
            goto fail;
        if ((ret = avio_read(pb, buf + buf_offset,
                             probe_size - buf_offset)) < 0) { //@wss add:buf_offset控制每次循环读取不需要重新把之前读过的数据copy进去
            /* Fail if error was not end of file, otherwise, lower score. 读文件失败*/
            if (ret != AVERROR_EOF)
                goto fail;
            //@wss add:读到文件尾了
            score = 0;
            ret   = 0;          /* error was end of file, nothing read */
        }
        buf_offset += ret; //@wss add:更新读取数据bytes
        if (buf_offset < offset) //@wss add:读取数据不够传入的数据偏移，此时数据不够继续读
            continue;
        pd.buf_size = buf_offset - offset; //@wss add:填充AVProbeData对象
        pd.buf = &buf[offset]; //@wss add:指针从offset开始，avio_read把数据从AVIOContext读到buf,这里直接让AVProbData.buf指针指向存储数据的buf

        memset(pd.buf + pd.buf_size, 0, AVPROBE_PADDING_SIZE);

        /* Guess file format. */
        *fmt = av_probe_input_format2(&pd, 1, &score); //@wss add:如果猜测的文件格式得分大于25，返回fmt，否则返回NULL(此处for循环中停止条件为探测出fmt，所以如果这里返回了fmt则for循环结束)
        if (*fmt) {
            /* This can only be true in the last iteration. */
            if (score <= AVPROBE_SCORE_RETRY) {
                av_log(logctx, AV_LOG_WARNING,
                       "Format %s detected only with low score of %d, "
                       "misdetection possible!\n", (*fmt)->name, score);
            } else
                av_log(logctx, AV_LOG_DEBUG,
                       "Format %s probed with size=%d and score=%d\n",
                       (*fmt)->name, probe_size, score);
#if 0
            FILE *f = fopen("probestat.tmp", "ab");
            fprintf(f, "probe_size:%d format:%s score:%d filename:%s\n", probe_size, (*fmt)->name, score, filename);
            fclose(f);
#endif
        }
    }

    if (!*fmt) //@wss add:读取完1M字节数据也没探测出格式
        ret = AVERROR_INVALIDDATA;

fail:
    /* Rewind. Reuse probe buffer to avoid seeking. @wss add:调整缓冲区*/
    ret2 = ffio_rewind_with_probe_data(pb, &buf, buf_offset);
    if (ret >= 0)
        ret = ret2;

    av_freep(&pd.mime_type);
    return ret < 0 ? ret : score;
}

int av_probe_input_buffer(AVIOContext *pb, const AVInputFormat **fmt,
                          const char *filename, void *logctx,
                          unsigned int offset, unsigned int max_probe_size)
{
    int ret = av_probe_input_buffer2(pb, fmt, filename, logctx, offset, max_probe_size);
    return ret < 0 ? ret : 0;
}
