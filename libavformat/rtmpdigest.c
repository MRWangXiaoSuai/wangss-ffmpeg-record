/*
 * RTMP network protocol
 * Copyright (c) 2009 Konstantin Shishkov
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

/**
 * @file
 * RTMP protocol digest
 */

#include <stdint.h>

#include "libavutil/error.h"
#include "libavutil/hmac.h"

#include "rtmp.h"

int ff_rtmp_calc_digest(const uint8_t *src, int len, int gap,
                        const uint8_t *key, int keylen, uint8_t *dst)
{
    AVHMAC *hmac;

    hmac = av_hmac_alloc(AV_HMAC_SHA256); //@wss add:根据加密方式分配具体的函数，后续使用
    if (!hmac)
        return AVERROR(ENOMEM);

    av_hmac_init(hmac, key, keylen);
    if (gap <= 0) {
        av_hmac_update(hmac, src, len);
    } else { //skip 32 bytes used for storing digest
        av_hmac_update(hmac, src, gap);
        av_hmac_update(hmac, src + gap + 32, len - gap - 32); //@wss add:32bytes digest数据
    }
    av_hmac_final(hmac, dst, 32); //@wss add:copy digest data

    av_hmac_free(hmac);

    return 0;
}

int ff_rtmp_calc_digest_pos(const uint8_t *buf, int off, int mod_val,
                            int add_val)
{
    int i, digest_pos = 0;

    for (i = 0; i < 4; i++)
        digest_pos += buf[i + off]; //@wss add:提取出digest前4字节数据，digest前4字节为offset offet表示紧跟着的random数据的长度 紧接着是32字节的digest-data以及剩余字节的random数据
    digest_pos = digest_pos % mod_val + add_val; //@wss add:offset % 632 + 8; 632 = 764字节的整体长度- 128字节的Key秘钥-4字节的自身长度 8是C1头部剩余长度(time +version)
    //@wss add:上述取余保证digest索引位置后面留有固定128字节的密文长度
    return digest_pos;
}
