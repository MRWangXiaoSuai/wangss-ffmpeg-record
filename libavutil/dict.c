/*
 * copyright (c) 2009 Michael Niedermayer
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

#include <string.h>

#include "avstring.h"
#include "dict.h"
#include "dict_internal.h"
#include "internal.h"
#include "mem.h"
#include "time_internal.h"
#include "bprint.h"

struct AVDictionary {
    int count;
    AVDictionaryEntry *elems;
};

int av_dict_count(const AVDictionary *m)
{
    return m ? m->count : 0;
}

AVDictionaryEntry *av_dict_get(const AVDictionary *m, const char *key,
                               const AVDictionaryEntry *prev, int flags)
{
    unsigned int i, j;

    if (!m || !key)
        return NULL;
    //@wss add:计算prev的下一个entry是第几个，注意计算方式，若prev是不属于AVDictionary条目或者是最后一个，计算出来的i必定是越界的
    if (prev)
        i = prev - m->elems + 1;
    else
        i = 0;
    //@wss add:从第i个条目进行匹配
    for (; i < m->count; i++) {
        const char *s = m->elems[i].key;
        if (flags & AV_DICT_MATCH_CASE) //@wss add:AV_DICT_MATCH_CASE大小写敏感不进行字符串转换
            for (j = 0; s[j] == key[j] && key[j]; j++)
                ;
        else
            for (j = 0; av_toupper(s[j]) == av_toupper(key[j]) && key[j]; j++) //@wss add:大小写不敏感，都转换为大写字母再进行匹配
                ;
        if (key[j]) //@wss add:经过上述过程，key中还有余留字段没匹配上，说明没匹配上，进入下个循环
            continue;
        if (s[j] && !(flags & AV_DICT_IGNORE_SUFFIX)) //@wss add:经过上述过程，key中没有余留字段，但是条目的key中还有余留，若AV_DICT_IGNORE_SUFFIX存在，则也算匹配上，否则就是要求全部匹配，进入下个循环
            continue;
        return &m->elems[i]; //@wss add:上述条件都通过，该条目就是满足匹配条件的条目，返回此条目
    }
    return NULL;
}

int av_dict_set(AVDictionary **pm, const char *key, const char *value,
                int flags)
{
    AVDictionary *m = *pm;
    AVDictionaryEntry *tag = NULL;
    char *copy_key = NULL, *copy_value = NULL;
    int err;

    if (flags & AV_DICT_DONT_STRDUP_VAL) //@wss add:AV_DICT_DONT_STRDUP_VAL表示对于value是否需要为其重新分配空间，如果需要，调用av_strdup拷贝一份返回给copy_value
        copy_value = (void *)value;
    else if (value)
        copy_value = av_strdup(value);
    if (!key) {
        err = AVERROR(EINVAL);
        goto err_out;
    }
    if (!(flags & AV_DICT_MULTIKEY)) { //@wss add:AV_DICT_MULTIKEY表示条目中允许存在重复key，如果不允许出现重复的key，则获取key所对应的条目
        tag = av_dict_get(m, key, NULL, flags);
    }
    if (flags & AV_DICT_DONT_STRDUP_KEY) //@wss add:AV_DICT_DONT_STRDUP_KEY表示对于key是否需要为其重新分配空间，如果需要，调用av_strdup拷贝一份返回给copy_key
        copy_key = (void *)key;
    else
        copy_key = av_strdup(key);
    if (!m)
        m = *pm = av_mallocz(sizeof(*m)); //@wss add:如果不存在AVDictionary，新创建一个
    /*
     * 以下三种情况认为是出错：
     * 如果m还为空，那边就是AVDictionary空间分配失败
     * 如果传入的key不为空，但是内部copy_key为空，也即分配空间失败
     * 如果传入的value不为空，但是内部copy_value为空，也即分配空间失败
    */
    if (!m || !copy_key || (value && !copy_value))
        goto enomem;
    //@wss add:tag存在，即不允许重复key，找到传入key对应的条目，就不需要创建新的条目了
    if (tag) {
        if (flags & AV_DICT_DONT_OVERWRITE) { //@wss add:AV_DICT_DONT_OVERWRITE表示不允许覆盖已有值，如果不允许重写value值，直接释放空间返回0
            av_free(copy_key);
            av_free(copy_value);
            return 0;
        }
        if (copy_value && flags & AV_DICT_APPEND) { //@wss add:AV_DICT_APPEND表示在value之后追加值
            size_t oldlen = strlen(tag->value);
            size_t new_part_len = strlen(copy_value);
            size_t len = oldlen + new_part_len + 1; //@wss add:计算旧值和新值总大小
            char *newval = av_realloc(tag->value, len); //@wss add:为新旧二者创建新的空间
            if (!newval)
                goto enomem;
            memcpy(newval + oldlen, copy_value, new_part_len + 1); //@wss add:将旧值和新值都拷贝到新创建的空间，释放旧空间
            av_freep(&copy_value);
            copy_value = newval;
        } else
            av_free(tag->value); //@wss add:不允许追加，释放条目中value空间
        av_free(tag->key); //@wss add:释放条目中key空间
        *tag = m->elems[--m->count]; //@wss add:将最后一个条目内容复制到tag这个条目，这是干啥呀？注意啊，m->count在这个时候自减一了！！！！
    } else if (copy_value) { //@wss add:需要创建新条目场景
        AVDictionaryEntry *tmp = av_realloc_array(m->elems,
                                                  m->count + 1, sizeof(*m->elems)); //@wss add:扩展m->elems指向的空间
        if (!tmp)
            goto enomem;
        m->elems = tmp; //@wss add:扩展后的空间地址可能改变，将m->elems指向新的地址空间
    }
    if (copy_value) { //@wss add:copy_value不为NULL，意味着要重新设置，不论什么场景，最后一个条目都是目的条目
        m->elems[m->count].key = copy_key; //@wss add:更新key value指针
        m->elems[m->count].value = copy_value;
        m->count++;
    } else {
        if (!m->count) { //@wss add:删除到无条目情况下，释放空间
            av_freep(&m->elems);
            av_freep(pm);
        }
        av_freep(&copy_key);
    }

    return 0;

enomem:
    err = AVERROR(ENOMEM);
err_out:
    if (m && !m->count) {
        av_freep(&m->elems);
        av_freep(pm);
    }
    av_free(copy_key);
    av_free(copy_value);
    return err;
}

int av_dict_set_int(AVDictionary **pm, const char *key, int64_t value,
                int flags)
{
    char valuestr[22];
    snprintf(valuestr, sizeof(valuestr), "%"PRId64, value);
    flags &= ~AV_DICT_DONT_STRDUP_VAL;
    return av_dict_set(pm, key, valuestr, flags);
}

static int parse_key_value_pair(AVDictionary **pm, const char **buf,
                                const char *key_val_sep, const char *pairs_sep,
                                int flags)
{
    char *key = av_get_token(buf, key_val_sep);
    char *val = NULL;
    int ret;

    if (key && *key && strspn(*buf, key_val_sep)) {
        (*buf)++;
        val = av_get_token(buf, pairs_sep);
    }

    if (key && *key && val && *val)
        ret = av_dict_set(pm, key, val, flags);
    else
        ret = AVERROR(EINVAL);

    av_freep(&key);
    av_freep(&val);

    return ret;
}

int av_dict_parse_string(AVDictionary **pm, const char *str,
                         const char *key_val_sep, const char *pairs_sep,
                         int flags)
{
    int ret;

    if (!str)
        return 0;

    /* ignore STRDUP flags */
    flags &= ~(AV_DICT_DONT_STRDUP_KEY | AV_DICT_DONT_STRDUP_VAL);

    while (*str) {
        if ((ret = parse_key_value_pair(pm, &str, key_val_sep, pairs_sep, flags)) < 0)
            return ret;

        if (*str)
            str++;
    }

    return 0;
}

void av_dict_free(AVDictionary **pm)
{
    AVDictionary *m = *pm;

    if (m) {
        while (m->count--) {
            av_freep(&m->elems[m->count].key);
            av_freep(&m->elems[m->count].value);
        }
        av_freep(&m->elems);
    }
    av_freep(pm);
}

int av_dict_copy(AVDictionary **dst, const AVDictionary *src, int flags)
{
    AVDictionaryEntry *t = NULL;

    while ((t = av_dict_get(src, "", t, AV_DICT_IGNORE_SUFFIX))) { //@wss add:不停迭代获取条目，注意这里使用AV_DICT_IGNORE_SUFFIX，这个标志使得key在匹配时，只要前面字符串能匹配上，则认为匹配成功。这里传入""，表示所有字符串都可匹配成功
        int ret = av_dict_set(dst, t->key, t->value, flags);
        if (ret < 0)
            return ret;
    }

    return 0;
}

int av_dict_get_string(const AVDictionary *m, char **buffer,
                       const char key_val_sep, const char pairs_sep)
{
    AVDictionaryEntry *t = NULL;
    AVBPrint bprint;
    int cnt = 0;
    char special_chars[] = {pairs_sep, key_val_sep, '\0'};

    if (!buffer || pairs_sep == '\0' || key_val_sep == '\0' || pairs_sep == key_val_sep ||
        pairs_sep == '\\' || key_val_sep == '\\')
        return AVERROR(EINVAL);

    if (!av_dict_count(m)) {
        *buffer = av_strdup("");
        return *buffer ? 0 : AVERROR(ENOMEM);
    }

    av_bprint_init(&bprint, 64, AV_BPRINT_SIZE_UNLIMITED);
    while ((t = av_dict_get(m, "", t, AV_DICT_IGNORE_SUFFIX))) {
        if (cnt++)
            av_bprint_append_data(&bprint, &pairs_sep, 1);
        av_bprint_escape(&bprint, t->key, special_chars, AV_ESCAPE_MODE_BACKSLASH, 0);
        av_bprint_append_data(&bprint, &key_val_sep, 1);
        av_bprint_escape(&bprint, t->value, special_chars, AV_ESCAPE_MODE_BACKSLASH, 0);
    }
    return av_bprint_finalize(&bprint, buffer);
}

int avpriv_dict_set_timestamp(AVDictionary **dict, const char *key, int64_t timestamp)
{
    time_t seconds = timestamp / 1000000;
    struct tm *ptm, tmbuf;
    ptm = gmtime_r(&seconds, &tmbuf);
    if (ptm) {
        char buf[32];
        if (!strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", ptm))
            return AVERROR_EXTERNAL;
        av_strlcatf(buf, sizeof(buf), ".%06dZ", (int)(timestamp % 1000000));
        return av_dict_set(dict, key, buf, 0);
    } else {
        return AVERROR_EXTERNAL;
    }
}
