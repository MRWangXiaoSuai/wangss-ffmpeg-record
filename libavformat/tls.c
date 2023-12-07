/*
 * TLS/SSL Protocol
 * Copyright (c) 2011 Martin Storsjo
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

#include "avformat.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#include "tls.h"
#include "libavutil/avstring.h"
#include "libavutil/getenv_utf8.h"
#include "libavutil/opt.h"
#include "libavutil/parseutils.h"

static void set_options(TLSShared *c, const char *uri)
{
    char buf[1024];
    const char *p = strchr(uri, '?');
    if (!p)
        return;

    if (!c->ca_file && av_find_info_tag(buf, sizeof(buf), "cafile", p)) //@wss add:CA证书
        c->ca_file = av_strdup(buf);

    if (!c->verify && av_find_info_tag(buf, sizeof(buf), "verify", p)) {
        char *endptr = NULL;
        c->verify = strtol(buf, &endptr, 10);
        if (buf == endptr)
            c->verify = 1;
    }

    if (!c->cert_file && av_find_info_tag(buf, sizeof(buf), "cert", p))
        c->cert_file = av_strdup(buf);

    if (!c->key_file && av_find_info_tag(buf, sizeof(buf), "key", p))
        c->key_file = av_strdup(buf);
}

int ff_tls_open_underlying(TLSShared *c, URLContext *parent, const char *uri, AVDictionary **options)
{
    int port;
    const char *p;
    char buf[200], opts[50] = "";
    struct addrinfo hints = { 0 }, *ai = NULL;
    const char *proxy_path;
    char *env_http_proxy, *env_no_proxy;
    int use_proxy;

    set_options(c, uri); //@wss add:把在uri中携带的配置信息提取出来并设置到TLSShared中

    if (c->listen)
        snprintf(opts, sizeof(opts), "?listen=1");

    av_url_split(NULL, 0, NULL, 0, c->underlying_host, sizeof(c->underlying_host), &port, NULL, 0, uri); //@wss add:提取出ip地址和端口号

    p = strchr(uri, '?');

    if (!p) {
        p = opts;
    } else {
        if (av_find_info_tag(opts, sizeof(opts), "listen", p)) //@wss add:区分客户端和服务端
            c->listen = 1;
    }

    ff_url_join(buf, sizeof(buf), "tcp", NULL, c->underlying_host, port, "%s", p); //@wss add:tcp://ip:port

    hints.ai_flags = AI_NUMERICHOST; //@wss add:调用中的节点名必须是一个地址字符串
    if (!getaddrinfo(c->underlying_host, NULL, &hints, &ai)) { //@wss add:该函数返回填充后的addrinfo
        c->numerichost = 1;
        freeaddrinfo(ai);
    }

    if (!c->host && !(c->host = av_strdup(c->underlying_host)))
        return AVERROR(ENOMEM);

    env_http_proxy = getenv_utf8("http_proxy"); //@wss add:http_proxy代理，可提高访问速度以及防火墙属性且更加安全
    proxy_path = c->http_proxy ? c->http_proxy : env_http_proxy;

    env_no_proxy = getenv_utf8("no_proxy");
    use_proxy = !ff_http_match_no_proxy(env_no_proxy, c->underlying_host) && //@wss add:匹配underlying_host中是否有no_proxy字符串
                proxy_path && av_strstart(proxy_path, "http://", NULL);//@wss add没有设置no_proxy且协议以http://开头 那么use_proxy = true
    freeenv_utf8(env_no_proxy);

    if (use_proxy) {
        char proxy_host[200], proxy_auth[200], dest[200];
        int proxy_port;
        av_url_split(NULL, 0, proxy_auth, sizeof(proxy_auth),
                     proxy_host, sizeof(proxy_host), &proxy_port, NULL, 0,
                     proxy_path);
        ff_url_join(dest, sizeof(dest), NULL, NULL, c->underlying_host, port, NULL); //@wss add:dest host:port
        ff_url_join(buf, sizeof(buf), "httpproxy", proxy_auth, proxy_host,
                    proxy_port, "/%s", dest); //@wss add:httpproxy://@autohost:port/host:port
    }
    //@wss add:使用代理buf为httpproxy://@autohost:port/host:port 没使用buf为tcp://ip:port
    freeenv_utf8(env_http_proxy);
    return ffurl_open_whitelist(&c->tcp, buf, AVIO_FLAG_READ_WRITE,
                                &parent->interrupt_callback, options,
                                parent->protocol_whitelist, parent->protocol_blacklist, parent);
}
