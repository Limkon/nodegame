/**
 * 文件名: src/pages/home.js
 */
import { CONSTANTS } from '../constants.js';
import { sha1 } from '../utils/helpers.js';

export async function generateHomePage(env, ctx, hostName) {
    const FileName = await env.KV?.get('SUBNAME') || env.SUBNAME || 'sub';
    const isWorkersDev = hostName.includes("workers.dev");
    const httpPorts = CONSTANTS.HTTP_PORTS;
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560'; // Default VLESS path
    const cdnIP = ctx.proxyIP || 'cloudflare.com';
    
    // 计算订阅路径哈希
    const subPathNames = [
        'all', 'all-tls', 'all-clash', 'all-clash-tls', 'all-sb', 'all-sb-tls',
        'vless', 'vless-tls', 'vless-clash', 'vless-clash-tls', 'vless-sb', 'vless-sb-tls',
        'trojan', 'trojan-tls', 'trojan-clash', 'trojan-clash-tls', 'trojan-sb', 'trojan-sb-tls',
        'ss', 'ss-tls', 'ss-clash', 'ss-clash-tls', 'ss-sb', 'ss-sb-tls',
        'socks', 'socks-tls', 'socks-clash', 'socks-clash-tls', 'socks-sb', 'socks-sb-tls',
        'mandala-tls', // [新增] Mandala 单独订阅路径
        'xhttp-tls', 'xhttp-clash-tls', 'xhttp-sb-tls'
    ];
    
    // 生成 Hash 映射
    const hashPromises = subPathNames.map(p => sha1(p));
    const hashes = (await Promise.all(hashPromises)).map(h => h.toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH));
    const subs = {};
    
    // 订阅前缀
    const userHash = (await sha1(ctx.dynamicUUID)).toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH);
    const subPathPrefix = `/${userHash}`;

    subPathNames.forEach((name, i) => {
        const key = name.replace(/-/g, '_');
        subs[key] = `https://${hostName}${subPathPrefix}${hashes[i]}`;
    });

    // 生成节点链接示例
    const vless_tls = `vless://${ctx.userID}@${hostName}:${httpsPorts[0]}?encryption=none&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${hostName}-VLESS-TLS`;
    const trojan_tls = `trojan://${ctx.dynamicUUID}@${hostName}:${httpsPorts[0]}?security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${hostName}-TROJAN-TLS`;
    
    const ss_b64 = btoa(`none:${ctx.dynamicUUID}`);
    const ss_tls = `ss://${ss_b64}@${hostName}:${httpsPorts[0]}/?plugin=${encodeURIComponent(`v2ray-plugin;tls;host=${hostName};sni=${hostName};path=${encodeURIComponent(path)}`)}#${hostName}-SS-TLS`;
    
    const socks_auth = btoa(`${ctx.userID}:${ctx.dynamicUUID}`);
    const socks_tls = `socks://${socks_auth}@${hostName}:${httpsPorts[0]}?transport=ws&security=tls&sni=${hostName}&path=${encodeURIComponent(path)}#${hostName}-SOCKS-TLS`;
    
    // [新增] Mandala 链接生成
    // 格式: mandala://password@host:port?params#remark
    const mandala_tls = `mandala://${ctx.dynamicUUID}@${hostName}:${httpsPorts[0]}?security=tls&sni=${hostName}&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${hostName}-MANDALA-TLS`;
    
    const xhttp_tls = `vless://${ctx.userID}@${hostName}:${httpsPorts[0]}?encryption=none&security=tls&sni=${hostName}&fp=random&allowInsecure=1&type=xhttp&host=${hostName}&path=${encodeURIComponent('/' + ctx.userID.substring(0, 8))}&mode=stream-one#${hostName}-XHTTP-TLS`;

    // HTML 模板片段
    const copyBtn = (val) => `<div class="input-group mb-2"><input type="text" class="form-control" value="${val}" readonly><button class="btn btn-secondary" onclick="copyToClipboard('${val}')">复制</button></div>`;
    
    let xhttpHtml = '';
    // [修改] 标题增加 Mandala
    let mixedTitle = '混合订阅 (VLESS+Trojan+SS+Socks5+Mandala)'; 

    if (ctx.enableXhttp) {
        mixedTitle = '混合订阅 (VLESS+Trojan+Mandala+XHTTP+SS+Socks5)';
        xhttpHtml = `<hr><h2 class="mt-4">XHTTP 节点 (VLESS)</h2>` +
            `<h3>Vless+xhttp+tls</h3>` +
            `<div class="input-group mb-3"><input type="text" class="form-control" value="${xhttp_tls}" readonly><button class="btn btn-outline-secondary" onclick="copyToClipboard('${xhttp_tls}')">复制</button></div>`;
    }

    const managementPath = '/' + ctx.dynamicUUID.toLowerCase();

    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>节点信息</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><style>.container{max-width:900px} .input-group{flex-wrap:nowrap} .form-control{min-width:100px}</style></head><body><div class="container mt-4 mb-4">` +
    `<h1>${FileName} 代理节点管理</h1><hr>` +
    `<h2>${mixedTitle}</h2>` +
    `<p class="text-danger"><b>(注意: 订阅链接已包含访问密钥，请勿泄露)</b></p>` +
    (isWorkersDev ? `<b>所有协议 (含无TLS):</b>${copyBtn(subs.all)}` : '') +
    `<b>通用订阅 (推荐 TLS):</b>${copyBtn(subs.all_tls)}` +
    `<b>Clash-Meta (TLS):</b>${copyBtn(subs.all_clash_tls)}` +
    `<b>Sing-Box (TLS):</b>${copyBtn(subs.all_sb_tls)}` +
    `<hr>` +
    `<h2>管理工具</h2>` +
    `<div class="mb-2"><a href="${managementPath}/edit" class="btn btn-primary">编辑配置</a> <a href="${managementPath}/bestip" class="btn btn-info">在线优选IP</a></div>` +
    `<hr>` +
    `<h2>节点详情</h2>` +
    `<h3>VLESS TLS</h3>${copyBtn(vless_tls)}` +
    `<h3>Trojan TLS</h3>${copyBtn(trojan_tls)}` +
    `<h3>Mandala TLS</h3>${copyBtn(mandala_tls)}` +
    `<h3>Shadowsocks TLS</h3>${copyBtn(ss_tls)}` +
    `<h3>Socks5 TLS</h3>${copyBtn(socks_tls)}` +
    xhttpHtml +
    `</div><script>function copyToClipboard(text){navigator.clipboard.writeText(text).then(function(){alert("已复制")}, function(err){alert("复制失败")});}</script></body></html>`;
}
