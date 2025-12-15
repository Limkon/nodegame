/**
 * 文件名: src/pages/generators.js
 * 说明: 
 * 1. 包含 Base64、Clash、SingBox 的订阅生成逻辑。
 * 2. 修复了 XHTTP 协议的 Headers (User-Agent/Content-Type) 和 path 生成。
 * 3. Socks5 节点采用 Base64 编码认证信息，解决客户端导入问题。
 * 4. 支持 noLinks 参数以防止 WebDAV 推送时节点重复。
 * 5. [新增] 支持 Mandala 协议链接生成。
 */
import { CONSTANTS } from '../constants.js';

// 辅助函数：生成 Base64 节点链接
export function generateBase64Subscription(protocol, id, hostName, tlsOnly, ctx, noLinks = false) {
    let finalLinks = [];
    const httpPorts = CONSTANTS.HTTP_PORTS;
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560'; // 对齐原代码

    const createLink = (addr, useTls) => {
        const portList = useTls ? httpsPorts : httpPorts;
        const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
        if (!match) return;
        
        const ip = match[1];
        const port = match[2] || portList[0];
        const remark = match[3] || `${hostName}-${protocol.toUpperCase()}`;
        
        if (protocol === 'xhttp') {
             const xhttpPath = '/' + id.substring(0, 8);
             finalLinks.push(`vless://${id}@${ip}:${port}?encryption=none&security=tls&sni=${hostName}&fp=random&allowInsecure=1&type=xhttp&host=${hostName}&path=${encodeURIComponent(xhttpPath)}&mode=stream-one#${encodeURIComponent(remark)}`);
        } else if (protocol === 'vless') {
             const security = useTls ? `&security=tls&sni=${hostName}&fp=random` : '&security=none';
             finalLinks.push(`vless://${id}@${ip}:${port}?encryption=none${security}&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`);
        } else if (protocol === 'trojan') {
             const security = useTls ? `&security=tls&sni=${hostName}&fp=random` : '&security=none';
             finalLinks.push(`trojan://${id}@${ip}:${port}?${security}&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`);
        } else if (protocol === 'mandala') {
             // [新增] Mandala 协议
             const security = useTls ? `&security=tls&sni=${hostName}` : '';
             finalLinks.push(`mandala://${id}@${ip}:${port}?type=ws&host=${hostName}&path=${encodeURIComponent(path)}${security}#${encodeURIComponent(remark)}`);
        } else if (protocol === 'ss') {
             const ss_method = 'none';
             const ss_b64 = btoa(`${ss_method}:${id}`);
             let plugin_opts = `v2ray-plugin;host=${hostName};path=${encodeURIComponent(path)}`;
             if (useTls) plugin_opts += `;tls;sni=${hostName}`;
             finalLinks.push(`ss://${ss_b64}@${ip}:${port}/?plugin=${encodeURIComponent(plugin_opts)}#${encodeURIComponent(remark)}`);
        } else if (protocol === 'socks') {
             const security = useTls ? `security=tls&sni=${hostName}&path=${encodeURIComponent(path)}` : `path=${encodeURIComponent(path)}`;
             // [修复] 将 User:Pass 进行 Base64 编码，解决导入无密码问题
             // 格式: socks://BASE64(User:Pass)@Host:Port?params#Remark
             const password = ctx.dynamicUUID || ctx.userID;
             const auth = btoa(`${id}:${password}`);
             finalLinks.push(`socks://${auth}@${ip}:${port}?${security}&transport=ws#${encodeURIComponent(remark)}`);
        }
    };

    if (ctx.addresses) ctx.addresses.forEach(addr => createLink(addr, true));
    if (!tlsOnly && ctx.addressesnotls) ctx.addressesnotls.forEach(addr => createLink(addr, false));

    // 仅当 noLinks 为 false 且协议不是 xhttp 时才附加硬编码链接
    if (!noLinks && protocol !== 'xhttp' && ctx.hardcodedLinks) {
        finalLinks = finalLinks.concat(ctx.hardcodedLinks);
    }

    return finalLinks.join('\n');
}

// 生成 Clash 配置 (单协议)
export function generateClashConfig(protocol, id, hostName, tlsOnly, ctx) {
    let proxies = [];
    const proxyNames = [];
    const httpPorts = CONSTANTS.HTTP_PORTS;
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560';
    
    const createProxy = (addr, useTls) => {
        const portList = useTls ? httpsPorts : httpPorts;
        const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
        if (!match) return;

        const ip = match[1];
        const port = match[2] || portList[0];
        const remark = match[3] || `${hostName}-${protocol.toUpperCase()}`;
        
        let proxy = {
            name: remark,
            type: protocol === 'xhttp' ? 'vless' : (protocol === 'ss' ? 'ss' : (protocol === 'socks' ? 'socks5' : protocol)),
            server: ip,
            port: parseInt(port),
            tls: useTls,
            'skip-cert-verify': true,
            udp: false
        };

        if (protocol === 'vless' || protocol === 'xhttp') {
            proxy.uuid = id;
            proxy.cipher = 'auto';
        } else if (protocol === 'trojan') {
            proxy.password = id;
        } else if (protocol === 'ss') {
            proxy.cipher = 'none';
            proxy.password = id;
            proxy.plugin = 'v2ray-plugin';
            proxy['plugin-opts'] = {
                mode: 'websocket',
                tls: useTls,
                host: hostName,
                path: path
            };
            if (useTls) proxy['plugin-opts'].sni = hostName;
        } else if (protocol === 'socks') {
            proxy.username = id;
            proxy.password = ctx.dynamicUUID || ctx.userID;
        } 
        // Mandala 暂不支持 Clash，此处会跳过相关配置生成

        if (protocol === 'xhttp') {
            proxy.network = 'xhttp';
            proxy['xhttp-opts'] = {
                mode: 'stream-one',
                path: '/' + id.substring(0, 8),
                headers: {
                    'Host': hostName,
                    'Content-Type': 'application/grpc',
                    'User-Agent': 'Go-http-client/2.0'
                }
            };
            proxy.servername = hostName;
        } else if (protocol !== 'ss' && protocol !== 'mandala') { // Mandala 不支持 Clash
            proxy.network = 'ws';
            proxy['ws-opts'] = {
                path: path,
                headers: { Host: hostName }
            };
            if (useTls) proxy.servername = hostName;
        }

        // 仅添加支持的协议
        if (protocol !== 'mandala') {
            proxies.push(proxy);
            proxyNames.push(remark);
        }
    };

    if (ctx.addresses) ctx.addresses.forEach(addr => createProxy(addr, true));
    if (!tlsOnly && ctx.addressesnotls) ctx.addressesnotls.forEach(addr => createProxy(addr, false));

    return buildClashYaml(proxies, proxyNames);
}

// 生成混合 Clash 配置 (VLESS + Trojan + SS + Socks5 + XHTTP)
export function generateMixedClashConfig(vlessId, trojanPass, hostName, tlsOnly, enableXhttp, ctx) {
    let proxies = [];
    const proxyNames = [];
    const httpPorts = CONSTANTS.HTTP_PORTS;
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560';

    const createMixedProxy = (protocol, addr, useTls) => {
        const portList = useTls ? httpsPorts : httpPorts;
        const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
        if (!match) return;

        const ip = match[1];
        const port = match[2] || portList[0];
        const remark = match[3] ? `${protocol.toUpperCase()}-${match[3]}` : `${hostName}-${protocol.toUpperCase()}`;
        
        let proxy = {
            name: remark,
            type: protocol === 'xhttp' ? 'vless' : (protocol === 'ss' ? 'ss' : (protocol === 'socks' ? 'socks5' : protocol)),
            server: ip,
            port: parseInt(port),
            tls: useTls,
            'skip-cert-verify': true,
            udp: false
        };

        if (protocol === 'vless' || protocol === 'xhttp') {
            proxy.uuid = vlessId;
            proxy.cipher = 'auto';
        } else if (protocol === 'trojan') {
            proxy.password = trojanPass;
        } else if (protocol === 'ss') {
            proxy.cipher = 'none';
            proxy.password = trojanPass;
            proxy.plugin = 'v2ray-plugin';
            proxy['plugin-opts'] = {
                mode: 'websocket',
                tls: useTls,
                host: hostName,
                path: path
            };
            if (useTls) proxy['plugin-opts'].sni = hostName;
        } else if (protocol === 'socks') {
            proxy.username = vlessId;
            proxy.password = trojanPass;
        }

        if (protocol === 'xhttp') {
            proxy.network = 'xhttp';
            proxy['xhttp-opts'] = {
                mode: 'stream-one',
                path: '/' + vlessId.substring(0, 8),
                headers: {
                    'Host': hostName,
                    'Content-Type': 'application/grpc',
                    'User-Agent': 'Go-http-client/2.0'
                }
            };
            proxy.servername = hostName;
        } else if (protocol !== 'ss') {
            proxy.network = 'ws';
            proxy['ws-opts'] = {
                path: path,
                headers: { Host: hostName }
            };
            if (useTls) proxy.servername = hostName;
        }

        proxies.push(proxy);
        proxyNames.push(remark);
    };

    const protocols = ['vless', 'trojan', 'ss', 'socks'];
    if (enableXhttp) protocols.push('xhttp');
    // Mandala 不加入 Clash 混合订阅

    if (ctx.addresses) {
        ctx.addresses.forEach(addr => {
            protocols.forEach(p => {
                if (p === 'xhttp') createMixedProxy(p, addr, true);
                else createMixedProxy(p, addr, true);
            });
        });
    }
    
    if (!tlsOnly && ctx.addressesnotls) {
        ctx.addressesnotls.forEach(addr => {
            protocols.forEach(p => {
                if (p !== 'xhttp') createMixedProxy(p, addr, false);
            });
        });
    }

    return buildClashYaml(proxies, proxyNames);
}

// 辅助函数: 构建 Clash YAML 字符串
function buildClashYaml(proxies, proxyNames) {
    const yamlProxies = proxies.map(p => {
        let s = `- name: ${p.name}\n  type: ${p.type}\n  server: ${p.server}\n  port: ${p.port}\n  tls: ${p.tls}\n  udp: ${p.udp}\n  skip-cert-verify: true\n`;
        if(p.uuid) s += `  uuid: ${p.uuid}\n`;
        if(p.password) s += `  password: "${p.password}"\n`;
        if(p.username) s += `  username: "${p.username}"\n`;
        if(p.cipher) s += `  cipher: ${p.cipher}\n`;
        if(p.network) s += `  network: ${p.network}\n`;
        if(p.servername) s += `  servername: ${p.servername}\n`;
        if(p['ws-opts']) {
            s += `  ws-opts:\n    path: "${p['ws-opts'].path}"\n    headers:\n      Host: ${p['ws-opts'].headers.Host}\n`;
        }
        if(p['xhttp-opts']) {
            s += `  xhttp-opts:\n    mode: ${p['xhttp-opts'].mode}\n    path: "${p['xhttp-opts'].path}"\n    headers:\n      Host: ${p['xhttp-opts'].headers.Host}\n      Content-Type: ${p['xhttp-opts'].headers['Content-Type']}\n      User-Agent: ${p['xhttp-opts'].headers['User-Agent']}\n`;
        }
        if(p.plugin) {
            s += `  plugin: ${p.plugin}\n  plugin-opts:\n    mode: ${p['plugin-opts'].mode}\n    tls: ${p['plugin-opts'].tls}\n    host: ${p['plugin-opts'].host}\n    path: "${p['plugin-opts'].path}"\n`;
            if (p['plugin-opts'].sni) s += `    sni: ${p['plugin-opts'].sni}\n`;
        }
        return s;
    }).join('');

    return `port: 7890
allow-lan: true
mode: rule
log-level: info
proxies:
${yamlProxies}
proxy-groups:
- name: 节点选择
  type: select
  proxies:
  - 自动选择
  - DIRECT
${proxyNames.map(n => `  - ${n}`).join('\n')}
- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
${proxyNames.map(n => `  - ${n}`).join('\n')}
rules:
- MATCH,节点选择`;
}

// 生成 SingBox 配置 (单协议)
export function generateSingBoxConfig(protocol, id, hostName, tlsOnly, ctx) {
    if (protocol === 'mandala') return '{}'; // Mandala 暂不支持 SingBox
    return generateMixedSingBoxConfig(id, ctx.dynamicUUID, hostName, tlsOnly, false, ctx, [protocol]);
}

// 生成混合 SingBox 配置
export function generateMixedSingBoxConfig(vlessId, trojanPass, hostName, tlsOnly, enableXhttp, ctx, protocolsFilter = null) {
    let outbounds = [];
    const httpPorts = CONSTANTS.HTTP_PORTS;
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560';

    const createMixedOutbound = (protocol, addr, useTls) => {
        const portList = useTls ? httpsPorts : httpPorts;
        const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
        if (!match) return;

        const ip = match[1];
        const port = match[2] || portList[0];
        const remark = match[3] ? `${protocol.toUpperCase()}-${match[3]}` : `${hostName}-${protocol.toUpperCase()}`;
        
        let outbound = {
            type: protocol === 'xhttp' ? 'vless' : (protocol === 'ss' ? 'shadowsocks' : (protocol === 'socks' ? 'socks5' : protocol)),
            tag: remark,
            server: ip,
            server_port: parseInt(port)
        };

        if (protocol === 'vless' || protocol === 'xhttp') {
            outbound.uuid = vlessId;
            outbound.packet_encoding = "packetaddr";
        } else if (protocol === 'trojan') {
            outbound.password = trojanPass;
        } else if (protocol === 'ss') {
            outbound.method = 'none';
            outbound.password = trojanPass;
        } else if (protocol === 'socks') {
            outbound.username = vlessId;
            outbound.password = trojanPass;
        }

        if (protocol === 'xhttp') {
            outbound.transport = {
                type: 'xhttp',
                mode: 'stream-one',
                path: '/' + vlessId.substring(0, 8),
                headers: { 
                    Host: hostName,
                    "Content-Type": "application/grpc",
                    "User-Agent": "Go-http-client/2.0"
                }
            };
        } else {
             outbound.transport = {
                type: 'ws',
                path: path,
                headers: { Host: hostName }
            };
        }

        if (useTls) {
            outbound.tls = {
                enabled: true,
                server_name: hostName,
                insecure: true,
                utls: { enabled: true, fingerprint: "chrome" }
            };
        }

        outbounds.push(outbound);
    };

    let protocols = protocolsFilter || ['vless', 'trojan', 'ss', 'socks'];
    if (!protocolsFilter && enableXhttp) protocols.push('xhttp');

    if (ctx.addresses) {
        ctx.addresses.forEach(addr => {
            protocols.forEach(p => {
                if (p === 'xhttp') createMixedOutbound(p, addr, true);
                else createMixedOutbound(p, addr, true);
            });
        });
    }
    
    if (!tlsOnly && ctx.addressesnotls) {
        ctx.addressesnotls.forEach(addr => {
            protocols.forEach(p => {
                if (p !== 'xhttp') createMixedOutbound(p, addr, false);
            });
        });
    }

    const tags = outbounds.map(o => o.tag);

    return JSON.stringify({
        "log": {"level": "info"},
        "inbounds": [{"type": "tun", "tag": "tun-in"}],
        "outbounds": [
            {
                "type": "selector",
                "tag": "select",
                "outbounds": ["auto", "direct", ...tags]
            },
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": "http://www.gstatic.com/generate_204"
            },
            { "type": "direct", "tag": "direct" },
            ...outbounds
        ],
        "route": {
            "final": "select",
            "rules": [
                {"protocol": "dns", "outbound": "direct"}
            ]
        }
    }, null, 2);
}
