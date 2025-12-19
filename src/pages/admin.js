/**
 * 文件名: src/pages/admin.js
 * 修改内容: 修复 WebDAV 推送时 ctx 参数缺失导致报错的问题。
 */
import { getConfig, loadRemoteConfig } from '../config.js';
import { executeWebDavPush } from '../handlers/webdav.js';
import { CONSTANTS } from '../constants.js';
import { cleanList } from '../utils/helpers.js';

// 处理 /edit 页面 (配置编辑器)
export async function handleEditConfig(request, env, ctx) {
    const FileName = await getConfig(env, 'SUBNAME', 'sub');
    
    // 如果没有 KV，报错
    if (!env.KV) {
        return new Response('<p>错误：未绑定KV空间，无法使用在线配置功能。</p>', { status: 404, headers: { "Content-Type": "text/html;charset=utf-8" } });
    }

    // 定义配置项列表 (Key, Label, Description, Placeholder, Type)
    const configItems = [
        ['ADMIN_PASS', '后台管理访问密码', '设置后，通过 /KEY 路径访问管理页需输入此密码。留空则不开启验证。', '例如: 123456', 'text'],
        ['UUID', 'UUID (用户ID/密码)', 'VLESS的用户ID, 也是Trojan/SS的密码。', '例如: 1234567', 'text'],
        ['KEY', '动态UUID密钥', '用于生成动态UUID, 填写后将覆盖上方静态UUID。', '例如: my-secret-key', 'text'],
        ['TIME', '动态UUID有效时间 (天)', '动态UUID的有效周期, 单位为天。', '例如: 1 (表示1天)', 'number'],
        ['UPTIME', '动态UUID更新时间 (小时)', '动态UUID在周期的第几个小时更新。', '例如: 0 (表示0点)', 'number'],
        ['PROXYIP', '出站代理IP (ProxyIP)', 'Worker访问目标网站时使用的IP, 多个用逗号隔开。', '例如: 1.2.3.4 或 [2606::]', 'text'],
        ['SUBNAME', '订阅文件名 (FileName)', '订阅链接下载时的文件名前缀。', '例如: sub.txt', 'text'],
        ['ADD.txt', '优选IP列表 (ADD.txt)', '订阅节点使用的地址列表, 一行一个。', 'usa.visa.com#备注\n1.2.3.4:8443#备注\n[2606:4700::]:2053#IPv6', 'textarea'],
        ['ADDAPI', '优选IP API (ADDAPI)', '远程优选IP列表(TXT格式)的下载链接。', 'https://example.com/ips.txt', 'text'],
        ['ADDNOTLS', '非TLS节点 (ADDNOTLS)', '手动添加非TLS节点(80端口等)。', 'www.example.com:80#备注', 'textarea'],
        ['ADDNOTLSAPI', '非TLS API (ADDNOTLSAPI)', '远程非TLS节点列表的下载链接。', 'https://example.com/notls.txt', 'text'],
        ['ADDCSV', 'CSV测速文件 (ADDCSV)', 'CloudflareSpeedTest 测速结果 CSV 文件的链接。', 'https://example.com/result.csv', 'text'],
        ['CFPORTS', 'CF端口 (httpsPorts)', 'Cloudflare支持的TLS端口, 逗号隔开。', '443,8443,2053,2083,2087,2096', 'text'],
        ['EX', '启用 XHTTP 协议', '是否启用 XHTTP (gRPC 伪装) 协议 (true/false)。', 'false', 'text'],
        ['DNS64', 'NAT64服务器', '用于将IPv4转为IPv6访问 (如无可留空)。', '例如: 64:ff9b::/96', 'text'],
        ['SOCKS5', 'SOCKS5/HTTP代理', 'Worker出站时使用的前置代理 (如无可留空)。', 'user:pass@host:port 或 http://user:pass@host:port', 'text'],
        ['GO2SOCKS5', 'SOCKS5分流规则', '哪些域名走SOCKS5代理, 逗号隔开。', '*example.net,*example.com,all in', 'text'],
        ['BAN', '禁止访问的域名', '禁止通过Worker代理访问的域名, 逗号隔开。', 'example.com,example.org', 'text'],
        ['URL302', '根路径跳转URL (302)', '访问根路径 / 时跳转到的地址。', 'https://github.com/', 'text'],
        ['URL', '根路径反代URL', '访问根路径 / 时反代的地址 (302优先)。', 'https://github.com/', 'text'],
        ['BESTIP_SOURCES', 'BestIP IP源 (JSON)', '自定义BestIP页面的IP源列表 (JSON格式)。', JSON.stringify([
            {"name": "CF官方", "url": "https://www.cloudflare.com/ips-v4/"},
            {"name": "CM整理", "url": "https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt"},
            {"name": "AS13335", "url": "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt"},
            {"name": "AS209242", "url": "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/209242/ipv4-aggregated.txt"}
        ], null, 2), 'textarea'],
    ];

    // 处理 POST 保存请求
    if (request.method === 'POST') {
        try {
            const formData = await request.formData();
            const savePromises = [];
            for (const [key] of configItems) {
                const value = formData.get(key);
                if (value !== null) {
                    if (value === '') {
                        savePromises.push(env.KV.delete(key));
                    } else {
                        if (key === 'BESTIP_SOURCES') {
                            try {
                                JSON.parse(value);
                            } catch (e) {
                                return new Response('保存失败: BestIP IP源 不是有效的 JSON 格式。\n' + e.message, { status: 400 });
                            }
                        }
                        savePromises.push(env.KV.put(key, value));
                    }
                }
            }
            await Promise.all(savePromises);

            // 触发 WebDAV 强制推送
            const hostName = request.headers.get('Host');
            
            // [修复] 获取 enableXhttp 配置，防止 generateBase64Subscription 报错
            const enableXhttp = (await getConfig(env, 'EX', 'false')).toLowerCase() === 'true';
            
            // [修复] 重新构建 ctx 必须包含 httpsPorts 和 enableXhttp
            const newCtx = { 
                userID: await getConfig(env, 'UUID'), 
                dynamicUUID: await getConfig(env, 'KEY'), 
                httpsPorts: CONSTANTS.HTTPS_PORTS, // 关键修复：补充端口列表
                enableXhttp: enableXhttp,          // 关键修复：补充 XHTTP 开关
                waitUntil: ctx.waitUntil.bind(ctx) 
            };
            
            await executeWebDavPush(env, hostName, newCtx, true);

            return new Response('保存成功', { status: 200 });
        } catch (e) {
            return new Response('保存失败: ' + e.message, { status: 500 });
        }
    }
    
    // 处理 GET 渲染页面
    const remoteConfig = await loadRemoteConfig(env);
    const kvPromises = configItems.map(item => env.KV.get(item[0]));
    const kvValues = await Promise.all(kvPromises);
    let formHtml = '';
    
    configItems.forEach(([key, label, desc, placeholder, type], index) => {
        const kvValue = kvValues[index];
        const remoteValue = remoteConfig[key];
        const envValue = env[key];
        let displayValue = kvValue ?? '';
        
        // 如果 KV 为空，显示默认值逻辑 (仅用于显示，不做保存)
        if (kvValue === null) {
             if (key === 'BESTIP_SOURCES') displayValue = placeholder;
        }
        
        let envHint = '';
        if (key !== 'ADD.txt' && key !== 'BESTIP_SOURCES') {
            if (remoteValue) envHint = `<div class="env-hint">远程配置: <code>${remoteValue}</code> (优先级高于环境变量)</div>`;
            else if (envValue) envHint = `<div class="env-hint">环境变量: <code>${envValue}</code></div>`;
        }
        
        const escapeHtml = (str) => { if (!str) return ''; return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;'); };
        let inputField = '';
        if (type === 'textarea') {
            const rows = (key === 'BESTIP_SOURCES' || key === 'ADD.txt' || key === 'ADDNOTLS') ? 8 : 4;
            inputField = `<textarea class="form-control" id="${key}" name="${key}" rows="${rows}" placeholder="${escapeHtml(placeholder)}">${escapeHtml(displayValue)}</textarea>`;
        } else {
            inputField = `<input type="${type}" class="form-control" id="${key}" name="${key}" value="${escapeHtml(displayValue)}" placeholder="${escapeHtml(placeholder)}">`;
        }
        formHtml += `<div class="mb-3"><label for="${key}" class="form-label">${label}</label>${inputField}<div class="form-text">${desc} (留空则使用远程配置、环境变量或默认值)</div>${envHint}</div><hr>`;
    });

    const html = `<!DOCTYPE html><html><head><title>配置管理</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><style>body{background-color:#f8f9fa}.container{max-width:800px;margin-top:20px;margin-bottom:20px;background-color:#fff;padding:2rem;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,.05)}.form-text{font-size:0.875em}.env-hint{font-size:0.8em;color:#6c757d;margin-top:4px}code{color:#d63384}.btn-group{gap:10px}.save-status{margin-left:15px;color:#666}textarea{font-family:monospace;font-size:0.9em}</style></head><body><div class="container">` +
    `<h2>${FileName} 配置设置</h2>` +
    '<p>在此页面修改的配置将保存在KV中, 优先级: <b>KV > 远程配置 > 环境变量</b>。如果某项留空并保存, 则该项配置将回退到使用下级配置或默认值。</p>' +
    '<form id="config-form">' + formHtml + '<div class="btn-group"><button type="button" class="btn btn-secondary" onclick="goBack()">返回配置页</button><button type="button" class="btn btn-info" onclick="goBestIP()">在线优选IP</button><button type="submit" class="btn btn-primary" id="save-btn">保存所有配置</button><span class="save-status" id="saveStatus"></span></div></form>' +
    '<script>function goBack(){const e=window.location.pathname.substring(0,window.location.pathname.lastIndexOf("/"));window.location.href=e+"/"}function goBestIP(){window.location.href=window.location.pathname.replace("/edit","/bestip")}document.getElementById("config-form").addEventListener("submit",function(e){e.preventDefault();const t=document.getElementById("save-btn"),n=document.getElementById("saveStatus"),o=new FormData(this),a=o.get("BESTIP_SOURCES");if(a)try{JSON.parse(a)}catch(e){return alert("保存失败: BestIP IP源 不是有效的 JSON 格式。\\n"+(e.message||e)),n.textContent="保存出错: JSON 格式错误",void 0}t.disabled=!0,t.textContent="保存中...",n.textContent="",fetch(window.location.href,{method:"POST",body:o}).then(e=>{if(e.ok){const o=(new Date).toLocaleString();n.textContent="保存成功 "+o,alert("保存成功！部分设置可能需要几秒钟生效。")}else return e.text().then(e=>Promise.reject(e))}).catch(e=>{n.textContent="保存出错: "+e}).finally(()=>{t.disabled=!1,t.textContent="保存所有配置"})});</script></body></html>';
    return new Response(html, { headers: { "Content-Type": "text/html;charset=utf-8" } });
}

export async function handleBestIP(request, env) {
    const url = new URL(request.url);
    const txt = 'ADD.txt'; // 默认保存到 ADD.txt

    // 1. 处理测试请求 API
    if (url.searchParams.get('action') === 'test') {
        const ip = url.searchParams.get('ip');
        const port = url.searchParams.get('port');
        if (!ip || !port) {
            return new Response(JSON.stringify({ error: 'Missing ip or port' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }
        const testUrl = 'https://cloudflare.com/cdn-cgi/trace';
        const startTime = Date.now();
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            const response = await fetch(testUrl, {
                method: "GET",
                headers: { "Accept": "text/plain" },
                signal: controller.signal,
                resolveOverride: ip
            });
            clearTimeout(timeoutId);
            if (!response.ok) {
                 throw new Error(`HTTP error! status: ${response.status}`);
            }
            const traceText = await response.text();
            const latency = Date.now() - startTime;
            const coloMatch = traceText.match(/colo=([A-Z]{3})/);
            const result = {
                ip: ip,
                port: port,
                latency: latency,
                colo: coloMatch ? coloMatch[1] : "N/A"
            };
            return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
        } catch (e) {
            return new Response(JSON.stringify({
                ip: ip,
                port: port,
                latency: 9999,
                colo: "FAIL"
            }), { headers: { 'Content-Type': 'application/json' } });
        }
    }
    
    // 2. 处理保存请求 API
    if (request.method === "POST") {
        if (!env.KV) return new Response(JSON.stringify({ error: '未绑定KV空间' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        try {
            const data = await request.json();
            const action = url.searchParams.get('action') || 'save';
            if (action === 'append') {
                const existing = await env.KV.get(txt) || '';
                const newContent = [...new Set([...existing.split('\n'), ...data.ips].filter(Boolean))].join('\n');
                await env.KV.put(txt, newContent);
                return new Response(JSON.stringify({ success: true, message: '追加成功' }), { headers: { 'Content-Type': 'application/json' } });
            } else {
                await env.KV.put(txt, data.ips.join('\n'));
                return new Response(JSON.stringify({ success: true, message: '保存成功' }), { headers: { 'Content-Type': 'application/json' } });
            }
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
        }
    }

    // 3. 处理 IP 源加载 API
    const defaultIpSources = [
        {"name": "CF官方", "url": "https://www.cloudflare.com/ips-v4/"},
        {"name": "CM整理", "url": "https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt"},
        {"name": "AS13335", "url": "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt"},
        {"name": "AS209242", "url": "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/209242/ipv4-aggregated.txt"}
    ];
    let ipSources = defaultIpSources;
    if (env.KV) {
        const kvData = await env.KV.get('BESTIP_SOURCES');
        const remoteData = await getConfig(env, 'BESTIP_SOURCES'); // 使用 getConfig 获取远程
        if (kvData || remoteData) {
            try {
                const parsedSources = JSON.parse(kvData || remoteData);
                if (Array.isArray(parsedSources) && parsedSources.every(s => s.name && s.url)) {
                    ipSources = parsedSources;
                }
            } catch (e) { console.error("解析 BESTIP_SOURCES 失败"); }
        }
    }
    const allIpSources = [...ipSources, {"name": "反代IP列表", "url": "proxyip"}];

    if (url.searchParams.has('loadIPs')) {
        const ipSourceName = url.searchParams.get('loadIPs');
        async function GetCFIPs(sourceName) {
            try {
                let response;
                const source = allIpSources.find(s => s.name === sourceName);
                if (sourceName === '反代IP列表') {
                    // 使用硬编码的白嫖列表作为示例
                    response = await fetch('https://raw.githubusercontent.com/cmliu/ACL4SSR/main/baipiao.txt');
                    const text = response.ok ? await response.text() : '';
                    return text.split('\n').map(l => l.trim()).filter(Boolean);
                } else if (source) {
                    response = await fetch(source.url);
                } else {
                    response = await fetch(allIpSources[0].url);
                }
                const text = response.ok ? await response.text() : '';
                const cidrs = text.split('\n').filter(line => line.trim() && !line.startsWith('#'));
                const ips = new Set();
                // 简单的 CIDR 转 IP 随机生成逻辑
                while (ips.size < 512 && cidrs.length > 0) {
                    for (const cidr of cidrs) {
                        if (ips.size >= 512) break;
                        try {
                            if (!cidr.includes('/')) { ips.add(cidr); continue; }
                            const [network, prefixStr] = cidr.split('/');
                            const prefix = parseInt(prefixStr);
                            if (prefix < 12 || prefix > 31) continue;
                            const ipToInt = (ip) => ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
                            const intToIp = (int) => [(int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255].join('.');
                            const networkInt = ipToInt(network);
                            const hostBits = 32 - prefix;
                            const numHosts = 1 << hostBits;
                            if (numHosts > 2) {
                                const randomOffset = Math.floor(Math.random() * (numHosts - 2)) + 1;
                                ips.add(intToIp(networkInt + randomOffset));
                            }
                        } catch (e) {}
                    }
                    if (cidrs.length === 0) break;
                }
                return Array.from(ips);
            } catch (error) { return []; }
        }
        const ips = await GetCFIPs(ipSourceName);
        return new Response(JSON.stringify({ ips }), { headers: { 'Content-Type': 'application/json' } });
    }

    // 4. 渲染页面 HTML
    const ipSourceOptions = allIpSources.map(s => `<option value="${s.name}">${s.name}</option>`).join('\n');
    const html = `<!DOCTYPE html><html><head><title>Cloudflare IP优选</title><style>body{width:80%;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;padding:20px}.ip-list{background-color:#f5f5f5;padding:10px;border-radius:5px;max-height:400px;overflow-y:auto}.ip-item{margin:2px 0;font-family:monospace}.stats{background-color:#e3f2fd;padding:15px;border-radius:5px;margin:20px 0}.test-controls{margin-bottom:20px}.button-group{display:flex;gap:10px}.test-button,.save-button,.append-button,.edit-button,.back-button{background-color:#4CAF50;color:white;padding:15px 32px;text-align:center;text-decoration:none;display:inline-block;font-size:16px;cursor:pointer;border:none;border-radius:4px}.save-button{background-color:#2196F3}.append-button{background-color:#FF9800}.edit-button{background-color:#9C27B0}.back-button{background-color:#607D8B}.test-button:disabled,.save-button:disabled,.append-button:disabled{background-color:#cccccc;cursor:not-allowed}.message{padding:10px;margin:10px 0;border-radius:4px;display:none}.message.success{background-color:#d4edda;color:#155724}.message.error{background-color:#f8d7da;color:#721c24}.progress{width:100%;background-color:#f0f0f0;border-radius:5px;margin-top:10px}.progress-bar{width:0%;height:20px;background-color:#4CAF50;border-radius:5px;transition:width .3s;text-align:center;color:white;line-height:20px}.good-latency{color:#4CAF50;font-weight:700}.medium-latency{color:#FF9800;font-weight:700}.bad-latency{color:#f44336;font-weight:700}</style></head><body><h1>在线优选IP</h1><div class="test-controls"><div class="port-selector"style="margin-bottom:10px"><label for="ip-source-select">IP库：</label>` +
`<select id="ip-source-select">${ipSourceOptions}</select> ` +
`<label for="port-select">端口：</label><select id="port-select"><option value="443">443</option><option value="2053">2053</option><option value="2083">2083</option><option value="2087">2087</option><option value="2096">2096</option><option value="8443">8443</option></select>` +
`</div><div class="button-group"><button class="test-button" id="test-btn">开始延迟测试</button><button class="save-button" id="save-btn" disabled>覆盖保存优选IP</button><button class="append-button" id="append-btn" disabled>追加保存优选IP</button><button class="edit-button" onclick="goEdit()">编辑优选列表</button><button class="back-button" onclick="goBack()">返回配置页</button></div></div><div class="stats"><p><strong>IP总数：</strong> <span id="ip-count">0</span></p><p><strong>测试进度：</strong> <span id="progress-text">未开始</span></p><div class="progress"><div class="progress-bar" id="progress-bar"></div></div></div><h2>IP列表 (结果已按延迟排序)</h2><div class="ip-list" id="ip-list">请选择端口和IP库，然后点击"开始延迟测试"</div><div id="message" class="message"></div>` +
`<script>` +
`let testResults=[],originalIPs=[];const testBtn=document.getElementById("test-btn"),saveBtn=document.getElementById("save-btn"),appendBtn=document.getElementById("append-btn"),ipList=document.getElementById("ip-list"),ipCount=document.getElementById("ip-count"),progressBar=document.getElementById("progress-bar"),progressText=document.getElementById("progress-text"),portSelect=document.getElementById("port-select"),ipSourceSelect=document.getElementById("ip-source-select");` +
`function getBasePath() {return window.location.pathname.substring(0, window.location.pathname.lastIndexOf("/"));}` +
`function goEdit(){window.location.href = getBasePath() + "/edit";}` +
`function goBack(){window.location.href = getBasePath() + "/";}` +
`async function testIP(e,t){const n=Date.now();try{const response = await fetch('?action=test&ip=' + e + '&port=' + t, {method:"GET",signal:AbortSignal.timeout(3e3)});if(response.ok){const data=await response.json();return data}}catch(err){console.error('Test failed for ' + e + ':' + t,err.name,err.message)}return null}` +
`async function startTest(){testBtn.disabled=!0,testBtn.textContent="测试中...",saveBtn.disabled=!0,appendBtn.disabled=!0,ipList.innerHTML="正在加载IP列表...";const e=portSelect.value,t=ipSourceSelect.value;try{const n=(await(await fetch('?loadIPs=' + encodeURIComponent(t) + '&port=' + e)).json()).ips;originalIPs=n,ipCount.textContent=originalIPs.length,testResults=[],ipList.innerHTML="开始测试...",progressBar.style.width="0%",progressBar.textContent="",progressText.textContent="0/0";let o=0;const s=Math.min(32,originalIPs.length);let i=0;await new Promise(e=>{const t=()=>{if(i>=originalIPs.length){if(0==--o)return void e();return}const n=originalIPs[i++];testIP(n,portSelect.value).then(e=>{if(e&&e.colo!=="FAIL"){testResults.push(e)}progressBar.style.width = (100*(i/originalIPs.length)) + '%';progressBar.textContent = Math.round(100*(i/originalIPs.length)) + '%';progressText.textContent = i + '/' + originalIPs.length;t()})};for(let n=0;n<s;n++)o++,t()});testResults.sort((e,t)=>e.latency-t.latency),ipList.innerHTML=testResults.map(function(e) {var latencyClass = e.latency<100 ? "good-latency" : (e.latency<200 ? "medium-latency" : "bad-latency");return '<div class="ip-item ' + latencyClass + '">' + e.ip + ':' + e.port + '#' + e.colo + ' - ' + e.latency + 'ms</div>';}).join(""),saveBtn.disabled=0===testResults.length,appendBtn.disabled=0===testResults.length}catch(e){ipList.innerHTML="加载IP列表失败",console.error(e)}finally{testBtn.disabled=!1,testBtn.textContent="开始延迟测试"}}` +
`async function saveIPs(e){const t=testResults.slice(0,16).map(function(e) { return e.ip + ':' + e.port + '#' + e.colo; });try{const n=(await(await fetch('?action=' + e,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ips:t})})).json());showMessage(n.message||n.error,n.success)}catch(e){showMessage("操作失败: "+e.message,!1)}}` +
`function showMessage(e,t){const n=document.getElementById("message");n.textContent=e;n.className = 'message ' + (t ? 'success' : 'error');n.style.display="block",setTimeout(()=>{n.style.display="none"},3e3)}testBtn.addEventListener("click",startTest),saveBtn.addEventListener("click",()=>saveIPs("save"));appendBtn.addEventListener("click",()=>saveIPs("append"));` +
`</script></body></html>`;

    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
}
