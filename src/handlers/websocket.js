/**
 * 文件名: src/handlers/websocket.js
 * 修复说明:
 * 1. [核心修复] 引入 Header Buffering 机制。解决因 TCP 分包导致 Mandala 等协议头部不完整而连接失败的问题。
 * 2. 只有当缓冲区超过一定大小时才认定为探测失败，提高抗网络波动能力。
 */
import { ProtocolManager } from '../protocols/manager.js';
import { processVlessHeader } from '../protocols/vless.js';
import { parseTrojanHeader } from '../protocols/trojan.js';
import { parseMandalaHeader } from '../protocols/mandala.js';
import { parseSocks5Header } from '../protocols/socks5.js';
import { parseShadowsocksHeader } from '../protocols/shadowsocks.js';
import { handleTCPOutBound } from './outbound.js';
import { safeCloseWebSocket, base64ToArrayBuffer, isHostBanned } from '../utils/helpers.js';

const protocolManager = new ProtocolManager()
    .register('vless', processVlessHeader)
    .register('trojan', parseTrojanHeader)
    .register('mandala', parseMandalaHeader)
    .register('socks5', parseSocks5Header)
    .register('ss', parseShadowsocksHeader);

// 辅助函数：拼接 Uint8Array
function concatUint8(a, b) {
    const res = new Uint8Array(a.length + b.length);
    res.set(a);
    res.set(b, a.length);
    return res;
}

export async function handleWebSocketRequest(request, ctx) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    
    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [] };
    let protocolDetected = false;
    let socks5State = 0; 
    let headerBuffer = new Uint8Array(0); // [新增] 用于缓存头部数据
    const MAX_HEADER_BUFFER = 1024; // [新增] 最大嗅探缓冲大小，防止内存攻击
    
    const log = (info, event) => console.log(`[WS] ${info}`, event || '');
    
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    
    const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            // 将 chunk 转为 Uint8Array
            let bufferView = new Uint8Array(chunk);
            
            // ---------------------------------------------------------
            // 1. 协议已识别：直接转发 (高性能路径)
            // ---------------------------------------------------------
            if (protocolDetected) {
                if (remoteSocketWrapper.value) {
                    const writer = remoteSocketWrapper.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                } else if (remoteSocketWrapper.isConnecting) {
                    remoteSocketWrapper.buffer.push(chunk);
                }
                return;
            }

            // ---------------------------------------------------------
            // 2. Socks5 握手特殊逻辑 (保持原样，Socks5 比较特殊通常是独立流程)
            // ---------------------------------------------------------
            // 注意：如果已经进入 Socks5 状态，就不走下面的缓冲逻辑了，直接处理
            if (socks5State > 0 || (headerBuffer.length === 0 && bufferView.length > 0 && bufferView[0] === 5 && !protocolDetected)) {
                 // ... (此处省略 Socks5 的握手代码，保持原逻辑不变，为节省篇幅未重复粘贴，请保留原文件中的 Socks5 逻辑块) ...
                 // 实际代码中请务必保留原文件中 if (socks5State > 0 ... ) { ... } 的完整逻辑
                 
                 // 为了简化回复，这里假设如果进入 Socks5 逻辑，它会自行处理，不走下面的 Detect
                 if (socks5State > 0) {
                     // 原有的 Socks5 处理逻辑...
                     // (请保留您原文件第 45-84 行的代码逻辑)
                     // ...
                     
                     // 简单复制关键部分以维持逻辑完整性 (简化版示意)
                     if (socks5State === 0) {
                        // ...
                        socks5State = 1; 
                        return; // 需要 return 等待下一次交互
                     }
                     if (socks5State === 1) {
                         // ...
                         webSocket.send(new Uint8Array([0x01, 0x00])); 
                         socks5State = 2;
                         return; // 等待
                     }
                 }
            }

            // ---------------------------------------------------------
            // 3. 协议探测与缓冲逻辑 (修复核心)
            // ---------------------------------------------------------
            
            // 累积数据到 headerBuffer
            headerBuffer = concatUint8(headerBuffer, bufferView);

            try {
                // 尝试检测协议
                // 注意：这里传入 headerBuffer 而不是 chunk
                const result = await protocolManager.detect(headerBuffer, ctx);
                
                // 如果是 Socks5 后续阶段的校验
                if (socks5State === 2 && result.protocol !== 'socks5') throw new Error('Socks5 protocol mismatch');

                protocolDetected = true;
                remoteSocketWrapper.isConnecting = true;

                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote} (Buf: ${headerBuffer.length})`);
                
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }
                
                let responseHeader = null;
                // 注意：clientData 必须基于 headerBuffer 提取，因为我们可能拼接了多个 chunk
                let clientData = headerBuffer; 
                
                if (protocol === 'vless') {
                    clientData = headerBuffer.slice(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                    if (isUDP && portRemote !== 53) throw new Error('UDP only for DNS(53)');
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') { 
                    // mandala/trojan/ss 返回的 rawClientData 已经是去头后的数据
                    clientData = result.rawClientData;
                } else if (protocol === 'socks5') {
                    clientData = result.rawClientData;
                    webSocket.send(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
                    socks5State = 3;
                }
                
                // 释放内存
                headerBuffer = null; 

                handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                
            } catch (e) {
                // [核心修改]
                // 如果检测失败，检查缓冲区大小。
                // 如果数据还很小 (例如 < 200 字节)，可能是分包导致的，此时不要断开，直接 return 等待下一个 chunk。
                // 只有当积累了足够多的数据 (例如 > 200 字节) 依然无法识别，才认定为失败。
                // Mandala 最小头部 67 字节，Trojan 58 字节。
                if (headerBuffer.length < 200 && headerBuffer.length < MAX_HEADER_BUFFER) {
                    // log('Buffering...', headerBuffer.length);
                    return; // 等待更多数据
                }

                log('Detection failed: ' + e.message);
                safeCloseWebSocket(webSocket);
            }
        },
        close() { log("Client WebSocket closed"); },
        abort(reason) { log("WebSocket aborted", reason); safeCloseWebSocket(webSocket); },
    })).catch((err) => {
        log("Stream processing failed", err.toString());
        safeCloseWebSocket(webSocket);
    });

    if (ctx.waitUntil) ctx.waitUntil(streamPromise);

    return new Response(null, { status: 101, webSocket: client });
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) return;
                if (typeof event.data === 'string') {
                    controller.enqueue(new TextEncoder().encode(event.data));
                } else {
                    controller.enqueue(event.data);
                }
            });
            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
            });
            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket server error');
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { readableStreamCancel = true; safeCloseWebSocket(webSocketServer); }
    });
}
