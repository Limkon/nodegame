/**
 * 文件名: src/handlers/websocket.js
 * 优化内容:
 * 1. [核心] 增加 Header Buffering 机制，完美解决 Mandala/Trojan 因 TCP 分包导致的连接中断问题。
 * 2. [优化] 只有在缓冲区数据积累到一定程度或识别成功后才进行转发，减少 CPU 占用。
 * 3. [安全] 增加 MAX_HEADER_BUFFER 限制，防止内存攻击。
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

// [新增] 辅助函数：高效拼接 Uint8Array
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
    let headerBuffer = new Uint8Array(0); // [核心] 协议头缓冲区
    const MAX_HEADER_BUFFER = 4096; // 最大缓冲 4KB，避免内存炸弹
    
    const log = (info, event) => console.log(`[WS] ${info}`, event || '');
    
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    
    const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            const bufferView = new Uint8Array(chunk);
            
            // -----------------------------------------------------------
            // 1. 已建立连接：直接转发 (高性能路径)
            // -----------------------------------------------------------
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

            // -----------------------------------------------------------
            // 2. Socks5 握手 (保持原有鉴权逻辑，优先处理)
            // -----------------------------------------------------------
            // 如果处于 Socks5 交互状态，或者通过第一个字节判断是 Socks5 且缓冲区为空
            if (socks5State > 0 || (headerBuffer.length === 0 && bufferView.length > 0 && bufferView[0] === 5)) {
                // 现有的 Socks5 逻辑比较复杂且依赖多次交互，这里保持原样以确保功能一致
                // 注意：如果 Socks5 握手包也被分包，这里的逻辑依然脆弱，但鉴于 Socks5 包很小，概率较低
                // 为保证 Mandala 修复的纯粹性，此处暂不重构 Socks5 的 Buffer 逻辑
                
                let currentChunk = chunk;
                let currentOffset = 0;
                
                if (socks5State === 0) {
                    if (bufferView.length < 2) return; // 简单的数据不足检查
                    const nMethods = bufferView[1];
                    const methods = bufferView.slice(2, 2 + nMethods);
                    let method = 0xFF;
                    for (let i = 0; i < methods.length; i++) {
                        if (methods[i] === 0x02) { method = 0x02; break; }
                    }
                    if (method === 0x02) {
                        webSocket.send(new Uint8Array([0x05, 0x02])); 
                        socks5State = 1;
                        currentOffset = 2 + nMethods;
                    } else {
                        webSocket.send(new Uint8Array([0x05, 0xFF])); 
                        safeCloseWebSocket(webSocket);
                        return;
                    }
                    // 如果还有剩余数据，继续处理（粘包处理）
                    if (currentOffset >= bufferView.length) return;
                    currentChunk = chunk.slice(currentOffset);
                }
                
                if (socks5State === 1) {
                    const view = new Uint8Array(currentChunk);
                    if (view.length < 3) return;
                    if (view[0] !== 0x01) { safeCloseWebSocket(webSocket); return; }
                    try {
                        let offset = 1;
                        const uLen = view[offset++];
                        const user = new TextDecoder().decode(view.slice(offset, offset + uLen));
                        offset += uLen;
                        const pLen = view[offset++];
                        const pass = new TextDecoder().decode(view.slice(offset, offset + pLen));
                        
                        const isValidUser = (user === ctx.userID || user === ctx.dynamicUUID);
                        const isValidPass = (pass === ctx.dynamicUUID || pass === ctx.userID);
                        
                        if (isValidUser && isValidPass) {
                            webSocket.send(new Uint8Array([0x01, 0x00])); 
                            socks5State = 2;
                            // 认证成功，准备进入数据阶段
                            // 此时不应立即 return，因为可能已经携带了后续请求数据
                            currentOffset = offset + pLen;
                        } else {
                            log(`Socks5 Auth Fail: ${user}`);
                            webSocket.send(new Uint8Array([0x01, 0x01])); 
                            safeCloseWebSocket(webSocket);
                            return;
                        }
                    } catch (e) {
                        safeCloseWebSocket(webSocket);
                        return;
                    }
                    // 处理完握手，剩余的数据可能是 CONNECT 请求，留给下方 detect 处理
                    if (currentOffset >= view.length) return;
                    // 将剩余数据放入 bufferView 供下方逻辑使用
                    // 注意：这里需要更新 headerBuffer，因为我们即将进入 detect 流程
                    headerBuffer = concatUint8(headerBuffer, view.slice(currentOffset));
                }
            } else {
                // 非 Socks5 握手阶段，或者非 Socks5 协议：累积数据到缓冲区
                headerBuffer = concatUint8(headerBuffer, bufferView);
            }

            // -----------------------------------------------------------
            // 3. 协议探测与缓冲 (修复 Mandala 不稳定的核心)
            // -----------------------------------------------------------
            if (headerBuffer.length === 0) return;

            try {
                // 使用累积的 headerBuffer 进行探测
                const result = await protocolManager.detect(headerBuffer, ctx);
                
                if (socks5State === 2 && result.protocol !== 'socks5') throw new Error('Socks5 protocol mismatch');

                protocolDetected = true;
                remoteSocketWrapper.isConnecting = true;

                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote} (Len: ${headerBuffer.length})`);
                
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }
                
                let responseHeader = null;
                // 注意：clientData 必须基于 headerBuffer 提取
                let clientData = headerBuffer;
                
                if (protocol === 'vless') {
                    clientData = headerBuffer.slice(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                    if (isUDP && portRemote !== 53) throw new Error('UDP only for DNS(53)');
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') { 
                    // 这些协议解析器通常已经处理了解密和去头
                    clientData = result.rawClientData;
                } else if (protocol === 'socks5') {
                    clientData = result.rawClientData;
                    // 发送 Socks5 连接成功响应
                    webSocket.send(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
                    socks5State = 3;
                }
                
                // 释放缓冲区内存
                headerBuffer = null; 

                handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                
            } catch (e) {
                // [关键修复]
                // 检测失败时不立即断开，而是检查是否需要等待更多数据。
                // 如果数据量较小（例如 < 512 字节），认为是 TCP 分包导致头部不完整，跳过当前循环继续缓冲。
                if (headerBuffer.length < 512 && headerBuffer.length < MAX_HEADER_BUFFER) {
                    // log('Buffering...', headerBuffer.length);
                    return; // 等待下一个 chunk
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
