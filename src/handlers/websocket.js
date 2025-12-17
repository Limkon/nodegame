/**
 * 文件名: src/handlers/websocket.js
 * 优化详情:
 * 1. [架构] 统一缓冲池：Socks5 握手和普通协议探测共享同一个 headerBuffer，完美解决所有协议的 TCP 分包/粘包问题。
 * 2. [稳定] 冲突解决：增加 Socks5 严格校验，防止 Mandala 随机头部(0x05开头)被误判。
 * 3. [整洁] 逻辑解耦：抽离 Socks5 状态机，主流程更加清晰高效。
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

// 高效拼接 Buffer
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
    
    // 状态管理
    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [] };
    let isConnected = false;  // 标记是否已建立后端连接
    let socks5State = 0;      // 0:初始, 1:Auth, 2:Command(交给ProtocolManager), 3:Done
    let headerBuffer = new Uint8Array(0); 
    const MAX_HEADER_BUFFER = 4096; // 4KB 安全限制

    const log = (info, event) => console.log(`[WS] ${info}`, event || '');

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            // 1. 快速通道：如果已连接，直接转发数据，零逻辑损耗
            if (isConnected) {
                if (remoteSocketWrapper.value) {
                    const writer = remoteSocketWrapper.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                } else if (remoteSocketWrapper.isConnecting) {
                    remoteSocketWrapper.buffer.push(chunk);
                }
                return;
            }

            // 2. 数据缓冲：将新数据拼接到缓冲区
            const newData = new Uint8Array(chunk);
            headerBuffer = concatUint8(headerBuffer, newData);

            // 3. Socks5 握手阶段处理 (State 0 & 1)
            // 如果处于 Socks5 流程中，或者尚未识别协议且数据特征像 Socks5
            if (socks5State < 2) {
                const { consumed, newState, error } = tryHandleSocks5Handshake(headerBuffer, socks5State, webSocket, ctx, log);
                
                if (error) {
                    // 如果明确是 Socks5 校验失败（如密码错误），则断开
                    // 注意：如果只是“看起来不像 Socks5”，tryHandleSocks5Handshake 会返回 consumed=0，不报错，继续走下方探测
                    throw new Error(error);
                }

                if (consumed > 0) {
                    // 成功处理了 Socks5 握手数据，更新状态并切除已处理的 buffer
                    headerBuffer = headerBuffer.slice(consumed);
                    socks5State = newState;
                    
                    // 如果刚刚完成了握手（进入 State 2），不要 return，继续尝试解析剩余数据中的 CMD
                    if (socks5State !== 2) {
                        return; // 等待客户端发送更多握手包
                    }
                }
            }

            // 4. 协议探测 (Vless / Trojan / Mandala / Socks5 CMD)
            if (headerBuffer.length === 0) return;

            try {
                // 尝试识别协议
                const result = await protocolManager.detect(headerBuffer, ctx);
                
                // 安全检查：如果走了 Socks5 握手，探测结果必须也是 Socks5
                if (socks5State === 2 && result.protocol !== 'socks5') {
                    throw new Error('Protocol mismatch after Socks5 handshake');
                }

                // 标记为已连接
                isConnected = true;
                remoteSocketWrapper.isConnecting = true;

                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote} (Buf: ${headerBuffer.length})`);
                
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }

                // 准备发送给后端的数据 (Client Hello)
                let clientData = headerBuffer; 
                let responseHeader = null;

                if (protocol === 'vless') {
                    clientData = headerBuffer.slice(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                    if (isUDP && portRemote !== 53) throw new Error('UDP only for DNS(53)');
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') {
                    // 这些协议使用 result.rawClientData (已解密/去头)
                    clientData = result.rawClientData;
                } else if (protocol === 'socks5') {
                    clientData = result.rawClientData;
                    // 发送 Socks5 连接成功响应
                    webSocket.send(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
                    socks5State = 3;
                }

                // 清空缓冲区，释放内存
                headerBuffer = null; 

                // 建立出站连接
                handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);

            } catch (e) {
                // [缓冲等待机制]
                // 只有当缓冲区较大时才认定为失败，否则认为是分包，等待更多数据
                if (headerBuffer.length < 512 && headerBuffer.length < MAX_HEADER_BUFFER) {
                    return; 
                }
                log(`Detection failed: ${e.message}`);
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

/**
 * 独立的 Socks5 握手处理器
 * 返回: { consumed: number, newState: number, error: string|null }
 */
function tryHandleSocks5Handshake(buffer, currentState, webSocket, ctx, log) {
    const res = { consumed: 0, newState: currentState, error: null };
    if (buffer.length === 0) return res;

    // 阶段 0: 协商版本和方法
    if (currentState === 0) {
        // 严格校验：必须以 0x05 开头
        if (buffer[0] !== 0x05) return res; 
        
        // 数据不足，等待
        if (buffer.length < 2) return res; 
        
        const nMethods = buffer[1];
        // 严格校验：完整长度必须匹配，防止误判 Mandala 随机头
        if (buffer.length < 2 + nMethods) return res; 

        // 确认为 Socks5，处理方法选择
        const methods = buffer.slice(2, 2 + nMethods);
        let hasAuth = false;
        for (let m of methods) {
            if (m === 0x02) hasAuth = true;
        }

        if (hasAuth) {
            webSocket.send(new Uint8Array([0x05, 0x02])); // 需认证
            res.newState = 1;
        } else {
            webSocket.send(new Uint8Array([0x05, 0xFF])); // 不支持无认证
            res.error = "Socks5: No supported auth method";
            return res; // 立即失败
        }
        
        res.consumed = 2 + nMethods;
        return res;
    }

    // 阶段 1: 用户名密码认证
    if (currentState === 1) {
        if (buffer.length < 3) return res; // 等待 Ver + Ulen
        
        // 简单校验版本
        if (buffer[0] !== 0x01) {
            res.error = "Socks5 Auth: Wrong version";
            return res;
        }

        let offset = 1;
        const uLen = buffer[offset++];
        if (buffer.length < offset + uLen + 1) return res; // 等待 User + Plen
        
        const user = new TextDecoder().decode(buffer.slice(offset, offset + uLen));
        offset += uLen;
        
        const pLen = buffer[offset++];
        if (buffer.length < offset + pLen) return res; // 等待 Pass
        
        const pass = new TextDecoder().decode(buffer.slice(offset, offset + pLen));
        offset += pLen;

        // 鉴权
        const isValid = (user === ctx.userID || user === ctx.dynamicUUID) && 
                        (pass === ctx.dynamicUUID || pass === ctx.userID);
        
        if (isValid) {
            webSocket.send(new Uint8Array([0x01, 0x00])); // 认证成功
            res.newState = 2; // 进入 Command 阶段
            res.consumed = offset;
        } else {
            webSocket.send(new Uint8Array([0x01, 0x01])); // 认证失败
            res.error = `Socks5 Auth Failed: ${user}`;
        }
        return res;
    }

    return res;
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) return;
                const data = typeof event.data === 'string' 
                    ? new TextEncoder().encode(event.data) 
                    : event.data;
                controller.enqueue(data);
            });
            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (!readableStreamCancel) controller.close();
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
