import { TypedEmitter } from "tiny-typed-emitter";
import { rootP2PLogger } from "../logging";
import { getError } from "../utils";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface NvrTurnCredentials {
    turn_addr: string;
    turn_port: number;
    alt_turn_addr: string;
    alt_turn_port: number;
    turn_user: string;
    turn_password: string;
}

export interface NvrIceParameters {
    ufrag: string;
    pwd: string;
    fingerprint: string;
}

export interface NvrSdpOffer {
    ice: NvrIceParameters;
    setup: string; // "actpass" | "active" | "passive"
}

export interface NvrIceCandidate {
    candidate: string;
    channelId: number;
}

export interface NvrWebRTCSignalingInfo {
    stationSN: string;
    channelId: number;
    sessionId: string;
    turnCredentials: NvrTurnCredentials;
    sdpOffer: NvrSdpOffer;
    iceCandidates: string[];
}

interface NvrWebRTCSessionEvents {
    "signalingReady": (info: NvrWebRTCSignalingInfo) => void;
    "iceCandidate": (candidate: NvrIceCandidate) => void;
    "error": (error: Error) => void;
    "close": () => void;
}

// ─── WS Message Shapes ───────────────────────────────────────────────────────

interface NvrWsMessage {
    msgid: string;
    data: string; // JSON string
}

interface NvrWsData {
    action: number;
    code: number;
    data: string;      // nested JSON string
    dataType?: string; // "scall" | "info" | "ack"
    isResponse?: number;
    sessionId?: string;
    sn: string;
    source?: string;
    channelId?: number;
    subSn?: string;
    ts?: number;
}

// ─── NvrWebRTCSession ────────────────────────────────────────────────────────

/**
 * Handles the WebRTC signaling for Eufy NVR cameras via
 * wss://security-smart.eufylife.com/v1/rtc/ws/join?reqtype=nvr
 *
 * Flow:
 *  1. Caller provides sign token (from GET /v1/smart/nvr/ws/sign)
 *  2. WebSocket opened with auth payload in Sec-WebSocket-Protocol header
 *  3. action=1 → session confirmed
 *  4. Send action=3 dataType=scall → get TURN credentials
 *  5. NVR sends SDP offer + ICE candidates (source=DEVICE, dataType=info)
 *  6. Emit "signalingReady" with all info needed for WebRTC negotiation
 *  7. Caller sends back SDP answer + ICE candidates via sendSdpAnswer() / sendIceCandidate()
 */
export class NvrWebRTCSession extends TypedEmitter<NvrWebRTCSessionEvents> {

    private static readonly WS_BASE = "wss://security-smart.eufylife.com/v1/rtc/ws/join";

    private ws: any = null; // WebSocket (loaded dynamically)
    private stationSN: string;
    private channelId: number;
    private token: string;
    private gtoken: string;
    private signToken: string;
    private country: string;

    private sessionId = "";
    private account = "";
    private turnCredentials?: NvrTurnCredentials;
    private sdpOffer?: NvrSdpOffer;
    private iceCandidates: string[] = [];
    private sdpOfferReceived = false;

    private msgCounter = 0;

    constructor(stationSN: string, channelId: number, token: string, gtoken: string, signToken: string, country = "US") {
        super();
        this.stationSN = stationSN;
        this.channelId = channelId;
        this.token = token;
        this.gtoken = gtoken;
        this.signToken = signToken;
        this.country = country.toUpperCase();
    }

    // ── Public API ───────────────────────────────────────────────────────────

    public async connect(): Promise<void> {
        rootP2PLogger.debug(`[NVR-WS] Connecting to NVR WebSocket`, { stationSN: this.stationSN, channelId: this.channelId });
        try {
            const { WebSocket } = await import("ws");

            const authPayload = {
                region: this.country,
                type: "NVR",
                sn: this.stationSN,
                token: this.token,
                gtoken: this.gtoken,
                sign: this.signToken,
                appName: "eufy_mega",
                modelType: "WEB"
            };
            const authBase64 = Buffer.from(JSON.stringify(authPayload)).toString("base64");

            this.ws = new WebSocket(
                `${NvrWebRTCSession.WS_BASE}?reqtype=nvr`,
                [`v1`, authBase64],
                {
                    headers: {
                        "Origin": "https://security.eufy.com",
                        "User-Agent": "Mozilla/5.0 eufy-security-client"
                    }
                }
            );

            this.ws.on("open", () => this.onOpen());
            this.ws.on("message", (data: any) => this.onMessage(data.toString()));
            this.ws.on("error", (err: Error) => {
                rootP2PLogger.error(`[NVR-WS] WebSocket error`, { error: getError(err), stationSN: this.stationSN });
                this.emit("error", err);
            });
            this.ws.on("close", (code: number, reason: Buffer) => {
                rootP2PLogger.debug(`[NVR-WS] WebSocket closed`, { stationSN: this.stationSN, code, reason: reason.toString() });
                this.emit("close");
            });
        } catch (err) {
            const error = err instanceof Error ? err : new Error(String(err));
            rootP2PLogger.error(`[NVR-WS] connect - Error`, { error: getError(error), stationSN: this.stationSN });
            this.emit("error", error);
        }
    }

    public disconnect(): void {
        if (this.ws) {
            this.ws.close(1000, "Client disconnect");
            this.ws = null;
        }
    }

    /**
     * Send our SDP answer back to the NVR via the WebSocket relay.
     */
    public sendSdpAnswer(sdp: NvrSdpOffer): void {
        this.sendWsData({
            dataType: "info",
            data: JSON.stringify({ ...sdp })
        });
    }

    /**
     * Send a local ICE candidate to the NVR via the WebSocket relay.
     */
    public sendIceCandidate(candidate: string): void {
        this.sendWsData({
            dataType: "info",
            data: JSON.stringify({ format: "CANDIDATE", value: candidate })
        });
    }

    // ── WebSocket Handlers ───────────────────────────────────────────────────

    private onOpen(): void {
        rootP2PLogger.debug(`[NVR-WS] WebSocket opened`, { stationSN: this.stationSN });
        // The server sends action=1 first; we wait for it before sending scall
    }

    private onMessage(raw: string): void {
        try {
            const msg: NvrWsMessage = JSON.parse(raw);
            const wsData: NvrWsData = JSON.parse(msg.data);
            rootP2PLogger.debug(`[NVR-WS] Received`, { stationSN: this.stationSN, action: wsData.action, dataType: wsData.dataType, isResponse: wsData.isResponse, source: wsData.source });

            switch (wsData.action) {
                case 1:
                    // Session established — store sessionId and request stream
                    this.sessionId = wsData.data; // the sign token echoed back
                    this.sendScall();
                    break;

                case 3:
                    this.handleAction3(wsData, msg.msgid);
                    break;

                default:
                    rootP2PLogger.debug(`[NVR-WS] Unknown action`, { action: wsData.action });
            }
        } catch (err) {
            rootP2PLogger.error(`[NVR-WS] onMessage parse error`, { error: getError(err instanceof Error ? err : new Error(String(err))), raw });
        }
    }

    private handleAction3(wsData: NvrWsData, msgid: string): void {
        // Response to our scall → TURN credentials
        if (wsData.dataType === "scall" && wsData.isResponse === 1) {
            const scallData = JSON.parse(wsData.data);
            rootP2PLogger.debug(`[NVR-WS] TURN credentials received`, { stationSN: this.stationSN, status: scallData.status });
            if (scallData.turn) {
                this.turnCredentials = {
                    turn_addr: scallData.turn.turn_addr,
                    turn_port: scallData.turn.turn_port,
                    alt_turn_addr: scallData.turn.alt_turn_addr,
                    alt_turn_port: scallData.turn.alt_turn_port,
                    turn_user: scallData.turn.turn_user,
                    turn_password: scallData.turn.turn_password
                };
                this.account = scallData.account;
            }
        }

        // SDP offer from device
        if (wsData.dataType === "info" && wsData.isResponse === 0 && wsData.source === "DEVICE") {
            const infoData = JSON.parse(wsData.data);

            if (infoData.format === "SDP" || infoData.ice) {
                // SDP offer
                const sdpValue = typeof infoData.value === "string" ? JSON.parse(infoData.value) : infoData;
                this.sdpOffer = {
                    ice: sdpValue.ice,
                    setup: sdpValue.setup
                };
                this.sdpOfferReceived = true;
                rootP2PLogger.debug(`[NVR-WS] SDP offer received`, { stationSN: this.stationSN, sdp: this.sdpOffer });

                // Send ACK for this message
                this.sendAck(msgid);
            } else if (infoData.format === "CANDIDATE" || infoData.candidate !== undefined) {
                // ICE candidate from NVR
                const candidateStr = infoData.value ?? infoData.candidate;
                this.iceCandidates.push(candidateStr);
                rootP2PLogger.debug(`[NVR-WS] ICE candidate from NVR`, { stationSN: this.stationSN, candidate: candidateStr });

                // Emit individual candidate
                this.emit("iceCandidate", { candidate: candidateStr, channelId: this.channelId });

                // Send ACK
                this.sendAck(msgid);

                // Check if we have everything to emit signalingReady
                this.checkSignalingReady();
            }
        }
    }

    private checkSignalingReady(): void {
        if (this.turnCredentials && this.sdpOfferReceived && this.iceCandidates.length > 0) {
            const info: NvrWebRTCSignalingInfo = {
                stationSN: this.stationSN,
                channelId: this.channelId,
                sessionId: this.sessionId,
                turnCredentials: this.turnCredentials,
                sdpOffer: this.sdpOffer!,
                iceCandidates: [...this.iceCandidates]
            };
            rootP2PLogger.info(`[NVR-WS] Signaling ready - emitting signalingReady`, { stationSN: this.stationSN, channelId: this.channelId });
            this.emit("signalingReady", info);
        }
    }

    // ── Send Helpers ─────────────────────────────────────────────────────────

    private send(msg: NvrWsMessage): void {
        if (this.ws && this.ws.readyState === 1 /* OPEN */) {
            this.ws.send(JSON.stringify(msg));
        }
    }

    private nextMsgId(): string {
        return `${this.token}_${this.randomUUID()}`;
    }

    private sendScall(): void {
        const msgid = this.nextMsgId();
        const data: NvrWsData = {
            action: 3,
            code: 200,
            sessionId: this.sessionId,
            sn: this.stationSN,
            subSn: "",
            channelId: this.channelId,
            isResponse: 0,
            dataType: "scall",
            source: "WEB",
            ts: Math.floor(Date.now() / 1000),
            data: JSON.stringify({ timestamp: Math.floor(Date.now() / 1000), account: this.account || this.md5(this.token) })
        };
        rootP2PLogger.debug(`[NVR-WS] Sending scall`, { stationSN: this.stationSN, channelId: this.channelId, msgid });
        this.send({ msgid, data: JSON.stringify(data) });
    }

    private sendWsData(partial: { dataType: string; data: string }): void {
        const msgid = this.nextMsgId();
        const data: NvrWsData = {
            action: 3,
            code: 200,
            sessionId: this.sessionId,
            sn: this.stationSN,
            subSn: "",
            channelId: this.channelId,
            isResponse: 0,
            dataType: partial.dataType,
            source: "WEB",
            ts: Math.floor(Date.now() / 1000),
            data: JSON.stringify({ timestamp: Math.floor(Date.now() / 1000), account: this.account, ...JSON.parse(partial.data) })
        };
        this.send({ msgid, data: JSON.stringify(data) });
    }

    private sendAck(originalMsgid: string): void {
        const data: NvrWsData = {
            action: 3,
            code: 200,
            sessionId: this.sessionId,
            sn: this.stationSN,
            channelId: this.channelId,
            isResponse: 1,
            dataType: "ack",
            source: "WEB",
            data: JSON.stringify({ status: 200 })
        };
        this.send({ msgid: originalMsgid, data: JSON.stringify(data) });
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private randomUUID(): string {
        return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
            const r = Math.random() * 16 | 0;
            return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
        });
    }

    private md5(input: string): string {
        // Simple stub — replaced by import if needed; account hash is stable per session
        const crypto = require("crypto");
        return crypto.createHash("md5").update(input).digest("hex");
    }
}
