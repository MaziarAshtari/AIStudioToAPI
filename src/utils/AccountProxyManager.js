/**
 * File: src/utils/AccountProxyManager.js
 * Description: Persistent proxy store (configs/proxies.json) with per-account assignments. Resolves Playwright
 *              context proxies (local forwarders for authenticated SOCKS5), Node.js agents for server-side requests
 *              made on behalf of an account, and proxy connectivity tests.
 */

const crypto = require("crypto");
const fs = require("fs");
const net = require("net");
const path = require("path");
const axios = require("axios");
const { anonymizeProxy, closeAnonymizedProxy } = require("proxy-chain");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { SocksProxyAgent } = require("socks-proxy-agent");

const { AccountProxyError } = require("./CustomErrors");
const { getLocalProxyBypass } = require("./ProxyUtils");

const PROXY_TYPES = ["http", "https", "socks5"];
const PASSWORD_MASK = "********";
const MAX_NAME_LENGTH = 64;
const MAX_CREDENTIAL_LENGTH = 256;
// Hostnames, IPv4 and IPv6 literals (brackets are stripped before validation)
const HOST_PATTERN = /^[a-zA-Z0-9._:-]+$/;
const ID_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;
const REACHABILITY_TIMEOUT_MS = 8000;
const TEST_TIMEOUT_MS = 15000;
const IP_CHECK_URLS = ["https://api.ipify.org?format=json", "https://icanhazip.com"];
// Firefox network errors raised when the proxy itself fails (refused, unknown host, auth, bad gateway, ...)
const PROXY_NETWORK_ERROR_PATTERN = /NS_ERROR_(?:PROXY_|UNKNOWN_PROXY_HOST|SOCKS)/i;

const formatHost = host => (host.includes(":") ? `[${host}]` : host);

const extractIp = data => {
    let candidate = typeof data === "string" ? data.trim() : "";
    try {
        const parsed = JSON.parse(candidate);
        if (parsed && typeof parsed.ip === "string") {
            candidate = parsed.ip.trim();
        }
    } catch {
        // Plain-text response
    }
    return net.isIP(candidate) ? candidate : null;
};

class AccountProxyManager {
    constructor(logger, authSource, options = {}) {
        this.logger = logger;
        this.authSource = authSource;
        this.storePath = path.resolve(
            process.cwd(),
            options.storePath || process.env.PROXY_CONFIG_PATH || path.join("configs", "proxies.json")
        );
        this.proxies = [];
        // Map: account key (lowercased account email/name, or "auth-N" for unnamed accounts) -> proxy id
        this.assignments = {};
        // Set when the store exists but cannot be parsed; every account then fails closed until it is fixed
        this.storeError = null;
        this._accountErrors = new Map(); // account key -> { message, proxyId }
        this._forwarders = new Map(); // proxy id -> { fingerprint, urlPromise }
        this._nodeAgents = new Map(); // proxy id -> { agent, fingerprint }
        this._load();
    }

    // ==================== Store ====================

    _load() {
        if (!fs.existsSync(this.storePath)) {
            return;
        }

        let data;
        try {
            const raw = fs.readFileSync(this.storePath, "utf-8");
            data = raw.trim() ? JSON.parse(raw) : {};
        } catch (error) {
            this.storeError = error.message;
            this.logger.error(
                `❌ [Proxy] Failed to read ${this.storePath}: ${error.message}. ` +
                    "No account will be started until the file is fixed or removed (fail-closed)."
            );
            return;
        }

        const seenIds = new Set();
        for (const entry of Array.isArray(data?.proxies) ? data.proxies : []) {
            try {
                const id = ID_PATTERN.test(String(entry?.id)) && !seenIds.has(entry.id) ? entry.id : this._generateId();
                seenIds.add(id);
                this.proxies.push({ id, ...this._normalizeProxy(entry) });
            } catch (error) {
                this.logger.warn(`[Proxy] Ignoring invalid proxy entry in ${this.storePath}: ${error.message}`);
            }
        }

        const rawAssignments = data?.assignments && typeof data.assignments === "object" ? data.assignments : {};
        for (const [key, proxyId] of Object.entries(rawAssignments)) {
            if (typeof proxyId === "string" && proxyId) {
                this.assignments[key.trim().toLowerCase()] = proxyId;
            }
        }

        this.logger.info(
            `[Proxy] Loaded ${this.proxies.length} proxies and ${Object.keys(this.assignments).length} account assignments from ${this.storePath}.`
        );
    }

    _assertStoreReadable() {
        if (this.storeError) {
            throw new AccountProxyError(
                `Proxy store ${this.storePath} is unreadable (${this.storeError}). Fix or remove the file and restart.`,
                "proxyErrorStoreUnreadable",
                500,
                { reason: this.storeError }
            );
        }
    }

    _writeStore(proxies, assignments) {
        this._assertStoreReadable();
        const sortedAssignments = Object.fromEntries(
            Object.entries(assignments).sort(([a], [b]) => a.localeCompare(b))
        );
        const content = `${JSON.stringify(
            {
                assignments: sortedAssignments,
                proxies: proxies.map(({ host, id, name, password, port, type, username }) => ({
                    host,
                    id,
                    name,
                    password,
                    port,
                    type,
                    username,
                })),
            },
            null,
            4
        )}\n`;

        fs.mkdirSync(path.dirname(this.storePath), { recursive: true });
        const tmpPath = `${this.storePath}.tmp`;
        // The store holds proxy credentials, keep it private to the service user
        fs.writeFileSync(tmpPath, content, { mode: 0o600 });
        try {
            fs.renameSync(tmpPath, this.storePath);
        } catch (error) {
            // Renaming onto a single-file bind mount fails (EBUSY/EXDEV), fall back to an in-place write
            fs.writeFileSync(this.storePath, content, { mode: 0o600 });
            fs.rmSync(tmpPath, { force: true });
        }
    }

    _commit(proxies, assignments) {
        this._writeStore(proxies, assignments);
        this.proxies = proxies;
        this.assignments = assignments;
    }

    _generateId() {
        let id;
        do {
            id = crypto.randomBytes(6).toString("hex");
        } while (this.proxies.some(proxy => proxy.id === id));
        return id;
    }

    /**
     * Validate and normalize proxy fields. Fields missing from `input` are taken from `existing`.
     * The password is kept when omitted or sent back masked, and cleared when the username is empty.
     */
    _normalizeProxy(input, existing = null) {
        const source = input && typeof input === "object" ? input : {};

        const type = String(source.type ?? existing?.type ?? "")
            .trim()
            .toLowerCase();
        if (!PROXY_TYPES.includes(type)) {
            throw new AccountProxyError(
                `Invalid proxy type "${type}". Supported types: ${PROXY_TYPES.join(", ")}.`,
                "proxyErrorInvalidType"
            );
        }

        let host = String(source.host ?? existing?.host ?? "").trim();
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.slice(1, -1);
        }
        if (!host || host.length > 255 || !HOST_PATTERN.test(host)) {
            throw new AccountProxyError("Invalid proxy host.", "proxyErrorInvalidHost");
        }

        const port = Number(source.port ?? existing?.port);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            throw new AccountProxyError("Invalid proxy port (expected 1-65535).", "proxyErrorInvalidPort");
        }

        const username = String(source.username ?? existing?.username ?? "").trim();
        const keepPassword =
            source.password === undefined || source.password === null || source.password === PASSWORD_MASK;
        const password = !username ? "" : keepPassword ? existing?.password || "" : String(source.password);
        if (username.length > MAX_CREDENTIAL_LENGTH || password.length > MAX_CREDENTIAL_LENGTH) {
            throw new AccountProxyError(
                `Proxy username and password must be at most ${MAX_CREDENTIAL_LENGTH} characters.`,
                "proxyErrorCredentialsTooLong"
            );
        }

        const name = String(source.name ?? existing?.name ?? "").trim() || `${formatHost(host)}:${port}`;
        if (name.length > MAX_NAME_LENGTH) {
            throw new AccountProxyError(
                `Proxy name must be at most ${MAX_NAME_LENGTH} characters.`,
                "proxyErrorNameTooLong"
            );
        }

        return { host, name, password, port, type, username };
    }

    _requireProxy(proxyId) {
        const proxy = this.proxies.find(entry => entry.id === proxyId);
        if (!proxy) {
            throw new AccountProxyError(`Proxy "${proxyId}" does not exist.`, "proxyErrorNotFound", 404, { proxyId });
        }
        return proxy;
    }

    _fingerprint(proxy) {
        return JSON.stringify([proxy.type, proxy.host, proxy.port, proxy.username, proxy.password]);
    }

    _buildProxyUrl(proxy, scheme) {
        const auth = proxy.username
            ? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@`
            : "";
        return `${scheme}://${auth}${formatHost(proxy.host)}:${proxy.port}`;
    }

    /**
     * API representation of a proxy. Passwords are never returned, only masked.
     */
    _toPublic(proxy) {
        return {
            hasPassword: Boolean(proxy.password),
            host: proxy.host,
            id: proxy.id,
            name: proxy.name,
            password: proxy.password ? PASSWORD_MASK : "",
            port: proxy.port,
            type: proxy.type,
            username: proxy.username,
        };
    }

    describeProxy(proxy) {
        return `"${proxy.name}" (${proxy.type}://${formatHost(proxy.host)}:${proxy.port})`;
    }

    // ==================== CRUD ====================

    listProxies() {
        return this.proxies.map(proxy => this._toPublic(proxy));
    }

    createProxy(input) {
        this._assertStoreReadable();
        const proxy = { id: this._generateId(), ...this._normalizeProxy(input) };
        this._commit([...this.proxies, proxy], this.assignments);
        return this._toPublic(proxy);
    }

    /**
     * @returns {{connectionChanged: boolean, proxy: object}} connectionChanged is true when contexts must be recreated
     */
    updateProxy(proxyId, input) {
        this._assertStoreReadable();
        const existing = this._requireProxy(proxyId);
        const updated = { id: existing.id, ...this._normalizeProxy(input, existing) };
        const connectionChanged = this._fingerprint(existing) !== this._fingerprint(updated);
        this._commit(
            this.proxies.map(proxy => (proxy.id === proxyId ? updated : proxy)),
            this.assignments
        );
        if (connectionChanged) {
            this._releaseProxyResources(proxyId);
        }
        return { connectionChanged, proxy: this._toPublic(updated) };
    }

    deleteProxy(proxyId) {
        this._assertStoreReadable();
        const existing = this._requireProxy(proxyId);
        const assignments = {};
        const removedAccountKeys = [];
        for (const [accountKey, assignedId] of Object.entries(this.assignments)) {
            if (assignedId === proxyId) {
                removedAccountKeys.push(accountKey);
            } else {
                assignments[accountKey] = assignedId;
            }
        }
        this._commit(
            this.proxies.filter(proxy => proxy.id !== proxyId),
            assignments
        );
        this._releaseProxyResources(proxyId);
        removedAccountKeys.forEach(accountKey => this._accountErrors.delete(accountKey));
        return { proxy: this._toPublic(existing), removedAccountKeys };
    }

    // ==================== Account assignments ====================

    /**
     * Stable account identity: lowercased account email/name when available, so assignments survive
     * restarts and auth file re-ordering. Unnamed accounts fall back to their auth index.
     */
    getAccountKey(authIndex) {
        const rawName = this.authSource?.accountNameMap?.get(authIndex);
        const name = typeof rawName === "string" ? rawName.trim().toLowerCase() : "";
        return name || `auth-${authIndex}`;
    }

    getAssignedProxyId(authIndex) {
        return this.assignments[this.getAccountKey(authIndex)] || null;
    }

    hasAssignment(authIndex) {
        return Boolean(this.getAssignedProxyId(authIndex));
    }

    /**
     * @param {number} authIndex
     * @param {string|null} proxyId - null removes the assignment
     */
    assignProxy(authIndex, proxyId) {
        this._assertStoreReadable();
        const accountKey = this.getAccountKey(authIndex);
        const nextProxyId = proxyId ? this._requireProxy(String(proxyId)).id : null;
        const previousProxyId = this.assignments[accountKey] || null;
        if (previousProxyId === nextProxyId) {
            return { accountKey, changed: false, previousProxyId, proxyId: nextProxyId };
        }

        const assignments = { ...this.assignments };
        if (nextProxyId) {
            assignments[accountKey] = nextProxyId;
        } else {
            delete assignments[accountKey];
        }
        this._commit(this.proxies, assignments);
        this._accountErrors.delete(accountKey);
        return { accountKey, changed: true, previousProxyId, proxyId: nextProxyId };
    }

    /**
     * All valid auth indices of an account (duplicate auth files share the same key and proxy).
     */
    getAccountIndices(accountKey) {
        return (this.authSource?.availableIndices || []).filter(index => this.getAccountKey(index) === accountKey);
    }

    getIndicesForProxy(proxyId) {
        return (this.authSource?.availableIndices || []).filter(index => this.getAssignedProxyId(index) === proxyId);
    }

    getAccountProxyInfo(authIndex) {
        const accountKey = this.getAccountKey(authIndex);
        const proxyId = this.assignments[accountKey] || null;
        const proxy = proxyId ? this.proxies.find(entry => entry.id === proxyId) : null;
        let proxyError = this._accountErrors.get(accountKey)?.message || null;
        if (this.storeError) {
            proxyError = `Proxy store is unreadable: ${this.storeError}`;
        } else if (proxyId && !proxy) {
            proxyError = `Assigned proxy "${proxyId}" no longer exists.`;
        }
        return { proxyError, proxyId, proxyName: proxy ? proxy.name : null };
    }

    markAccountError(authIndex, message) {
        const accountKey = this.getAccountKey(authIndex);
        const firstLine = String(message || "Unknown proxy error").split("\n")[0];
        this._accountErrors.set(accountKey, {
            message: firstLine.slice(0, 300),
            proxyId: this.assignments[accountKey] || null,
        });
    }

    clearAccountError(authIndex) {
        this._accountErrors.delete(this.getAccountKey(authIndex));
    }

    isProxyNetworkError(error) {
        return PROXY_NETWORK_ERROR_PATTERN.test(String(error?.message || error || ""));
    }

    // ==================== Proxy resolution ====================

    /**
     * Resolve the Playwright proxy settings for an account's browser context.
     * @returns {Promise<null|{display: string, proxy: object, proxyId: string}>} null when no proxy is assigned
     * @throws {AccountProxyError} When the assigned proxy cannot be used. Callers must not fall back to another route.
     */
    async resolveContextProxy(authIndex) {
        this._assertStoreReadable();
        const proxyId = this.getAssignedProxyId(authIndex);
        return proxyId ? this.resolveProxyById(proxyId) : null;
    }

    async resolveProxyById(proxyId) {
        this._assertStoreReadable();
        const proxy = this._requireProxy(proxyId);
        await this._assertReachable(proxy);

        // Loopback stays direct: the injected page script connects to the local WebSocket server
        const bypass = getLocalProxyBypass();
        let playwrightProxy;
        if (proxy.type === "socks5" && proxy.username) {
            // Playwright cannot authenticate to SOCKS5 proxies, so use a local unauthenticated forwarder
            playwrightProxy = { bypass, server: await this._getForwarderUrl(proxy) };
        } else {
            playwrightProxy = { bypass, server: `${proxy.type}://${formatHost(proxy.host)}:${proxy.port}` };
            if (proxy.username) {
                playwrightProxy.username = proxy.username;
                playwrightProxy.password = proxy.password;
            }
        }
        return { display: this.describeProxy(proxy), proxy: playwrightProxy, proxyId: proxy.id };
    }

    _assertReachable(proxy, timeoutMs = REACHABILITY_TIMEOUT_MS) {
        return new Promise((resolve, reject) => {
            const socket = net.connect({ host: proxy.host, port: proxy.port });
            const fail = error => {
                socket.destroy();
                reject(
                    new AccountProxyError(
                        `Proxy ${this.describeProxy(proxy)} is unreachable: ${error.message}`,
                        "proxyErrorUnreachable",
                        502,
                        { proxyName: proxy.name, reason: error.message }
                    )
                );
            };
            socket.setTimeout(timeoutMs, () => fail(new Error(`connection timed out after ${timeoutMs}ms`)));
            socket.once("error", fail);
            socket.once("connect", () => {
                socket.destroy();
                resolve();
            });
        });
    }

    _getForwarderUrl(proxy) {
        const fingerprint = this._fingerprint(proxy);
        const cached = this._forwarders.get(proxy.id);
        if (cached && cached.fingerprint === fingerprint) {
            return cached.urlPromise;
        }
        if (cached) {
            this._closeForwarder(proxy.id);
        }

        const urlPromise = anonymizeProxy(this._buildProxyUrl(proxy, "socks5")).then(
            url => {
                this.logger.info(
                    `[Proxy] Started local forwarder ${url} for authenticated SOCKS5 proxy ${this.describeProxy(proxy)}.`
                );
                return url;
            },
            error => {
                if (this._forwarders.get(proxy.id)?.urlPromise === urlPromise) {
                    this._forwarders.delete(proxy.id);
                }
                throw new AccountProxyError(
                    `Failed to start local forwarder for proxy ${this.describeProxy(proxy)}: ${error.message}`,
                    "proxyErrorForwarderFailed",
                    500,
                    { proxyName: proxy.name, reason: error.message }
                );
            }
        );
        this._forwarders.set(proxy.id, { fingerprint, urlPromise });
        return urlPromise;
    }

    _closeForwarder(proxyId) {
        const entry = this._forwarders.get(proxyId);
        if (!entry) {
            return Promise.resolve();
        }
        this._forwarders.delete(proxyId);
        return entry.urlPromise
            .then(url => closeAnonymizedProxy(url, true))
            .catch(error => this.logger.warn(`[Proxy] Failed to close local forwarder: ${error.message}`));
    }

    _createNodeAgent(proxy) {
        // socks5h: the proxy resolves hostnames, so DNS lookups do not bypass it
        return proxy.type === "socks5"
            ? new SocksProxyAgent(this._buildProxyUrl(proxy, "socks5h"))
            : new HttpsProxyAgent(this._buildProxyUrl(proxy, proxy.type));
    }

    _getNodeAgent(proxy) {
        const fingerprint = this._fingerprint(proxy);
        const cached = this._nodeAgents.get(proxy.id);
        if (cached && cached.fingerprint === fingerprint) {
            return cached.agent;
        }
        cached?.agent.destroy();
        const agent = this._createNodeAgent(proxy);
        this._nodeAgents.set(proxy.id, { agent, fingerprint });
        return agent;
    }

    /**
     * Axios options that route a server-side request made on behalf of an account through its proxy.
     * @returns {object} Empty object when the account has no assigned proxy
     * @throws {AccountProxyError} When the assigned proxy cannot be used (the request must not go direct)
     */
    getRequestOptionsForAuth(authIndex) {
        if (!Number.isInteger(authIndex) || authIndex < 0) {
            return {};
        }
        this._assertStoreReadable();
        const proxyId = this.getAssignedProxyId(authIndex);
        if (!proxyId) {
            return {};
        }
        const agent = this._getNodeAgent(this._requireProxy(proxyId));
        return { httpAgent: agent, httpsAgent: agent, proxy: false };
    }

    _releaseProxyResources(proxyId) {
        const nodeAgent = this._nodeAgents.get(proxyId);
        if (nodeAgent) {
            nodeAgent.agent.destroy();
            this._nodeAgents.delete(proxyId);
        }
        this._closeForwarder(proxyId);
    }

    // ==================== Connectivity test ====================

    /**
     * Test a proxy by fetching the outgoing IP address through it.
     * @param {object} input - Proxy fields. With `id`, missing fields (including the password) come from the stored proxy.
     * @returns {Promise<{error?: string, ip?: string, latencyMs?: number, success: boolean}>}
     */
    async testProxy(input = {}) {
        const existing = input.id ? this._requireProxy(String(input.id)) : null;
        const proxy = { id: existing?.id || "draft", ...this._normalizeProxy(input, existing) };
        const label = this.describeProxy(proxy);
        const startedAt = Date.now();

        let lastError = null;
        try {
            await this._assertReachable(proxy);
        } catch (error) {
            lastError = error;
        }

        if (!lastError) {
            const agent = this._createNodeAgent(proxy);
            try {
                for (const url of IP_CHECK_URLS) {
                    try {
                        const response = await axios.get(url, {
                            httpAgent: agent,
                            httpsAgent: agent,
                            proxy: false,
                            responseType: "text",
                            signal: AbortSignal.timeout(TEST_TIMEOUT_MS),
                            timeout: TEST_TIMEOUT_MS,
                            transformResponse: [data => data],
                        });
                        const ip = extractIp(response.data);
                        if (ip) {
                            const latencyMs = Date.now() - startedAt;
                            this.logger.info(`[Proxy] Test passed for ${label}: outgoing IP ${ip} (${latencyMs}ms).`);
                            return { ip, latencyMs, success: true };
                        }
                        lastError = new Error(`Unexpected response from ${url}`);
                    } catch (error) {
                        lastError =
                            error?.code === "ERR_CANCELED"
                                ? new Error(`Request timed out after ${TEST_TIMEOUT_MS}ms`)
                                : error;
                    }
                }
            } finally {
                agent.destroy();
            }
        }

        const message = lastError?.message || "Unknown error";
        this.logger.warn(`[Proxy] Test failed for ${label}: ${message}`);
        return { error: message, success: false };
    }

    /**
     * Close local forwarders and agents (called on shutdown).
     */
    async closeAll() {
        await Promise.all([...this._forwarders.keys()].map(proxyId => this._closeForwarder(proxyId)));
        for (const { agent } of this._nodeAgents.values()) {
            agent.destroy();
        }
        this._nodeAgents.clear();
    }
}

module.exports = AccountProxyManager;
