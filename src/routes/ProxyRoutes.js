/**
 * File: src/routes/ProxyRoutes.js
 * Description: Proxy management routes (CRUD, connectivity test) and per-account proxy assignment
 */

const { isAccountProxyError } = require("../utils/CustomErrors");

/**
 * Proxy Routes Manager
 * Manages the proxy store and applies proxy changes to the affected account contexts
 */
class ProxyRoutes {
    constructor(serverSystem) {
        this.serverSystem = serverSystem;
        this.logger = serverSystem.logger;
    }

    get proxyManager() {
        return this.serverSystem.browserManager.accountProxyManager;
    }

    _rejectIfSystemBusy(res) {
        if (!this.serverSystem.requestHandler?.isSystemBusy) {
            return false;
        }

        return res.status(409).json({
            error: "System is busy switching or recovering accounts. Please try again later.",
            message: "systemBusySwitchingOrRecoveringAccounts",
        });
    }

    _sendError(res, error, fallbackMessageKey) {
        if (isAccountProxyError(error)) {
            return res.status(error.status).json({ ...error.details, error: error.message, message: error.messageKey });
        }
        this.logger.error(`[Proxy] Request failed (${fallbackMessageKey}): ${error.message}`);
        return res.status(500).json({ error: error.message, message: fallbackMessageKey });
    }

    /**
     * Recreate the live browser contexts of the given accounts so that proxy changes take effect immediately.
     * Accounts without a live context pick up the change on their next initialization.
     * Runs in the background; the system stays busy while the current account is being recreated.
     * @param {number[]} authIndices - Accounts affected by the change
     * @param {string} reason - Reason for logging
     * @returns {number[]} Indices whose contexts are being recreated
     */
    _recreateAccountContexts(authIndices, reason) {
        const { browserManager, connectionRegistry, requestHandler } = this.serverSystem;
        const targets = [...new Set(authIndices)].filter(
            index => browserManager.contexts.has(index) || browserManager.initializingContexts.has(index)
        );
        if (targets.length === 0) {
            return [];
        }

        const currentAuthIndex = requestHandler.currentAuthIndex;
        const includesCurrent = targets.includes(currentAuthIndex);
        if (includesCurrent) {
            // Hold new requests until the current account is back with its new proxy settings
            requestHandler.isSystemBusy = true;
        }

        const recreate = async () => {
            await browserManager.abortBackgroundPreload();
            for (const index of targets) {
                this.logger.info(`[Proxy] Closing context #${index} to apply proxy change (${reason})...`);
                await browserManager.closeContext(index);
                connectionRegistry.closeConnectionByAuth(index);
            }
            if (includesCurrent) {
                this.logger.info(`[Proxy] Re-initializing current account #${currentAuthIndex} with its new proxy...`);
                await browserManager.launchOrSwitchContext(currentAuthIndex);
                this.logger.info(`✅ [Proxy] Account #${currentAuthIndex} is ready with its new proxy settings.`);
            }
        };

        recreate()
            .catch(error => this.logger.error(`❌ [Proxy] Failed to recreate account context(s): ${error.message}`))
            .finally(() => {
                if (includesCurrent) {
                    requestHandler.isSystemBusy = false;
                }
                // Background contexts are re-created by the pool with their new proxy settings
                browserManager.rebalanceContextPool().catch(error => {
                    this.logger.error(`[Proxy] Background rebalance failed: ${error.message}`);
                });
            });

        return targets;
    }

    async _handleTest(input, res) {
        try {
            const result = await this.proxyManager.testProxy(input);
            res.status(200).json({ ...result, message: result.success ? "proxyTestSuccess" : "proxyTestFailed" });
        } catch (error) {
            this._sendError(res, error, "proxyTestFailed");
        }
    }

    /**
     * Setup proxy management routes
     */
    setupRoutes(app, isAuthenticated) {
        app.get("/api/proxies", isAuthenticated, (req, res) => {
            res.status(200).json({
                proxies: this.proxyManager.listProxies(),
                storeError: this.proxyManager.storeError,
            });
        });

        app.post("/api/proxies", isAuthenticated, (req, res) => {
            try {
                const proxy = this.proxyManager.createProxy(req.body);
                this.logger.info(`[Proxy] Created proxy ${this.proxyManager.describeProxy(proxy)} via web interface.`);
                res.status(201).json({ message: "proxyCreateSuccess", proxy });
            } catch (error) {
                this._sendError(res, error, "proxySaveFailed");
            }
        });

        // Test unsaved settings (e.g. from the edit dialog); with `id`, omitted fields come from the stored proxy
        app.post("/api/proxies/test", isAuthenticated, async (req, res) => {
            await this._handleTest(req.body || {}, res);
        });

        app.post("/api/proxies/:id/test", isAuthenticated, async (req, res) => {
            await this._handleTest({ id: req.params.id }, res);
        });

        app.put("/api/proxies/:id", isAuthenticated, (req, res) => {
            if (this._rejectIfSystemBusy(res)) return;

            try {
                const { connectionChanged, proxy } = this.proxyManager.updateProxy(req.params.id, req.body);
                this.logger.info(`[Proxy] Updated proxy ${this.proxyManager.describeProxy(proxy)} via web interface.`);
                const recreatedIndices = connectionChanged
                    ? this._recreateAccountContexts(
                          this.proxyManager.getIndicesForProxy(proxy.id),
                          `proxy "${proxy.name}" updated`
                      )
                    : [];
                res.status(200).json({ message: "proxyUpdateSuccess", proxy, recreatedIndices });
            } catch (error) {
                this._sendError(res, error, "proxySaveFailed");
            }
        });

        app.delete("/api/proxies/:id", isAuthenticated, (req, res) => {
            if (this._rejectIfSystemBusy(res)) return;

            try {
                const proxyId = req.params.id;
                const affectedIndices = this.proxyManager.getIndicesForProxy(proxyId);
                if (affectedIndices.length > 0 && req.query.force !== "true") {
                    return res.status(409).json({
                        indices: affectedIndices.join(", "),
                        message: "proxyDeleteInUse",
                        requiresConfirmation: true,
                    });
                }

                const { proxy } = this.proxyManager.deleteProxy(proxyId);
                this.logger.info(
                    `[Proxy] Deleted proxy ${this.proxyManager.describeProxy(proxy)} via web interface` +
                        (affectedIndices.length > 0
                            ? ` (unassigned from accounts [${affectedIndices.join(", ")}]).`
                            : ".")
                );
                const recreatedIndices = this._recreateAccountContexts(
                    affectedIndices,
                    `proxy "${proxy.name}" deleted`
                );
                res.status(200).json({ message: "proxyDeleteSuccess", proxy, recreatedIndices });
            } catch (error) {
                this._sendError(res, error, "proxyDeleteFailed");
            }
        });

        app.put("/api/accounts/:index/proxy", isAuthenticated, (req, res) => {
            if (this._rejectIfSystemBusy(res)) return;

            const targetIndex = Number(req.params.index);
            if (!Number.isInteger(targetIndex)) {
                return res.status(400).json({ message: "errorInvalidIndex" });
            }
            if (!this.serverSystem.authSource.availableIndices.includes(targetIndex)) {
                return res.status(404).json({ index: targetIndex, message: "errorAccountNotFound" });
            }

            const rawProxyId = req.body?.proxyId;
            const proxyId = typeof rawProxyId === "string" && rawProxyId.trim() ? rawProxyId.trim() : null;

            try {
                const { accountKey, changed } = this.proxyManager.assignProxy(targetIndex, proxyId);
                let recreatedIndices = [];
                if (changed) {
                    const { proxyName } = this.proxyManager.getAccountProxyInfo(targetIndex);
                    this.logger.info(
                        `[Proxy] Account #${targetIndex} ("${accountKey}") ${
                            proxyId ? `assigned to proxy "${proxyName}"` : "unassigned from its proxy"
                        } via web interface.`
                    );
                    // Duplicate auth files of the same account share its assignment
                    recreatedIndices = this._recreateAccountContexts(
                        this.proxyManager.getAccountIndices(accountKey),
                        "account proxy assignment changed"
                    );
                }
                res.status(200).json({
                    index: targetIndex,
                    message: proxyId ? "proxyAssignSuccess" : "proxyUnassignSuccess",
                    proxyId,
                    recreatedIndices,
                });
            } catch (error) {
                this._sendError(res, error, "proxyAssignFailed");
            }
        });
    }
}

module.exports = ProxyRoutes;
