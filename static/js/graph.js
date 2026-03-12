(function () {
    const LOGGER_SOURCE = "graph-page";
    const state = {
        rawData: null,
        graph: null,
        renderer: null,
        selectedNode: null,
        selectedEdge: null,
        query: "",
        riskyOnly: false,
        neighborSet: new Set(),
        dnsServers: new Set(),
        lastNodeClickTs: 0,
        lastEdgeClickTs: 0,
        showAllNeighbors: false,
    };

    const els = {
        loadingState: document.getElementById("loadingState"),
        errorState: document.getElementById("errorState"),
        graphWorkspace: document.getElementById("graphWorkspace"),
        graphContainer: document.getElementById("networkGraph"),
        statNodes: document.getElementById("statNodes"),
        statEdges: document.getElementById("statEdges"),
        statRisky: document.getElementById("statRisky"),
        searchInput: document.getElementById("searchInput"),
        searchBtn: document.getElementById("searchBtn"),
        clearBtn: document.getElementById("clearBtn"),
        riskyOnly: document.getElementById("riskyOnly"),
        zoomInBtn: document.getElementById("zoomInBtn"),
        zoomOutBtn: document.getElementById("zoomOutBtn"),
        fitBtn: document.getElementById("fitBtn"),
        nodeDetails: document.getElementById("nodeDetails"),
    };

    document.addEventListener("DOMContentLoaded", async () => {
        logInfo("Graph page initialized");
        bindUiEvents();
        await loadLatestGraph();
    });

    function bindUiEvents() {
        els.searchBtn.addEventListener("click", onSearch);
        els.searchInput.addEventListener("keydown", (event) => {
            if (event.key === "Enter") {
                event.preventDefault();
                onSearch();
            }
        });
        els.clearBtn.addEventListener("click", resetSelection);
        els.riskyOnly.addEventListener("change", () => {
            state.riskyOnly = els.riskyOnly.checked;
            refreshRenderer();
        });
        els.zoomInBtn.addEventListener("click", () => zoomBy(0.75));
        els.zoomOutBtn.addEventListener("click", () => zoomBy(1.35));
        els.fitBtn.addEventListener("click", fitGraph);
        els.nodeDetails.addEventListener("click", (event) => {
            const button = event.target.closest("[data-node-id]");
            if (button) {
                focusNode(button.dataset.nodeId);
                return;
            }

            const actionBtn = event.target.closest("[data-action='toggle-neighbors']");
            if (actionBtn && state.selectedNode) {
                state.showAllNeighbors = !state.showAllNeighbors;
                renderNodeDetails(state.selectedNode);
            }
        });
    }

    async function loadLatestGraph() {
        showLoading();
        try {
            const dataUrl = await resolveDataUrl();
            if (!dataUrl) {
                throw new Error("Результат анализа не найден. Запустите анализ на главной странице.");
            }
            logInfo("Loading graph data", { dataUrl });
            const response = await fetch(dataUrl);
            if (!response.ok) {
                throw new Error("Не удалось загрузить JSON с результатами анализа.");
            }
            const payload = await response.json();
            state.rawData = payload;
            persistLastDataUrl(dataUrl);
            showWorkspace();
            initSigmaGraph(payload);
            logInfo("Graph loaded successfully", {
                nodes: payload?.Network_Graph?.nodes?.length || 0,
                edges: payload?.Network_Graph?.edges?.length || 0,
            });
        } catch (error) {
            logError("Graph loading failed", { error: error?.message || String(error) });
            showError(error.message || "Ошибка загрузки графа.");
        }
    }

    async function resolveDataUrl() {
        const fromStorage = readLastDataUrl();
        if (fromStorage) return fromStorage;

        const response = await fetch("/api/latest-result");
        if (!response.ok) return null;
        const payload = await response.json();
        return payload?.dataUrl || null;
    }

    function initSigmaGraph(data) {
        const SigmaClass = resolveSigmaClass();
        if (!window.graphology || !SigmaClass) {
            logError("Sigma class was not found on window", {
                hasGraphology: Boolean(window.graphology),
                hasSigmaUpper: typeof window.Sigma,
                hasSigmaNamespace: typeof window.sigma,
                hasSigmaNamespaceClass: typeof window.sigma?.Sigma,
            });
            throw new Error("Не удалось загрузить библиотеку визуализации (Sigma.js).");
        }

        const Graph =
            window.graphology.MultiDirectedGraph ||
            window.graphology.DirectedGraph ||
            window.graphology.MultiGraph ||
            window.graphology.Graph;
        if (!Graph) {
            throw new Error("Конструктор графа Graphology не найден.");
        }
        const graph = new Graph();
        const ipDetails = data?.IP_Details || {};
        const nodes = data?.Network_Graph?.nodes || [];
        const edges = data?.Network_Graph?.edges || [];
        state.dnsServers = extractDnsServers(ipDetails);

        const nodeCount = Math.max(1, nodes.length);
        const radius = Math.max(3, Math.sqrt(nodeCount) * 2.6);

        nodes.forEach((node, index) => {
            if (!node || !node.id || graph.hasNode(node.id)) return;
            const angle = (2 * Math.PI * index) / nodeCount;
            const details = ipDetails[node.id] || {};
            const packets = details?.traffic?.total_packets || 0;
            const bytes = details?.traffic?.total_bytes || 0;
            const isBlacklisted = Boolean(details?.threat_info?.is_blacklisted);
            const isDnsServer = state.dnsServers.has(node.id);
            graph.addNode(node.id, {
                label: node.id,
                x: Math.cos(angle) * radius,
                y: Math.sin(angle) * radius,
                size: Math.max(3, Math.min(12, Math.log10(packets + 10) * 2.3)),
                color: resolveNodeBaseColor({ isBlacklisted, isDnsServer }),
                packets,
                bytes,
                asn: details?.asn || "Unknown",
                threat: details?.threat_info?.threat_level || "Безопасный",
                isBlacklisted,
                isDnsServer,
            });
        });

        edges.forEach((edge, index) => {
            if (!edge?.from || !edge?.to) return;
            if (!graph.hasNode(edge.from) || !graph.hasNode(edge.to)) return;
            const key = `${edge.from}->${edge.to}-${index}`;
            try {
                if (typeof graph.addDirectedEdgeWithKey === "function") {
                    graph.addDirectedEdgeWithKey(key, edge.from, edge.to, {
                        size: calculateEdgeBaseSize(edge.value),
                        color: "#cbd5e1",
                        type: "arrow",
                        trafficScore: Number(edge.value || 0),
                    });
                } else if (typeof graph.addEdgeWithKey === "function") {
                    graph.addEdgeWithKey(key, edge.from, edge.to, {
                        size: calculateEdgeBaseSize(edge.value),
                        color: "#cbd5e1",
                        type: "arrow",
                        trafficScore: Number(edge.value || 0),
                    });
                } else {
                    graph.addEdge(edge.from, edge.to, {
                        size: calculateEdgeBaseSize(edge.value),
                        color: "#cbd5e1",
                        type: "arrow",
                        trafficScore: Number(edge.value || 0),
                    });
                }
            } catch (error) {
                // Duplicate edges are acceptable in visual analysis; skip noisy failures.
                logInfo("Skipped edge while building graph", { key, reason: error?.message || "unknown" });
            }
        });

        if (window.graphologyLayoutForceatlas2?.assign && graph.order > 1) {
            window.graphologyLayoutForceatlas2.assign(graph, {
                iterations: Math.min(300, graph.order * 4),
                settings: {
                    gravity: 0.8,
                    scalingRatio: 12,
                    strongGravityMode: false,
                },
            });
        }

        state.graph = graph;
        renderSigma(SigmaClass);
        updateStats();
    }

    function renderSigma(SigmaClass) {
        if (state.renderer) {
            state.renderer.kill();
            state.renderer = null;
        }

        ensureGraphContainerHasSize();

        state.renderer = new SigmaClass(state.graph, els.graphContainer, {
            minCameraRatio: 0.05,
            maxCameraRatio: 8,
            defaultEdgeType: "arrow",
            enableEdgeClickEvents: true,
            renderLabels: true,
            defaultLabelSize: 12,
            defaultLabelColor: "#0f172a",
            labelRenderedSizeThreshold: 6,
            nodeReducer: (node, data) => reduceNode(node, data),
            edgeReducer: (edge, data) => reduceEdge(edge, data),
        });

        state.renderer.on("clickNode", ({ node }) => {
            state.lastNodeClickTs = Date.now();
            focusNode(node);
        });

        state.renderer.on("clickEdge", ({ edge }) => {
            state.lastEdgeClickTs = Date.now();
            focusEdge(edge);
        });

        state.renderer.on("clickStage", () => {
            // В Sigma clickStage может срабатывать сразу после clickNode.
            // Игнорируем такие события, чтобы не сбрасывать выбор мгновенно.
            const sinceNodeClick = Date.now() - state.lastNodeClickTs;
            const sinceEdgeClick = Date.now() - state.lastEdgeClickTs;
            if (sinceNodeClick < 220 || sinceEdgeClick < 220) {
                return;
            }
            resetSelection();
        });

        // Повторно подгоняем canvas после первой отрисовки.
        requestAnimationFrame(() => {
            if (state.renderer) {
                state.renderer.refresh();
            }
        });
    }

    function reduceNode(nodeId, data) {
        const next = { ...data };
        const selected = state.selectedNode === nodeId;
        const hasQuery = state.query.length > 0;
        const queryMatch = hasQuery && nodeId.toLowerCase().includes(state.query);
        const isNeighbor = state.neighborSet.has(nodeId);
        const isSelected = state.selectedNode === nodeId;
        const hiddenByRisk = state.riskyOnly && !data.isBlacklisted && !isSelected;

        if (hiddenByRisk) {
            next.hidden = true;
            return next;
        }

        if (selected) {
            next.color = "#f59e0b";
            next.size = data.size + 2;
            next.zIndex = 2;
            return next;
        }

        if (state.selectedEdge) {
            const source = state.graph.source(state.selectedEdge);
            const target = state.graph.target(state.selectedEdge);
            if (nodeId === source || nodeId === target) {
                next.color = "#f59e0b";
                next.size = data.size + 1.5;
                next.zIndex = 2;
            } else {
                next.color = "#cbd5e1";
                next.label = "";
            }
            return next;
        }

        if (state.selectedNode) {
            if (isNeighbor) {
                next.color = resolveNeighborColor(data);
                next.zIndex = 1;
            } else {
                next.color = "#cbd5e1";
                next.label = "";
            }
            return next;
        }

        if (queryMatch) {
            next.color = "#0ea5e9";
            next.size = data.size + 1.5;
        }

        return next;
    }

    function reduceEdge(edgeId, data) {
        const next = { ...data };
        const source = state.graph.source(edgeId);
        const target = state.graph.target(edgeId);

        if (state.riskyOnly) {
            const sourceNode = state.graph.getNodeAttributes(source);
            const targetNode = state.graph.getNodeAttributes(target);
            if (!sourceNode.isBlacklisted || !targetNode.isBlacklisted) {
                next.hidden = true;
                return next;
            }
        }

        if (state.selectedNode) {
            const isRelated = source === state.selectedNode || target === state.selectedNode;
            if (isRelated) {
                next.color = "#475569";
                next.size = Math.max(2.3, Number(data.size || 1));
            } else {
                next.color = "#e2e8f0";
                next.size = 0.5;
            }
        }

        if (state.selectedEdge) {
            if (edgeId === state.selectedEdge) {
                next.color = "#f59e0b";
                next.size = 2.6;
                next.zIndex = 2;
            } else {
                next.color = "#e2e8f0";
                next.size = 0.5;
            }
        }
        return next;
    }

    function onSearch() {
        const query = (els.searchInput.value || "").trim().toLowerCase();
        state.query = query;
        if (!query) {
            refreshRenderer();
            return;
        }

        const nodeId = state.graph
            .nodes()
            .find((id) => id.toLowerCase().includes(query));

        if (!nodeId) {
            showError("IP не найден в текущем наборе данных.");
            return;
        }

        focusNode(nodeId);
    }

    function focusNode(nodeId) {
        if (!state.graph.hasNode(nodeId)) return;
        state.selectedNode = nodeId;
        state.selectedEdge = null;
        state.query = nodeId.toLowerCase();
        state.showAllNeighbors = false;

        const neighbors = new Set([nodeId]);
        state.graph.forEachNeighbor(nodeId, (neighbor) => neighbors.add(neighbor));
        state.neighborSet = neighbors;

        renderNodeDetails(nodeId);
        refreshRenderer();
    }

    function focusEdge(edgeId) {
        if (!state.graph.hasEdge(edgeId)) return;
        state.selectedEdge = edgeId;
        state.selectedNode = null;
        state.query = "";
        state.neighborSet = new Set();
        renderEdgeDetails(edgeId);
        refreshRenderer();
    }

    function resetSelection() {
        state.selectedNode = null;
        state.selectedEdge = null;
        state.query = "";
        state.neighborSet = new Set();
        state.showAllNeighbors = false;
        els.searchInput.value = "";
        renderNodeDetails(null);
        refreshRenderer();
    }

    function renderNodeDetails(nodeId) {
        if (!nodeId) {
            els.nodeDetails.className = "muted";
            els.nodeDetails.textContent = "Выберите узел на графе, чтобы увидеть детали.";
            return;
        }

        const node = state.graph.getNodeAttributes(nodeId);
        const neighbors = (state.graph.neighbors(nodeId) || []).sort((a, b) => a.localeCompare(b));
        const roleLabel = node.isDnsServer ? "DNS-сервер" : "Хост";
        const previewCount = 12;
        const visibleNeighbors = state.showAllNeighbors ? neighbors : neighbors.slice(0, previewCount);
        const neighborsHtml = visibleNeighbors
            .map((id) => `<button class="neighbor-btn" data-node-id="${id}">${id}</button>`)
            .join("");
        const hiddenCount = Math.max(0, neighbors.length - visibleNeighbors.length);
        const toggleButton = neighbors.length > previewCount
            ? `<button class="btn btn-sm btn-outline-secondary mt-2" data-action="toggle-neighbors">
                    ${state.showAllNeighbors ? "Свернуть список" : `Показать все (${neighbors.length})`}
               </button>`
            : "";

        els.nodeDetails.className = "";
        els.nodeDetails.innerHTML = `
            <div class="details-grid">
                <div class="detail-row"><span class="detail-key">IP</span><span class="detail-val">${nodeId}</span></div>
                <div class="detail-row"><span class="detail-key">ASN</span><span class="detail-val">${escapeHtml(node.asn)}</span></div>
                <div class="detail-row"><span class="detail-key">Роль</span><span class="detail-val">${roleLabel}</span></div>
                <div class="detail-row"><span class="detail-key">Трафик</span><span class="detail-val">${formatBytes(node.bytes)}</span></div>
                <div class="detail-row"><span class="detail-key">Пакеты</span><span class="detail-val">${formatNumber(node.packets)}</span></div>
                <div class="detail-row"><span class="detail-key">Риск</span><span class="detail-val">${escapeHtml(node.threat)}</span></div>
                <div class="detail-row"><span class="detail-key">Связей</span><span class="detail-val">${neighbors.length}</span></div>
            </div>
            ${neighbors.length ? `<div class="neighbors-list ${state.showAllNeighbors ? "expanded" : ""}">${neighborsHtml}</div>` : ""}
            ${hiddenCount > 0 && !state.showAllNeighbors ? `<div class="neighbors-hint">Скрыто еще: ${hiddenCount}</div>` : ""}
            ${toggleButton}
        `;
    }

    function renderEdgeDetails(edgeId) {
        const source = state.graph.source(edgeId);
        const target = state.graph.target(edgeId);
        const attrs = state.graph.getEdgeAttributes(edgeId) || {};
        const score = Number(attrs.trafficScore || 0);
        const telemetry = buildEdgeTelemetry(source, target);
        const protocolChips = telemetry.protocols.length
            ? telemetry.protocols
                .map((p) => `<span class="proto-chip">${escapeHtml(p.name)}: ${formatNumber(p.count)}</span>`)
                .join("")
            : '<span class="text-muted">Недостаточно данных</span>';
        const contentBlocks = [];
        if (telemetry.dnsQueries.length) {
            contentBlocks.push(`
                <div class="edge-block">
                    <div class="edge-block-title">DNS запросы к серверу ${escapeHtml(target)}</div>
                    <div class="edge-list">${telemetry.dnsQueries.map((q) => `<div class="edge-list-item">${escapeHtml(q)}</div>`).join("")}</div>
                </div>
            `);
        }
        if (telemetry.httpRequests.length) {
            contentBlocks.push(`
                <div class="edge-block">
                    <div class="edge-block-title">HTTP запросы от ${escapeHtml(source)}</div>
                    <div class="edge-list">${telemetry.httpRequests.map((q) => `<div class="edge-list-item">${escapeHtml(q)}</div>`).join("")}</div>
                </div>
            `);
        }
        if (telemetry.httpResponses.length) {
            contentBlocks.push(`
                <div class="edge-block">
                    <div class="edge-block-title">HTTP ответы (контент)</div>
                    <div class="edge-list">${telemetry.httpResponses.map((q) => `<div class="edge-list-item">${escapeHtml(q)}</div>`).join("")}</div>
                </div>
            `);
        }
        if (telemetry.tlsRecords.length) {
            contentBlocks.push(`
                <div class="edge-block">
                    <div class="edge-block-title">TLS / SNI</div>
                    <div class="edge-list">${telemetry.tlsRecords.map((q) => `<div class="edge-list-item">${escapeHtml(q)}</div>`).join("")}</div>
                </div>
            `);
        }

        els.nodeDetails.className = "";
        els.nodeDetails.innerHTML = `
            <div class="details-grid">
                <div class="detail-row"><span class="detail-key">Тип</span><span class="detail-val">Соединение</span></div>
                <div class="detail-row"><span class="detail-key">Инициатор</span><span class="detail-val">${escapeHtml(source)}</span></div>
                <div class="detail-row"><span class="detail-key">Назначение</span><span class="detail-val">${escapeHtml(target)}</span></div>
                <div class="detail-row"><span class="detail-key">Направление</span><span class="detail-val">${escapeHtml(source)} → ${escapeHtml(target)}</span></div>
                <div class="detail-row"><span class="detail-key">Метрика трафика</span><span class="detail-val">${formatNumber(score)}</span></div>
            </div>
            <div class="edge-block">
                <div class="edge-block-title">Протоколы и активность</div>
                <div class="proto-chips">${protocolChips}</div>
            </div>
            ${contentBlocks.join("") || '<div class="edge-tip">Для этой связи нет детализированных протокольных данных.</div>'}
            <div class="edge-tip">Стрелка показывает, кто инициировал соединение.</div>
        `;
    }

    function zoomBy(multiplier) {
        const camera = state.renderer.getCamera();
        camera.animate(
            { ratio: Math.max(0.05, Math.min(8, camera.ratio * multiplier)) },
            { duration: 200 }
        );
    }

    function fitGraph() {
        if (!state.renderer) return;
        const camera = state.renderer.getCamera();
        if (typeof camera.animatedReset === "function") {
            camera.animatedReset();
            return;
        }
        camera.animate({ x: 0, y: 0, ratio: 1 }, { duration: 250 });
    }

    function updateStats() {
        const risky = state.graph
            .nodes()
            .filter((nodeId) => state.graph.getNodeAttribute(nodeId, "isBlacklisted")).length;
        els.statNodes.textContent = formatNumber(state.graph.order);
        els.statEdges.textContent = formatNumber(state.graph.size);
        els.statRisky.textContent = formatNumber(risky);
    }

    function refreshRenderer() {
        hideError();
        if (state.renderer) {
            state.renderer.refresh();
        }
    }

    function showLoading() {
        els.loadingState.classList.remove("d-none");
        els.graphWorkspace.classList.add("d-none");
        hideError();
    }

    function showWorkspace() {
        els.loadingState.classList.add("d-none");
        els.graphWorkspace.classList.remove("d-none");
    }

    function showError(message) {
        els.loadingState.classList.add("d-none");
        els.errorState.classList.remove("d-none");
        els.errorState.textContent = message;
    }

    function hideError() {
        els.errorState.classList.add("d-none");
        els.errorState.textContent = "";
    }

    function persistLastDataUrl(dataUrl) {
        try {
            localStorage.setItem("netparser_last_data_url", dataUrl);
        } catch (_) {
            // ignore storage write errors
        }
    }

    function readLastDataUrl() {
        try {
            return localStorage.getItem("netparser_last_data_url");
        } catch (_) {
            return null;
        }
    }

    function formatBytes(bytes) {
        const value = Number(bytes || 0);
        if (value === 0) return "0 B";
        const units = ["B", "KB", "MB", "GB", "TB"];
        let current = value;
        let idx = 0;
        while (current >= 1024 && idx < units.length - 1) {
            current /= 1024;
            idx += 1;
        }
        return `${current.toFixed(1)} ${units[idx]}`;
    }

    function formatNumber(number) {
        return Number(number || 0).toLocaleString("ru-RU", { maximumFractionDigits: 2 });
    }

    function buildEdgeTelemetry(sourceIp, targetIp) {
        const sourceDetails = state.rawData?.IP_Details?.[sourceIp] || {};
        const targetDetails = state.rawData?.IP_Details?.[targetIp] || {};

        const dnsQueriesRaw = sourceDetails?.dns?.queries_by_server?.[targetIp] || [];
        const dnsQueries = dnsQueriesRaw
            .map((entry) => String(entry || "").trim())
            .filter(Boolean)
            .slice(0, 10);

        const sourceHttpRequests = Array.isArray(sourceDetails?.http?.requests) ? sourceDetails.http.requests : [];
        const targetHttpResponses = Array.isArray(targetDetails?.http?.responses) ? targetDetails.http.responses : [];
        const sourceTls = Array.isArray(sourceDetails?.tls?.sni_records) ? sourceDetails.tls.sni_records : [];

        const httpRequests = sourceHttpRequests
            .map((req) => {
                const method = (req?.method || "GET").toString();
                const host = (req?.host || "").toString();
                const uri = (req?.uri || "/").toString();
                return `${method} ${uri}${host ? ` (Host: ${host})` : ""}`;
            })
            .filter(Boolean)
            .slice(0, 8);

        const httpResponses = targetHttpResponses
            .map((resp) => {
                const status = resp?.status_code || "-";
                const statusMsg = resp?.status_message || "";
                const contentType = resp?.content_type || "unknown";
                const length = resp?.content_length || "-";
                return `${status} ${statusMsg} | ${contentType} | ${length} bytes`;
            })
            .filter(Boolean)
            .slice(0, 8);

        const tlsRecords = sourceTls
            .map((record) => String(record || "").trim())
            .filter(Boolean)
            .slice(0, 8);

        const protocols = [];
        if (dnsQueries.length) protocols.push({ name: "DNS", count: dnsQueries.length });
        if (httpRequests.length || httpResponses.length) {
            protocols.push({ name: "HTTP", count: httpRequests.length + httpResponses.length });
        }
        if (tlsRecords.length) protocols.push({ name: "TLS", count: tlsRecords.length });

        return {
            protocols,
            dnsQueries,
            httpRequests,
            httpResponses,
            tlsRecords,
        };
    }

    function calculateEdgeBaseSize(rawValue) {
        const value = Number(rawValue || 0);
        if (value <= 0) return 1.3;
        return Math.max(1.3, Math.min(3.3, Math.log10(value + 1) + 1.15));
    }

    function escapeHtml(text) {
        return String(text || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function resolveSigmaClass() {
        if (typeof window.Sigma === "function") {
            return window.Sigma;
        }
        if (typeof window.sigma === "function") {
            return window.sigma;
        }
        if (window.sigma && typeof window.sigma.Sigma === "function") {
            return window.sigma.Sigma;
        }
        return null;
    }

    function ensureGraphContainerHasSize() {
        const rect = els.graphContainer.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
            return;
        }

        // Fallback на случай, если CSS еще не применился в момент инициализации.
        if (!els.graphContainer.style.minHeight) {
            els.graphContainer.style.minHeight = "70vh";
        }
        if (!els.graphContainer.style.width) {
            els.graphContainer.style.width = "100%";
        }
        logInfo("Applied graph container size fallback", {
            width: rect.width,
            height: rect.height,
        });
    }

    function extractDnsServers(ipDetails) {
        const servers = new Set();
        const allDetails = Object.entries(ipDetails || {});

        for (const [ip, details] of allDetails) {
            const responses = details?.dns?.responses || [];
            const hasRealDnsResponse = responses.some((response) => {
                if (!response || typeof response !== "object") return false;
                const type = String(response.type || "").toUpperCase();
                const name = String(response.name || "").trim();
                const resolution = String(response.resolution || "").trim();
                return type && type !== "UNKNOWN" && (name || resolution);
            });
            if (hasRealDnsResponse) {
                servers.add(ip);
            }
        }

        return servers;
    }

    function resolveNodeBaseColor(nodeData) {
        if (nodeData.isBlacklisted) return "#dc2626";
        if (nodeData.isDnsServer) return "#7c3aed";
        return "#2563eb";
    }

    function resolveNeighborColor(nodeData) {
        if (nodeData.isBlacklisted) return "#ef4444";
        if (nodeData.isDnsServer) return "#8b5cf6";
        return "#3b82f6";
    }

    function logInfo(message, meta = null) {
        console.info(`[graph] ${message}`, meta || "");
        postFrontendLog("info", message, meta);
    }

    function logError(message, meta = null) {
        console.error(`[graph] ${message}`, meta || "");
        postFrontendLog("error", message, meta);
    }

    function postFrontendLog(level, message, meta) {
        const payload = {
            source: LOGGER_SOURCE,
            level,
            message,
            meta: meta || {},
        };

        try {
            const body = JSON.stringify(payload);
            if (navigator.sendBeacon) {
                const blob = new Blob([body], { type: "application/json" });
                navigator.sendBeacon("/api/frontend-log", blob);
                return;
            }
            fetch("/api/frontend-log", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body,
                keepalive: true,
            }).catch(() => {});
        } catch (_) {
            // Ignore telemetry errors.
        }
    }
})();
