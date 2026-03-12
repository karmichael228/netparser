/**
 * NetParser Dashboard Pro v3.0
 * JavaScript for advanced network traffic analysis with unified interface
 */

// Global variables
let networkData = null;
let cyGraph = null;
let graphData = { nodes: [], links: [] };
let selectedNode = null;
let currentFilter = '';
let protocolChart = null;
let trafficChart = null;
let showNodeLabels = true;
let showTrafficParticles = true;
let edgeThicknessMultiplier = 2;
let highlightedNodeId = null;
let currentLayout = null;
let dnsClientQueriesMap = {};
let currentReportUrl = null;
const currentPage = document.body?.dataset?.page || 'dashboard';

const nodeLabelFormatter = (node) => {
    if (!node) return '';
    return `IP: ${node.id || 'Unknown'}
ASN: ${node.asn || 'Unknown'}
Трафик: ${formatBytes(node.traffic || 0)}
Пакеты: ${formatNumber(node.packets || 0)}
${node.is_blacklisted ? '⚠️ ПОДОЗРИТЕЛЬНЫЙ' : '✓ Безопасный'}`;
};

// DOM Ready
$(document).ready(function() {
    console.log('NetParser Pro v3.0 - Dashboard loaded');
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize form handlers
    initFormHandlers();

    // Register Cytoscape layouts if plugin exposed
    if (window.cytoscape && window.cytoscapeFcose) {
        cytoscape.use(window.cytoscapeFcose);
    }
    if (document.getElementById('networkGraph')) {
        initNetworkGraph();
    }

    // Initialize chart containers
    initChartContainers();

    // Initialize filters and search
    initFilters();
    
    // Initialize expandable handlers
    initExpandableHandlers();
    
    // Dark mode toggle
    $('#darkModeToggle').on('click', function() {
        toggleDarkMode();
    });

    $('#openHtmlReportBtn').on('click', function(e) {
        e.preventDefault();
        exportCurrentHtmlReport();
    });
    
    // Export graph as PNG
    $('#exportGraphPNG').on('click', function() {
        exportNetworkAsPNG();
    });

    // Delegate connection navigation
    $(document).on('click', '.connection-link', function() {
        const targetIp = $(this).data('ipTarget');
        if (targetIp) {
            jumpToIP(targetIp);
        }
    });
    
    // Delegate IP selection
    $(document).on('click', '.ip-item', function() {
        const ip = $(this).data('ip');
        if (!ip || !networkData || !networkData.IP_Details || !networkData.IP_Details[ip]) {
            return;
        }
        selectIP(ip);
        showIPDetails(ip, networkData.IP_Details[ip]);
    });

    // Delegate copy actions
    $(document).on('click', '.copy-ip-btn', function() {
        const ip = $(this).data('ip');
        if (ip) {
            copyTextToClipboard(ip, 'IP адрес скопирован');
        }
    });

    $(document).on('click', '.copy-url-btn', function() {
        const url = $(this).data('url');
        if (url) {
            const msg = $(this).data('toast') || 'URL скопирован';
            copyTextToClipboard(url, msg);
        }
    });

    $(document).on('click', '.copy-text-btn', function() {
        const text = $(this).data('copy');
        if (text) {
            copyTextToClipboard(text);
        }
    });
    
    // IP filter
    $('#ipFilter').on('input', function() {
        currentFilter = $(this).val().toLowerCase();
        filterIPList();
    });
    
    // DNS chain expand/collapse
    $(document).on('click', '.dns-chain-header', function() {
        const $group = $(this).closest('.dns-chain-group');
        $group.toggleClass('dns-chain-collapsed');
        const $chevron = $(this).find('.dns-chain-chevron');
        $chevron.toggleClass('fa-chevron-right fa-chevron-down');
    });
    $(document).on('keydown', '.dns-chain-header', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            $(this).trigger('click');
        }
    });

    if (currentPage === 'graph') {
        loadLatestGraphData();
    } else if (currentPage === 'dashboard') {
        loadLatestDashboardData();
    }
});

/**
 * Initialize form handlers
 */
function initFormHandlers() {
    // Fetch system information
    $.get('/api/system-info', function(data) {
        if (data.cpuCount) {
            $('#threads').attr('max', data.cpuCount);
            $('#threads').val(data.recommendedThreads);
            $('#cpuCoresFooter').text(data.cpuCount);
        }
    });

    // Single file analysis form
    $('#singleFileForm').on('submit', function(e) {
        e.preventDefault();
        
        const fileInput = $('#singleFile')[0];
        if (fileInput.files.length === 0) {
            showError('Пожалуйста, выберите PCAP файл для анализа');
            return;
        }

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('threads', $('#threads').val());
        formData.append('checkBlacklists', $('#checkBlacklists').is(':checked'));

        // Show loading indicator
        showLoading();

        // Submit form
        $.ajax({
            url: '/api/analyze',
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                if (response.success) {
                    if (response.dataUrl) {
                        persistLastDataUrl(response.dataUrl);
                    }
                    if (response.reportUrl) {
                        setCurrentReportUrl(response.reportUrl);
                    }
                    if (response.cpuCount && response.threadsUsed) {
                        console.log(`Используется ${response.threadsUsed} потоков из ${response.cpuCount} доступных CPU`);
                    }
                    loadData(response.dataUrl);
                } else {
                    hideLoading();
                    showError(response.error || 'Ошибка при анализе файла');
                }
            },
            error: function(xhr) {
                hideLoading();
                showError(xhr.responseJSON?.error || 'Ошибка при анализе файла');
            }
        });
    });

    // Compare files form
    $('#compareFilesForm').on('submit', function(e) {
        e.preventDefault();
        
        const baseFileInput = $('#baseFile')[0];
        const compareFileInput = $('#compareFile')[0];
        
        if (baseFileInput.files.length === 0 || compareFileInput.files.length === 0) {
            showError('Пожалуйста, выберите оба PCAP файла для сравнения');
            return;
        }

        const formData = new FormData();
        formData.append('baseFile', baseFileInput.files[0]);
        formData.append('compareFile', compareFileInput.files[0]);

        // Show loading indicator
        showLoading();

        // Submit form
        $.ajax({
            url: '/api/compare',
            type: 'POST',
            data: formData,
            contentType: false,
            processData: false,
            success: function(response) {
                if (response.success) {
                    if (response.dataUrl) {
                        persistLastDataUrl(response.dataUrl);
                    }
                    if (response.reportUrl) {
                        setCurrentReportUrl(response.reportUrl);
                    }
                    loadData(response.dataUrl);
                } else {
                    hideLoading();
                    showError(response.error || 'Ошибка при сравнении файлов');
                }
            },
            error: function(xhr) {
                hideLoading();
                showError(xhr.responseJSON?.error || 'Ошибка при сравнении файлов');
            }
        });
    });
}

/**
 * Initialize the network graph container with D3.js Force Graph
 */
function initNetworkGraph() {
    const container = document.getElementById('networkGraph');

    if (!container) {
        console.error('Network graph container not found');
        return;
    }

    cyGraph = cytoscape({
        container,
        elements: [],
        wheelSensitivity: 0.2,
        selectionType: 'single',
        minZoom: 0.2,
        maxZoom: 4,
        layout: { name: 'grid' },
        style: getCytoscapeStyles()
    });

    cyGraph.on('tap', 'node', (evt) => {
        const node = evt.target;
        if (!node) return;
        const nodeId = node.id();
        highlightedNodeId = nodeId;
        highlightNodeConnections(nodeId);
        selectIP(nodeId);
        if (networkData?.IP_Details?.[nodeId]) {
            showIPDetails(nodeId, networkData.IP_Details[nodeId]);
        }
        showNodeDetails(nodeId);
        cyGraph.center(node);
        cyGraph.animate({ zoom: Math.min(2, cyGraph.zoom() * 1.2), center: { eles: node } }, { duration: 400 });
    });

    cyGraph.on('tap', 'edge', (evt) => {
        const edge = evt.target;
        if (!edge) return;
        cyGraph.edges().removeClass('highlight');
        edge.addClass('highlight');
        showEdgeDetails({
            from: edge.data('source'),
            to: edge.data('target'),
            value: edge.data('weight')
        });
    });

    cyGraph.on('tap', function(evt) {
        if (evt.target === cyGraph) {
            highlightedNodeId = null;
            resetGraphHighlights();
            hideSelectionInfo();
        }
    });

    showGraphEmptyState();
    setupGraphControls();
    initGraphSidebarControls();

    window.addEventListener('resize', () => {
        if (cyGraph && container) {
            cyGraph.resize();
        }
    });

    console.log('Cytoscape network graph initialized');
}

/**
 * Setup enhanced graph controls
 */
function setupGraphControls() {
    $('#zoomIn').off('click').on('click', function() {
        if (cyGraph) {
            const currentZoom = cyGraph.zoom();
            cyGraph.zoom({
                level: currentZoom * 1.2,
                renderedPosition: { x: cyGraph.width() / 2, y: cyGraph.height() / 2 }
            });
        }
    });

    $('#zoomOut').off('click').on('click', function() {
        if (cyGraph) {
            const currentZoom = cyGraph.zoom();
            cyGraph.zoom({
                level: currentZoom * 0.8,
                renderedPosition: { x: cyGraph.width() / 2, y: cyGraph.height() / 2 }
            });
        }
    });

    $('#resetZoom').off('click').on('click', function() {
        if (cyGraph) {
            cyGraph.fit(cyGraph.elements(), 80);
        }
    });

    // Add keyboard shortcuts
    $(document).off('keydown.graph').on('keydown.graph', function(e) {
        if ($(e.target).is('input, textarea, select')) return; // Don't interfere with form inputs

        switch(e.key) {
            case '+':
            case '=':
                e.preventDefault();
                $('#zoomIn').click();
                break;
            case '-':
                e.preventDefault();
                $('#zoomOut').click();
                break;
            case '0':
                e.preventDefault();
                $('#resetZoom').click();
                break;
        }
    });
}

function initGraphSidebarControls() {
    $('#graphNodeSearch').off('keydown').on('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            const target = $(this).val().trim();
            focusGraphNode(target);
        }
    });

    $('#edgeThicknessRange').off('input').on('input', function() {
        const val = parseFloat($(this).val());
        if (!isNaN(val)) {
            edgeThicknessMultiplier = val;
            applyGraphStyles();
        }
    });

    $('#toggleLabels').off('change').on('change', function() {
        showNodeLabels = $(this).is(':checked');
        applyGraphStyles();
    });

    $('#toggleParticles').off('change').on('change', function() {
        showTrafficParticles = $(this).is(':checked');
        applyGraphStyles();
    });

    $('#reheatLayoutBtn').off('click').on('click', function() {
        if (cyGraph) {
            currentLayout = cyGraph.layout({
                name: 'fcose',
                animate: true,
                randomize: true,
                idealEdgeLength: 120,
                nodeSeparation: 100
            });
            currentLayout.run();
        }
    });

    $('#fitGraphBtn').off('click').on('click', function() {
        if (cyGraph) {
            cyGraph.fit(cyGraph.elements(':visible'), 80);
        }
    });
}

/**
 * Show empty state for network graph
 */
function showGraphEmptyState() {
    const container = document.getElementById('networkGraph');
    if (!container) return;

    if (container.querySelector('.graph-empty-state')) {
        return;
    }

    const emptyState = document.createElement('div');
    emptyState.className = 'graph-empty-state';
    emptyState.innerHTML = `
        <div class="empty-state-content">
            <i class="fas fa-diagram-project fa-4x text-muted mb-3"></i>
            <h4 class="text-muted">Граф сетевых соединений</h4>
            <p class="text-muted">Загрузите PCAP файл для анализа сетевого трафика</p>
            <div class="mt-3">
                <small class="text-muted">
                    <i class="fas fa-mouse-pointer me-2"></i>Кликните на узлы для подробной информации<br>
                    <i class="fas fa-search-plus me-2"></i>Используйте колесо мыши для масштабирования<br>
                    <i class="fas fa-arrows-alt me-2"></i>Перетаскивайте узлы для изменения расположения
                </small>
            </div>
        </div>
    `;

    container.appendChild(emptyState);
}

/**
 * Hide empty state when data is loaded
 */
function hideGraphEmptyState() {
    const container = document.getElementById('networkGraph');
    if (!container) return;

    const emptyState = container.querySelector('.graph-empty-state');
    if (emptyState) {
        emptyState.remove();
    }
}

/**
 * Initialize chart containers
 */
function initChartContainers() {
    // Protocol chart placeholder
    if (typeof ApexCharts !== 'undefined') {
        console.log('ApexCharts initialized');
    }
}

/**
 * Initialize filters
 */
function initFilters() {
    $('#showBlacklistedOnly').on('change', function() {
        filterNetworkGraph();
    });
    
    $('#hideIsolatedNodes').on('change', function() {
        filterNetworkGraph();
    });
}

/**
 * Load and process data from URL
 */
function loadData(url) {
    $.getJSON(url)
        .done(function(data) {
            networkData = data;
            console.log('Data loaded:', data);
            processData(data);
            hideLoading();
            
            if (currentPage === 'graph') {
                $('#network-section').removeClass('d-none').addClass('scale-in');
            } else {
                // Show dashboard sections
                $('#dashboard-section').removeClass('d-none').addClass('scale-in');
                $('#analysis-section').removeClass('d-none').addClass('scale-in');
            }
        })
        .fail(function() {
            hideLoading();
            showError('Не удалось загрузить данные анализа');
    });
}

function persistLastDataUrl(dataUrl) {
    if (!dataUrl) return;
    try {
        localStorage.setItem('netparser_last_data_url', dataUrl);
    } catch (error) {
        console.warn('Unable to save last data URL to localStorage', error);
    }
}

function loadLatestGraphData() {
    showLoading();
    let savedUrl = null;
    try {
        savedUrl = localStorage.getItem('netparser_last_data_url');
    } catch (error) {
        console.warn('Unable to read last data URL from localStorage', error);
    }

    if (savedUrl) {
        loadData(savedUrl);
        return;
    }

    $.get('/api/latest-result')
        .done(function(response) {
            if (!response || !response.dataUrl) {
                hideLoading();
                showError('Последний результат анализа не найден. Запустите анализ на главной странице.');
                return;
            }
            persistLastDataUrl(response.dataUrl);
            loadData(response.dataUrl);
        })
        .fail(function() {
            hideLoading();
            showError('Последний результат анализа не найден. Запустите анализ на главной странице.');
        });
}

function loadLatestDashboardData() {
    let savedUrl = null;
    try {
        savedUrl = localStorage.getItem('netparser_last_data_url');
    } catch (error) {
        console.warn('Unable to read last data URL from localStorage', error);
    }

    if (savedUrl) {
        loadData(savedUrl);
        $.get('/api/latest-result').done(function(response) {
            if (response && response.reportUrl) {
                setCurrentReportUrl(response.reportUrl);
            }
        });
        showCopyToast('Загружен последний анализ');
        return;
    }

    $.get('/api/latest-result')
        .done(function(response) {
            if (!response || !response.dataUrl) {
                return;
            }
            persistLastDataUrl(response.dataUrl);
            if (response.reportUrl) {
                setCurrentReportUrl(response.reportUrl);
            }
            loadData(response.dataUrl);
            showCopyToast('Загружен последний анализ');
        })
        .fail(function() {
            // Не показываем ошибку: на чистом запуске данных может не быть.
        });
}

function setCurrentReportUrl(reportUrl) {
    currentReportUrl = reportUrl || null;
    const reportBtn = $('#openHtmlReportBtn');
    if (!reportBtn.length) return;

    if (currentReportUrl) {
        reportBtn.attr('data-report-url', currentReportUrl).removeClass('d-none');
    } else {
        reportBtn.removeAttr('data-report-url').addClass('d-none');
    }
}

function exportCurrentHtmlReport() {
    if (!currentReportUrl) {
        showError('HTML отчет пока недоступен. Сначала выполните анализ.');
        return;
    }
    const exportUrl = `/api/export-report?reportUrl=${encodeURIComponent(currentReportUrl)}`;
    const link = document.createElement('a');
    link.href = exportUrl;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

/**
 * Process the loaded data
 */
function processData(data) {
    // Update dashboard
    updateDashboard(data);
    
    // Update network graph only when graph container exists
    if (document.getElementById('networkGraph')) {
        updateNetworkGraph(data);
    }

    // Build DNS lookup helpers
    buildDnsClientLookup();
    
    // Update IP list
    updateIPList(data);
}

/**
 * Update dashboard metrics and charts
 */
function updateDashboard(data) {
    const stats = data.Overall_Packet_Statistics || {};
    const ipDetails = data.IP_Details || {};
    
    // Calculate metrics
    const totalPackets = stats.total_packets || 0;
    const uniqueIPs = Object.keys(ipDetails).length;
    let totalTraffic = 0;
    let suspiciousIPs = 0;
    
    Object.values(ipDetails).forEach(ip => {
        totalTraffic += ip.traffic.total_bytes || 0;
        if (ip.threat_info.is_blacklisted) {
            suspiciousIPs++;
        }
    });
    
    // Update key metrics
    $('#totalPackets').text(formatNumber(totalPackets));
    $('#uniqueIPs').text(formatNumber(uniqueIPs));
    $('#totalTraffic').text(formatBytes(totalTraffic));
    $('#suspiciousIPs').text(formatNumber(suspiciousIPs));
    
    // Update protocol chart
    updateProtocolChart(data);
    
    // Update traffic chart
    updateTrafficChart(data);
}

/**
 * Update protocol distribution chart
 */
function updateProtocolChart(data) {
    // Destroy existing chart if it exists
    if (protocolChart) {
        protocolChart.destroy();
        protocolChart = null;
    }
    
    const protocolStats = data.Protocol_Statistics || {};
    
    if (Object.keys(protocolStats).length === 0) {
        $('#protocolChart').html('<p class="text-center text-muted">Нет данных для отображения</p>');
        return;
    }
    
    const chartData = Object.entries(protocolStats).map(([protocol, count]) => ({
        x: protocol.toUpperCase(),
        y: count
    }));
    
    const options = {
        series: chartData.map(item => item.y),
        chart: {
            type: 'donut',
            height: 300,
            fontFamily: 'Inter, sans-serif'
        },
        labels: chartData.map(item => item.x),
        colors: ['#4361ee', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#84cc16', '#f97316'],
        legend: {
            position: 'bottom',
            horizontalAlign: 'center',
            fontSize: '14px'
        },
        plotOptions: {
            pie: {
                donut: {
                    size: '60%',
                    labels: {
                        show: true,
                        name: {
                            show: true,
                            fontSize: '16px',
                            fontWeight: 600
                        },
                        value: {
                            show: true,
                            fontSize: '14px',
                            formatter: function(val) {
                                return formatNumber(val);
                            }
                        },
                        total: {
                            show: true,
                            showAlways: false,
                            label: 'Всего пакетов',
                            fontSize: '16px',
                            fontWeight: 600,
                            formatter: function(w) {
                                return formatNumber(w.globals.seriesTotals.reduce((a, b) => a + b, 0));
                            }
                        }
                    }
                }
            }
        },
        dataLabels: {
            enabled: true,
            formatter: function(val) {
                return Math.round(val) + '%';
            },
            style: {
                fontSize: '12px',
                fontWeight: 'bold'
            }
        },
        tooltip: {
            y: {
                formatter: function(val) {
                    return formatNumber(val) + ' пакетов';
                }
            }
        },
        responsive: [{
            breakpoint: 480,
            options: {
                chart: {
                    height: 250
                },
                legend: {
                    position: 'bottom'
                }
            }
        }]
    };
    
    protocolChart = new ApexCharts(document.querySelector('#protocolChart'), options);
    protocolChart.render();
}

/**
 * Update traffic distribution chart
 */
function updateTrafficChart(data) {
    // Destroy existing chart if it exists
    if (trafficChart) {
        trafficChart.destroy();
        trafficChart = null;
    }
    
    const ipDetails = data.IP_Details || {};
    
    // Get top 10 IPs by traffic
    const trafficData = Object.entries(ipDetails)
        .map(([ip, details]) => ({
            ip: ip,
            incoming: details.traffic.incoming_bytes || 0,
            outgoing: details.traffic.outgoing_bytes || 0,
            total: details.traffic.total_bytes || 0
        }))
        .sort((a, b) => b.total - a.total)
        .slice(0, 10);
    
    if (trafficData.length === 0) {
        $('#trafficChart').html('<p class="text-center text-muted">Нет данных для отображения</p>');
        return;
    }
    
    const options = {
        series: [
            {
                name: 'Входящий трафик',
                data: trafficData.map(item => item.incoming)
            },
            {
                name: 'Исходящий трафик',
                data: trafficData.map(item => item.outgoing)
            }
        ],
        chart: {
            type: 'bar',
            height: 300,
            fontFamily: 'Inter, sans-serif',
            stacked: true,
            toolbar: {
                show: true,
                tools: {
                    download: true,
                    selection: false,
                    zoom: false,
                    zoomin: false,
                    zoomout: false,
                    pan: false,
                    reset: false
                }
            }
        },
        xaxis: {
            categories: trafficData.map(item => item.ip),
            labels: {
                rotate: -45,
                style: {
                    fontSize: '12px'
                }
            }
        },
        yaxis: {
            labels: {
                formatter: function(val) {
                    return formatBytes(val);
                }
            }
        },
        colors: ['#10b981', '#4361ee'],
        legend: {
            position: 'top',
            horizontalAlign: 'center'
        },
        tooltip: {
            y: {
                formatter: function(val) {
                    return formatBytes(val);
                }
            }
        },
        plotOptions: {
            bar: {
                horizontal: false,
                columnWidth: '70%',
                dataLabels: {
                    position: 'top'
                }
            }
        },
        dataLabels: {
            enabled: false
        },
        responsive: [{
            breakpoint: 480,
            options: {
                chart: {
                    height: 250
                },
                xaxis: {
                    labels: {
                        rotate: -90
                    }
                }
            }
        }]
    };
    
    trafficChart = new ApexCharts(document.querySelector('#trafficChart'), options);
    trafficChart.render();
}

/**
 * Update network graph visualization
 */
function updateNetworkGraph(data) {
    if (!data) {
        console.warn('No data provided for network graph update');
        showGraphEmptyState();
        return;
    }

    if (!data.Network_Graph) {
        console.warn('No Network_Graph data found in analysis results');
        showGraphEmptyState();
        return;
    }

    if (!data.Network_Graph.nodes || !data.Network_Graph.edges) {
        console.warn('Network_Graph data is missing nodes or edges');
        showGraphEmptyState();
        return;
    }

    if (!cyGraph) {
        console.error('Network graph not initialized');
        return;
    }

    try {
        console.log('Processing network graph data...');

        const nodes = [];
        const nodeMap = new Map();

        data.Network_Graph.nodes.forEach((node, index) => {
            if (!node || !node.id) {
                console.warn(`Skipping invalid node at index ${index}:`, node);
                return;
            }

            const ipDetails = data.IP_Details?.[node.id] || {};
            const transformedNode = {
                id: node.id,
                asn: ipDetails.asn || 'Unknown',
                traffic: ipDetails.traffic?.total_bytes || 0,
                packets: ipDetails.traffic?.total_packets || 0,
                is_blacklisted: ipDetails.threat_info?.is_blacklisted || false,
                threat_level: ipDetails.threat_info?.threat_level || 'Безопасный',
                label: node.id
            };

            nodes.push(transformedNode);
            nodeMap.set(node.id, transformedNode);
        });

        const links = [];
        data.Network_Graph.edges.forEach((edge, index) => {
            if (!edge || !edge.from || !edge.to) {
                console.warn(`Skipping invalid edge at index ${index}:`, edge);
                return;
            }
            if (!nodeMap.has(edge.from) || !nodeMap.has(edge.to)) {
                console.warn(`Skipping edge with non-existent nodes: ${edge.from} -> ${edge.to}`);
                return;
            }
            links.push({
                from: edge.from,
                to: edge.to,
                value: edge.value || 1
            });
        });

        if (nodes.length === 0) {
            showGraphEmptyState();
            return;
        }

        graphData = { nodes, links };

        const elements = [];
        nodes.forEach(node => {
            elements.push({
                data: {
                    id: node.id,
                    label: node.label,
                    asn: node.asn,
                    traffic: node.traffic,
                    packets: node.packets,
                    isBlacklisted: node.is_blacklisted,
                    threatLevel: node.threat_level
                }
            });
        });

        const edgeIdCounts = {};
        links.forEach(edge => {
            const baseId = `${edge.from}-${edge.to}`;
            edgeIdCounts[baseId] = (edgeIdCounts[baseId] || 0) + 1;
            elements.push({
                data: {
                    id: `${baseId}-${edgeIdCounts[baseId]}`,
                    source: edge.from,
                    target: edge.to,
                    weight: edge.value
                }
            });
        });

        hideGraphEmptyState();
        cyGraph.startBatch();
        cyGraph.elements().remove();
        cyGraph.add(elements);
        cyGraph.endBatch();
        applyGraphStyles();
        resetGraphHighlights();

        currentLayout = cyGraph.layout({
            name: 'fcose',
            animate: true,
            randomize: true,
            idealEdgeLength: 120,
            nodeSeparation: 100,
            gravity: 0.9,
            nodeRepulsion: 4500
        });
        currentLayout.run();

        setTimeout(() => {
            cyGraph.fit(cyGraph.elements(), 80);
        }, 600);

        updateGraphStatistics(nodes, links);
        console.log(`Network graph updated successfully: ${nodes.length} nodes, ${links.length} edges`);

    } catch (error) {
        console.error('Error updating network graph:', error);
        showGraphErrorState('Ошибка при загрузке графа сетевых соединений');
    }
}

/**
 * Update graph statistics display
 */
function updateGraphStatistics(nodes, links) {
    const statsContainer = document.getElementById('graphStats');
    if (!statsContainer) return;

    const totalNodes = nodes.length;
    const totalLinks = links.length;
    const blacklistedNodes = nodes.filter(n => n.is_blacklisted).length;
    const isolatedNodes = nodes.filter(n => {
        return !links.some(l => l.from === n.id || l.to === n.id);
    }).length;

    statsContainer.innerHTML = `
        <small class="text-muted">
            <i class="fas fa-circle-nodes me-1"></i>${totalNodes} узлов
            <i class="fas fa-link ms-3 me-1"></i>${totalLinks} соединений
            ${blacklistedNodes > 0 ? `<i class="fas fa-shield-virus ms-3 me-1 text-danger"></i>${blacklistedNodes} подозрительных` : ''}
            ${isolatedNodes > 0 ? `<i class="fas fa-ban ms-3 me-1 text-warning"></i>${isolatedNodes} изолированных` : ''}
        </small>
    `;

    const nodesChip = document.getElementById('graphStatsNodes');
    const linksChip = document.getElementById('graphStatsLinks');
    const suspiciousChip = document.getElementById('graphStatsSuspicious');
    if (nodesChip) nodesChip.textContent = totalNodes;
    if (linksChip) linksChip.textContent = totalLinks;
    if (suspiciousChip) suspiciousChip.textContent = blacklistedNodes;
}

/**
 * Show error state for network graph
 */
function showGraphErrorState(message) {
    const container = document.getElementById('networkGraph');
    if (!container) return;

    const existingEmpty = container.querySelector('.graph-empty-state');
    if (existingEmpty) {
        existingEmpty.remove();
    }
    const existingError = container.querySelector('.graph-error-state');
    if (existingError) {
        existingError.remove();
    }

    const errorState = document.createElement('div');
    errorState.className = 'graph-error-state';
    errorState.innerHTML = `
        <div class="error-state-content">
            <i class="fas fa-exclamation-triangle fa-4x text-danger mb-3"></i>
            <h4 class="text-danger">Ошибка графа</h4>
            <p class="text-muted">${message}</p>
            <button class="btn btn-outline-primary btn-sm" onclick="initNetworkGraph()">
                <i class="fas fa-redo me-1"></i>Переинициализировать
            </button>
        </div>
    `;

    container.appendChild(errorState);
}

/**
 * Update IP list in analysis section
 */
function updateIPList(data) {
    const ipDetails = data.IP_Details || {};
    const ipList = $('#ipList');
    
    ipList.empty();
    
    const sortedIPs = Object.entries(ipDetails)
        .sort(([a], [b]) => {
            const aOctets = a.split('.').map(Number);
            const bOctets = b.split('.').map(Number);
            for (let i = 0; i < 4; i++) {
                if (aOctets[i] !== bOctets[i]) {
                    return aOctets[i] - bOctets[i];
                }
            }
            return 0;
        });
    
    sortedIPs.forEach(([ip, details]) => {
        const isBlacklisted = details.threat_info.is_blacklisted;
        const threatLevel = details.threat_info.threat_level || 'Безопасный';
        const firstDnsQuery = getFirstDnsQuery(details);
        const dnsName = getDnsNodeName(details);
        const searchBlob = buildIpSearchBlob(ip, details, dnsName, firstDnsQuery);
        const normalizedDnsName = (dnsName || '').trim().toLowerCase();
        const normalizedHintDomain = (firstDnsQuery?.domain || '').trim().toLowerCase();
        const shouldShowDnsHint = firstDnsQuery && (!normalizedDnsName || normalizedDnsName !== normalizedHintDomain);
        const dnsHint = shouldShowDnsHint ? `DNS: ${firstDnsQuery.domain} (${firstDnsQuery.type})` : '';
        const metaParts = [details.asn];
        if (dnsHint) {
            metaParts.push(`<span class="dns-hint">${dnsHint}</span>`);
        }
        
        const badges = [];
        if (isBlacklisted) {
            badges.push(`<span class="badge bg-danger">${threatLevel}</span>`);
        }
        const dnsQueriesCount = getDnsQueriesForHost(ip).length;
        const dnsResponsesCount = (details.dns.responses || []).length;
        if (dnsResponsesCount > 0 && dnsResponsesCount >= dnsQueriesCount) {
            badges.push(`<span class="badge bg-dark">DNS сервер</span>`);
        }
        if (details.http.domains.length > 0) {
            badges.push(`<span class="badge bg-success">HTTP</span>`);
        }
        if (details.tls.sni_records.length > 0) {
            badges.push(`<span class="badge bg-warning">TLS</span>`);
        }
        
        const ipItem = $(`
            <div class="ip-item" data-ip="${ip}" data-search="${searchBlob}">
                <div class="ip-info">
                    <div class="ip-address">${ip}</div>
                    ${dnsName ? `<div class="ip-host-name">${dnsName}</div>` : ''}
                    <div class="ip-meta">${metaParts.join(' • ')}</div>
                </div>
                <div class="ip-badges">
                    ${badges.join('')}
                </div>
            </div>
        `);
        
        ipList.append(ipItem);
    });
    
    // Apply current filter
    filterIPList();
}

/**
 * Filter IP list based on search
 */
function filterIPList() {
    $('.ip-item').each(function() {
        const ip = $(this).data('ip');
        const searchBlob = String($(this).data('search') || '').toLowerCase();
        const visible = !currentFilter || ip.toLowerCase().includes(currentFilter) || searchBlob.includes(currentFilter);
        $(this).toggle(visible);
    });
}

function buildIpSearchBlob(ip, details, dnsName, firstDnsQuery) {
    const tokens = [ip];

    if (details?.asn) {
        tokens.push(String(details.asn));
    }
    if (dnsName) {
        tokens.push(String(dnsName));
    }
    if (firstDnsQuery?.domain) {
        tokens.push(String(firstDnsQuery.domain));
    }

    const associations = details?.dns?.associations || [];
    associations.forEach((domain) => {
        if (domain) tokens.push(String(domain));
    });

    const dnsResponses = details?.dns?.responses || [];
    dnsResponses.slice(0, 20).forEach((response) => {
        if (response?.name) tokens.push(String(response.name));
        if (response?.resolution) tokens.push(String(response.resolution));
    });

    const httpDomains = details?.http?.domains || [];
    httpDomains.forEach((domain) => {
        if (domain) tokens.push(String(domain));
    });

    return tokens
        .join(' ')
        .toLowerCase()
        .replace(/\s+/g, ' ')
        .trim();
}

/**
 * Select IP in the list
 */
function selectIP(ip) {
    $('.ip-item').removeClass('active');
    $(`.ip-item[data-ip="${ip}"]`).addClass('active');
    selectedNode = ip;
    
    // Highlight in graph
    highlightNodeConnections(ip);
}

/**
 * Show detailed IP information
 */
function showIPDetails(ip, details) {
    $('#ipDetailsTitle').html(`<i class="fas fa-info-circle me-2"></i>Детальная информация: ${ip}`);
    
    const detailsHtml = generateIPDetailsHTML(ip, details);
    $('#ipDetailsBody').html(detailsHtml);
}

/**
 * Generate HTML for IP details
 */
function generateIPDetailsHTML(ip, details) {
    const threatInfo = details.threat_info || {};
    const traffic = details.traffic || {};
    const dns = details.dns || {};
    const http = details.http || {};
    const tls = details.tls || {};
    const connections = details.connections || {};
    const dnsNodeName = getDnsNodeName(details);
    const firstDnsQuery = getFirstDnsQuery(details);
    const dnsQueriesList = generateDnsQueryList(ip);
    
    const incomingBytes = traffic.incoming_bytes || 0;
    const outgoingBytes = traffic.outgoing_bytes || 0;
    const totalBytes = traffic.total_bytes || incomingBytes + outgoingBytes;
    
    let html = '<div class="ip-details-container">';
    
    html += `
        <div class="ip-detail-section">
            <div class="section-header">
                <h5 class="section-title"><i class="fas fa-info-circle me-2"></i>Основная информация</h5>
            </div>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">IP адрес</div>
                    <div class="d-flex align-items-center justify-content-between gap-2">
                        <div class="info-value monospace mb-0">${ip}</div>
                        <button class="copy-btn copy-ip-btn" data-ip="${ip}" title="Скопировать IP">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">ASN</div>
                    <div class="info-value">${details.asn}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Хост</div>
                    <div class="info-value">${dnsNodeName || 'Нет данных'}</div>
                </div>
            </div>
        </div>
    `;
    
    if (threatInfo.is_blacklisted) {
        html += `
            <div class="ip-detail-section">
                <div class="section-header">
                    <h5 class="section-title"><i class="fas fa-shield-virus me-2"></i>Информация об угрозе</h5>
                </div>
                <div class="alert alert-danger">
                    <strong>⚠️ Подозрительный IP адрес!</strong><br>
                    Уровень угрозы: <strong>${threatInfo.threat_level}</strong><br>
                    Счётчик угрозы: <strong>${threatInfo.threat_score}</strong>
                </div>
            </div>
        `;
    }
    
    html += `
        <div class="ip-detail-section">
            <div class="section-header">
                <h5 class="section-title"><i class="fas fa-chart-line me-2"></i>Статистика трафика</h5>
            </div>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Входящие байты</div>
                    <div class="info-value">${formatBytes(incomingBytes)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Исходящие байты</div>
                    <div class="info-value">${formatBytes(outgoingBytes)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Входящие пакеты</div>
                    <div class="info-value">${formatNumber(traffic.incoming_packets || 0)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Исходящие пакеты</div>
                    <div class="info-value">${formatNumber(traffic.outgoing_packets || 0)}</div>
                </div>
            </div>
        </div>
    `;
    
    if ((connections.outgoing && connections.outgoing.length > 0) || (connections.incoming && connections.incoming.length > 0)) {
        html += `
            <div class="ip-detail-section">
                <div class="section-header">
                    <h5 class="section-title"><i class="fas fa-network-wired me-2"></i>Соединения</h5>
                </div>
        `;
        if (connections.outgoing && connections.outgoing.length > 0) {
            html += `
                <h6><i class="fas fa-arrow-right me-2"></i>Исходящие (${connections.outgoing.length})</h6>
                ${generateConnectionList(connections.outgoing, 'outgoing')}
            `;
        }
        if (connections.incoming && connections.incoming.length > 0) {
            html += `
                <h6 class="mt-3"><i class="fas fa-arrow-left me-2"></i>Входящие (${connections.incoming.length})</h6>
                ${generateConnectionList(connections.incoming, 'incoming')}
            `;
        }
        html += '</div>';
    }
    
    const hostDnsQueries = getDnsQueriesForHost(ip);
    if ((dns.associations && dns.associations.length > 0) || (dns.responses && dns.responses.length > 0) || hostDnsQueries.length > 0) {
        html += `
            <div class="ip-detail-section">
                <div class="section-header">
                    <h5 class="section-title"><i class="fas fa-globe me-2"></i>DNS информация</h5>
                </div>
        `;
        if (dns.associations && dns.associations.length > 0) {
            html += `
                <h6>DNS ассоциации</h6>
                <div class="mb-3">
                    ${generateExpandableList(dns.associations, 6, 'badge bg-info me-1 mb-1')}
                </div>
            `;
        }
        const isDnsServer = dns.responses && dns.responses.length > 0;
        if (!isDnsServer && firstDnsQuery) {
            html += `
                <div class="mb-3">
                    <small class="text-muted d-block">Первый DNS запрос</small>
                    <div class="fw-bold">${firstDnsQuery.domain} (${firstDnsQuery.type})</div>
                    ${firstDnsQuery.server ? `<div class="small text-muted">DNS сервер: <button class="connection-link ms-1" data-ip-target="${firstDnsQuery.server}"><i class="fas fa-server me-1"></i>${firstDnsQuery.server}</button></div>` : ''}
                </div>
            `;
        }
        if (!isDnsServer && dnsQueriesList) {
            html += `
                <h6>DNS запросы</h6>
                ${dnsQueriesList}
            `;
        }
        if (dns.responses && dns.responses.length > 0) {
            html += `
                <h6>DNS ответы сервера</h6>
                ${generateDNSResponseTable(dns.responses)}
            `;
        }
        html += '</div>';
    }
    
    if ((http.domains && http.domains.length > 0) || (http.requests && http.requests.length > 0) || (http.responses && http.responses.length > 0)) {
        html += `
            <div class="ip-detail-section">
                <div class="section-header">
                    <h5 class="section-title"><i class="fas fa-globe me-2"></i>HTTP информация</h5>
                </div>
                ${generateHttpSection(http, ip)}
            </div>
        `;
    }
    
    const hasTlsInfo = tls.sni_records && tls.sni_records.length > 0;
    if (hasTlsInfo) {
        html += `
            <div class="ip-detail-section">
                <div class="section-header">
                    <h5 class="section-title"><i class="fas fa-lock me-2"></i>TLS информация</h5>
                </div>
        `;
        if (tls.sni_records && tls.sni_records.length > 0) {
            html += `
                <h6>SNI записи</h6>
                <div class="mb-3">
                    ${generateExpandableList(tls.sni_records, 6, 'badge bg-warning me-1 mb-1')}
                </div>
            `;
        }
        html += '</div>';
    }
    
    html += '</div>';
    return html;
}


/**
 * Show node details in selection info panel
 */
function showNodeDetails(nodeId) {
    if (!networkData || !networkData.IP_Details || !networkData.IP_Details[nodeId]) {
        return;
    }
    
    const details = networkData.IP_Details[nodeId];
    const threatInfo = details.threat_info;
    
    let html = `
        <h6 class="mb-3"><i class="fas fa-desktop me-2"></i>${nodeId}</h6>
        <div class="mb-2">
            <small class="text-muted">ASN:</small><br>
            <span class="fw-bold">${details.asn}</span>
        </div>
        <div class="mb-2">
            <small class="text-muted">Трафик:</small><br>
            <span class="fw-bold">${formatBytes(details.traffic.total_bytes)}</span>
        </div>
        <div class="mb-2">
            <small class="text-muted">Пакеты:</small><br>
            <span class="fw-bold">${formatNumber(details.traffic.total_packets)}</span>
        </div>
    `;
    
    if (threatInfo.is_blacklisted) {
        html += `
            <div class="mb-2">
                <span class="badge bg-danger">${threatInfo.threat_level}</span>
            </div>
        `;
    }
    
    html += `
        <button class="btn btn-sm btn-primary w-100 mt-2" onclick="selectIP('${nodeId}'); showIPDetails('${nodeId}', networkData.IP_Details['${nodeId}']); $('html, body').animate({scrollTop: $('#analysis-section').offset().top}, 500);">
            <i class="fas fa-info-circle me-1"></i>Подробнее
        </button>
    `;
    
    $('#selectionInfoBody').html(html);
    $('#selectionInfo').show().addClass('show');
}

/**
 * Show edge details in selection info panel
 */
function showEdgeDetails(edgeInfo) {
    if (!edgeInfo) return;
    
    const fromIP = edgeInfo.from || edgeInfo.source;
    const toIP = edgeInfo.to || edgeInfo.target;
    const weight = edgeInfo.value || edgeInfo.weight || 1;
    
    let html = `
        <h6 class="mb-3"><i class="fas fa-link me-2"></i>Соединение</h6>
        <div class="mb-2">
            <small class="text-muted">Источник:</small><br>
            <code>${fromIP}</code>
        </div>
        <div class="mb-2">
            <small class="text-muted">Назначение:</small><br>
            <code>${toIP}</code>
        </div>
        <div class="mb-2">
            <small class="text-muted">Интенсивность:</small><br>
            <span class="fw-bold">${formatBytes(weight * 1024)}</span>
        </div>
        <div class="btn-group w-100 mt-2">
            <button class="btn btn-sm btn-outline-primary" onclick="jumpToIP('${fromIP}')">
                <i class="fas fa-circle-arrow-left me-1"></i>Источник
            </button>
            <button class="btn btn-sm btn-outline-primary" onclick="jumpToIP('${toIP}')">
                <i class="fas fa-circle-arrow-right me-1"></i>Назначение
            </button>
        </div>
    `;
    
    $('#selectionInfoBody').html(html);
    $('#selectionInfo').show().addClass('show');
}

/**
 * Hide selection info panel
 */
function hideSelectionInfo() {
    $('#selectionInfo').removeClass('show').hide();
}

/**
 * Highlight node connections in graph
 */
function highlightNodeConnections(nodeId) {
    if (!cyGraph) return;
    cyGraph.nodes().removeClass('highlight neighbor');
    cyGraph.edges().removeClass('highlight');
    
    const node = cyGraph.getElementById(nodeId);
    if (!node || node.empty()) return;
    
    node.addClass('highlight');
    const connectedNodes = node.connectedEdges().connectedNodes();
    connectedNodes.addClass('neighbor');
    node.connectedEdges().addClass('highlight');
}

/**
 * Reset graph highlights
 */
function resetGraphHighlights() {
    if (!cyGraph) return;
    cyGraph.nodes().removeClass('highlight neighbor');
    cyGraph.edges().removeClass('highlight');
}

/**
 * Filter network graph based on selected filters
 */
function filterNetworkGraph() {
    if (!cyGraph) return;
    
    const showBlacklistedOnly = $('#showBlacklistedOnly').is(':checked');
    const hideIsolatedNodes = $('#hideIsolatedNodes').is(':checked');
    
    cyGraph.batch(() => {
        cyGraph.nodes().forEach(node => {
            let visible = true;
            if (showBlacklistedOnly && !node.data('isBlacklisted')) {
                visible = false;
            }
            if (visible && hideIsolatedNodes && node.degree() === 0) {
                visible = false;
            }
            node.toggleClass('hidden', !visible);
        });
        
        cyGraph.edges().forEach(edge => {
            const srcHidden = edge.source().hasClass('hidden');
            const tgtHidden = edge.target().hasClass('hidden');
            edge.toggleClass('hidden', srcHidden || tgtHidden);
        });
    });
    
    const visibleElements = cyGraph.elements(':visible');
    if (visibleElements.length > 0) {
        cyGraph.fit(visibleElements, 80);
    }
}

/**
 * Export network as PNG
 */
function exportNetworkAsPNG() {
    if (!cyGraph) return;
    
    try {
        const pngData = cyGraph.png({ full: true, scale: 2 });
        const link = document.createElement('a');
        link.href = pngData;
        link.download = 'network-graph.png';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } catch (error) {
        console.error('Error exporting graph:', error);
    }
}

/**
 * Toggle dark mode
 */
function toggleDarkMode() {
    // This would implement dark mode toggle
    console.log('Dark mode toggle clicked');
}

/**
 * Show loading indicator
 */
function showLoading() {
    $('#loadingIndicator').removeClass('d-none');
    $('#errorAlert').addClass('d-none');
}

/**
 * Hide loading indicator
 */
function hideLoading() {
    $('#loadingIndicator').addClass('d-none');
}

/**
 * Show error message
 */
function showError(message) {
    $('#errorMessage').text(message);
    $('#errorAlert').removeClass('d-none');
}

/**
 * Utility functions
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatNumber(num) {
    if (num === 0) return '0';
    
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    
    return num.toString();
}

function computeLinkWidth(link) {
    if (!link || !link.value) {
        return 1 * edgeThicknessMultiplier;
    }
    const base = Math.max(1, Math.min(8, Math.log10(link.value + 1) + 1));
    return base * edgeThicknessMultiplier;
}

function applyGraphStyles() {
    if (!cyGraph) return;
    cyGraph.style(getCytoscapeStyles());
}

function focusGraphNode(target) {
    const nodeId = target?.trim();
    if (!nodeId) {
        showCopyToast('Введите IP для поиска');
        return;
    }

    if (!networkData || !networkData.IP_Details || !networkData.IP_Details[nodeId]) {
        showCopyToast('Узел не найден');
        return;
    }

    selectIP(nodeId);
    showIPDetails(nodeId, networkData.IP_Details[nodeId]);
    highlightNodeConnections(nodeId);

    if (cyGraph) {
        const node = cyGraph.getElementById(nodeId);
        if (node && node.isNode()) {
            cyGraph.animate({
                center: { eles: node },
                zoom: 1.6
            }, { duration: 400 });
        }
    }

    const analysisSection = $('#analysis-section');
    if (analysisSection.length) {
        $('html, body').animate({ scrollTop: analysisSection.offset().top }, 400);
    }
}

/**
 * Generate expandable list HTML
 */
function generateExpandableList(items, maxItems = 5, className = 'badge bg-secondary', type = 'badge') {
    if (!items || items.length === 0) {
        return '<span class="text-muted">Нет данных</span>';
    }
    
    const uniqueId = 'list_' + Math.random().toString(36).substr(2, 9);
    
    let html = '';
    if (type === 'badge') {
        const visibleItems = items.slice(0, maxItems);
        const hiddenItems = items.slice(maxItems);
        
        html += `<div class="expandable-list-container">`;
        html += `<div class="expandable-list ${hiddenItems.length === 0 ? 'expanded' : ''}" id="${uniqueId}">`;
        
        // Показываем первые элементы
        visibleItems.forEach(item => {
            html += `<span class="${className} me-1 mb-1">${item}</span>`;
        });
        
        // Скрытые элементы
        if (hiddenItems.length > 0) {
            hiddenItems.forEach(item => {
                html += `<span class="${className} me-1 mb-1 hidden-item" style="display: none;">${item}</span>`;
            });
        }
        
        html += `</div>`;
        
        // Кнопка показать/скрыть
        if (hiddenItems.length > 0) {
            html += `<div class="expand-toggle" data-target="${uniqueId}">`;
            html += `<span class="show-text">Показать ещё ${hiddenItems.length} <i class="fas fa-chevron-down"></i></span>`;
            html += `<span class="hide-text" style="display: none;">Скрыть <i class="fas fa-chevron-up"></i></span>`;
            html += `</div>`;
        }
        
        html += `</div>`;
    }
    
    return html;
}

/**
 * Generate DNS response table with proper chain visualization
 */
function generateDNSResponseTable(responses) {
    if (!responses || responses.length === 0) {
        return '<span class="text-muted">Нет данных</span>';
    }

    // Sort responses by timestamp to show chronological order
    const sortedResponses = [...responses].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));

    // Group into resolution chains
    const resolutionChains = buildDNSResolutionChains(sortedResponses);

    let html = '<div class="dns-response-chains">';

    resolutionChains.forEach((chain, chainIndex) => {
        const firstDomain = chain.steps[0] ? chain.steps[0].name : 'DNS';
        html += `
            <div class="dns-chain-group mb-3 dns-chain-collapsed">
                <div class="dns-chain-header" role="button" tabindex="0">
                    <i class="dns-chain-chevron fas fa-chevron-right me-2"></i>
                    <strong class="dns-chain-title">${firstDomain}</strong>
                </div>
                <div class="dns-chain-steps">
        `;

        chain.steps.forEach((step, stepIndex) => {
            const isLastStep = stepIndex === chain.steps.length - 1;
            const stepClass = isLastStep ? 'dns-step-final' : 'dns-step-middle';

            html += `
                <div class="dns-step ${stepClass}">
                    <div class="dns-step-connector">
                        <div class="dns-step-number">${stepIndex + 1}</div>
                    </div>
                    <div class="dns-step-content">
                        <div class="dns-step-info">
                            <div class="dns-step-domain">
                                <i class="fas fa-globe me-2"></i>
                                <strong>${step.name}</strong>
                            </div>
                            <div class="dns-step-meta">
                                <span class="badge ${getDNSBadgeClass(step.type)}">${step.type}</span>
                                ${step.timestamp ? `<small class="text-muted ms-2">${formatTimestamp(step.timestamp)}</small>` : ''}
                            </div>
                        </div>
                        <div class="dns-step-resolution">
                            <i class="fas fa-arrow-right me-2 text-primary"></i>
                            ${formatResolutionWithLinks(step.resolution)}
                            ${step.ttl ? `<small class="text-muted ms-2">TTL: ${step.ttl}</small>` : ''}
                        </div>
                    </div>
                </div>
            `;
        });

        html += `
                </div>
            </div>
        `;
    });

    // If no chains were built, show simple grouped view
    if (resolutionChains.length === 0) {
        html += '<div class="alert alert-info">Не удалось построить цепочки разрешения. Показан простой список.</div>';
        html += generateSimpleDNSList(sortedResponses);
    }

    html += '</div>';
    return html;
}

/**
 * Build DNS resolution chains from responses
 */
function buildDNSResolutionChains(responses) {
    const chains = [];
    const processed = new Set();
    const cnameMap = new Map(); // domain -> {target, response}
    const aRecordsMap = new Map(); // domain -> [responses]

    // First pass: build maps of CNAME and A/AAAA records
    responses.forEach(response => {
        if (response.type === 'CNAME' && response.resolution) {
            const target = response.resolution.replace(/\.$/, ''); // Remove trailing dot
            cnameMap.set(response.name, { target, response });
        } else if ((response.type === 'A' || response.type === 'AAAA') && response.resolution) {
            if (!aRecordsMap.has(response.name)) {
                aRecordsMap.set(response.name, []);
            }
            aRecordsMap.get(response.name).push(response);
        }
    });

    // Find all domains that are CNAME targets (these should not start chains)
    const cnameTargets = new Set();
    cnameMap.forEach(({ target }) => cnameTargets.add(target));

    // Find domains that are not CNAME targets (these start chains)
    const startingDomains = new Set();
    responses.forEach(response => {
        if (!cnameTargets.has(response.name)) {
            startingDomains.add(response.name);
        }
    });

    // Build chains for each starting domain
    startingDomains.forEach(domain => {
        if (processed.has(domain)) return;

        const chain = buildResolutionChain(domain, cnameMap, aRecordsMap, processed);
        if (chain.steps.length > 0) {
            chains.push(chain);
        }
    });

    return chains;
}

/**
 * Build a single resolution chain starting from a domain
 */
function buildResolutionChain(startDomain, cnameMap, aRecordsMap, processed) {
    const chain = { steps: [] };
    let currentDomain = startDomain;

    // Mark as processed to avoid duplicates
    processed.add(currentDomain);

    // Follow CNAME chain until we reach a domain with A/AAAA records
    while (cnameMap.has(currentDomain)) {
        const cnameData = cnameMap.get(currentDomain);
        if (cnameData) {
            chain.steps.push(formatDNSResponse(cnameData.response));
            currentDomain = cnameData.target;
            processed.add(currentDomain);
        } else {
            break;
        }
    }

    // Add A/AAAA records for the final domain in the CNAME chain
    if (aRecordsMap.has(currentDomain)) {
        const aRecords = aRecordsMap.get(currentDomain);
        aRecords.forEach(record => {
            chain.steps.push(formatDNSResponse(record));
        });
    }

    return chain;
}

/**
 * Format DNS response for chain display
 */
function formatDNSResponse(response) {
    return {
        name: response.name || 'Unknown',
        type: response.type || 'Unknown',
        resolution: response.resolution || 'N/A',
        ttl: response.ttl || 'N/A',
        timestamp: response.timestamp
    };
}

/**
 * Generate simple DNS list when chain building fails
 */
function generateSimpleDNSList(responses) {
    let html = '<div class="dns-simple-list">';

    responses.forEach(response => {
        html += `
            <div class="dns-simple-item">
                <div class="dns-simple-header">
                    <code class="dns-simple-domain">${response.name}</code>
                    <span class="badge ${getDNSBadgeClass(response.type)} ms-2">${response.type}</span>
                </div>
                <div class="dns-simple-resolution">
                    <i class="fas fa-arrow-right me-2 text-muted"></i>
                    ${formatResolutionWithLinks(response.resolution)}
                    ${response.ttl ? `<small class="text-muted ms-2">TTL: ${response.ttl}</small>` : ''}
                </div>
            </div>
        `;
    });

    html += '</div>';
    return html;
}

/**
 * Get appropriate badge class for DNS record type
 */
function getDNSBadgeClass(type) {
    const typeClasses = {
        'A': 'bg-success',
        'AAAA': 'bg-primary',
        'CNAME': 'bg-warning',
        'MX': 'bg-info',
        'TXT': 'bg-secondary',
        'SRV': 'bg-dark',
        'PTR': 'bg-light text-dark',
        'NS': 'bg-danger',
        'SOA': 'bg-info'
    };
    return typeClasses[type] || 'bg-secondary';
}

/**
 * Toggle DNS domain group visibility
 */
function toggleDNSGroup(headerElement) {
    const content = headerElement.nextElementSibling;
    const icon = headerElement.querySelector('.dns-toggle-icon');

    if (content.style.display === 'none') {
        content.style.display = 'block';
        icon.classList.remove('fa-chevron-right');
        icon.classList.add('fa-chevron-down');
    } else {
        content.style.display = 'none';
        icon.classList.remove('fa-chevron-down');
        icon.classList.add('fa-chevron-right');
    }
}

/**
 * Format resolution string with anchor links for IPs that exist as nodes
 */
function formatResolutionWithLinks(resolution) {
    if (!resolution || resolution === 'N/A') return resolution;
    const knownIps = networkData?.IP_Details ? Object.keys(networkData.IP_Details) : [];
    const ipv4Regex = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g;
    const result = resolution.replace(ipv4Regex, (match) => {
        const trimmed = match.trim();
        if (knownIps.includes(trimmed)) {
            return `<button class="connection-link connection-link--active btn btn-link p-0 align-baseline text-decoration-none" data-ip-target="${trimmed}" title="Перейти к ${trimmed}"><code class="dns-resolution-code">${trimmed}</code></button>`;
        }
        return `<code class="dns-resolution-code">${trimmed}</code>`;
    });
    return result === resolution ? `<code class="dns-resolution-code">${resolution}</code>` : result;
}

/**
 * Format timestamp for display
 */
function formatTimestamp(timestamp) {
    if (!timestamp) return '';
    try {
        const date = new Date(timestamp * 1000);
        return date.toLocaleTimeString();
    } catch (e) {
        return timestamp;
    }
}

/**
 * Generate expandable table HTML
 */
function generateExpandableTable(items, maxItems = 5, headers, rowGenerator) {
    if (!items || items.length === 0) {
        return '<span class="text-muted">Нет данных</span>';
    }
    
    const uniqueId = 'table_' + Math.random().toString(36).substr(2, 9);
    const visibleItems = items.slice(0, maxItems);
    const hiddenItems = items.slice(maxItems);
    
    let html = '<table class="table table-sm detail-table mb-3">';
    html += '<thead><tr>';
    headers.forEach(header => {
        html += `<th>${header}</th>`;
    });
    html += '</tr></thead>';
    
    html += '<tbody>';
    
    // Видимые строки
    visibleItems.forEach(item => {
        html += rowGenerator(item);
    });
    
    // Скрытые строки
    if (hiddenItems.length > 0) {
        hiddenItems.forEach(item => {
            html += `<tr class="expandable-row hidden-row" data-parent="${uniqueId}" style="display: none;">`;
            const rowContent = rowGenerator(item);
            // Убираем теги <tr> и </tr> из сгенерированной строки
            const cleanRowContent = rowContent.replace(/<\/?tr[^>]*>/g, '');
            html += cleanRowContent;
            html += '</tr>';
        });
    }
    
    html += '</tbody></table>';
    
    // Кнопка показать/скрыть для таблицы
    if (hiddenItems.length > 0) {
        html += `<div class="expand-toggle" data-target="${uniqueId}" data-type="table">`;
        html += `<span class="show-text">Показать ещё ${hiddenItems.length} записей <i class="fas fa-chevron-down"></i></span>`;
        html += `<span class="hide-text" style="display: none;">Скрыть <i class="fas fa-chevron-up"></i></span>`;
        html += `</div>`;
    }
    
    return html;
}

/**
 * Generate interactive connection chips
 */
function generateConnectionList(items = [], direction = 'outgoing') {
    if (!items || items.length === 0) {
        return '<span class="text-muted">Нет данных</span>';
    }
    
    const uniqueItems = [...new Set(items)];
    const iconClass = direction === 'outgoing' ? 'fa-arrow-up-right-from-square' : 'fa-arrow-down-left';
    const knownIps = networkData?.IP_Details ? Object.keys(networkData.IP_Details) : [];
    
    return `
        <div class="connection-list mb-2">
            ${uniqueItems.map(target => {
                const isActive = knownIps.includes(target);
                const activeClass = isActive ? ' connection-link--active' : '';
                return `
                <button class="connection-link${activeClass}" data-ip-target="${target}" title="Перейти к ${target}">
                    <i class="fas ${iconClass}"></i>
                    <span class="monospace">${target}</span>
                </button>
            `}).join('')}
        </div>
    `;
}

/**
 * Render DNS query overview by server
 */
/**
 * Ссылка-якорь на узел с HTTP-запросами или ответами
 */
function httpPeerLink(items, label, currentIp) {
    if (!items || items.length === 0) return '';
    const peerIps = [...new Set(items.map(x => x.peer_ip).filter(Boolean))];
    if (peerIps.length === 0) return '';
    return peerIps.map(peerIp => `
        <button class="connection-link btn btn-sm btn-outline-secondary mt-1 me-1" data-ip-target="${peerIp}" title="Перейти к узлу ${peerIp}">
            <i class="fas fa-external-link-alt me-1"></i>${label} → ${peerIp}
        </button>
    `).join('');
}

/**
 * HTTP overview grouped by домен
 */
function generateHttpSection(http = {}, currentIp = '') {
    let content = '';
    
    const hostEntries = Object.entries(http.by_domain || {});
    const rawResponses = http.responses || [];
    if (hostEntries.length === 0) {
        if ((http.requests && http.requests.length > 0) || rawResponses.length > 0) {
            const fallbackHost = (http.domains && http.domains.length > 0) ? http.domains[0] : '';
            const reqLink = httpPeerLink(http.requests || [], 'Ответы на сервере', currentIp);
            const respLink = httpPeerLink(rawResponses, 'Запросы от клиента', currentIp);
            content += `
                <div class="http-host-block">
                    <div class="http-host-header">
                        <span class="http-host-name">${fallbackHost || 'HTTP'}</span>
                    </div>
                    ${generateHttpRequestTable(http.requests || [], fallbackHost)}
                    ${reqLink}
                    ${generateHttpResponseTable(rawResponses)}
                    ${respLink}
                </div>
            `;
            return content;
        }
        return content || '<span class="text-muted">Нет данных</span>';
    }
    
    let hasDomainResponses = false;
    content += hostEntries
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([host, payload]) => {
            const domainRequests = payload.requests || [];
            const domainResponses = payload.responses || [];
            if (domainResponses.length > 0) {
                hasDomainResponses = true;
            }
            const reqLink = httpPeerLink(domainRequests, 'Ответы на сервере', currentIp);
            const respLink = httpPeerLink(domainResponses, 'Запросы от клиента', currentIp);
            return `
            <div class="http-host-block">
                <div class="http-host-header">
                    <span class="http-host-name">${host}</span>
                </div>
                ${generateHttpRequestTable(domainRequests, host)}
                ${reqLink}
                ${generateHttpResponseTable(domainResponses)}
                ${respLink}
            </div>
        `;
        }).join('');
    
    if (!hasDomainResponses && rawResponses.length > 0) {
        const respLink = httpPeerLink(rawResponses, 'Запросы от клиента', currentIp);
        content += `
            <div class="http-host-block">
                <div class="http-host-header">
                    <span class="http-host-name">HTTP ответы узла</span>
                </div>
                ${generateHttpResponseTable(rawResponses)}
                ${respLink}
            </div>
        `;
    }
    
    return content || '<span class="text-muted">Нет данных</span>';
}

function generateHttpRequestTable(requests, hostHint = '') {
    if (!requests || requests.length === 0) {
        return '<div class="text-muted mb-2">Запросы отсутствуют</div>';
    }
    
    const seen = new Set();
    const uniqueRequests = requests.filter(req => {
        const key = `${req.method || 'GET'}|${req.uri || '/'}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
    
    const rows = uniqueRequests.slice(0, 20).map(req => {
        const fullUrl = buildFullUrl(req.host || hostHint, req.uri);
        const safeUrl = (fullUrl || '').replace(/"/g, '&quot;');
        const uri = req.uri || '/';
        return `
            <tr>
                <td class="align-middle"><span class="badge bg-primary">${req.method || 'GET'}</span></td>
                <td class="monospace align-middle text-break">${uri}</td>
                <td class="align-middle" style="min-width: 2.5rem;">
                    <button class="copy-btn copy-url-btn btn btn-sm btn-outline-primary" type="button" data-url="${safeUrl}" data-toast="Ссылка скопирована" title="Скопировать ссылку на ресурс">
                        <i class="fas fa-link me-1"></i>Ссылка
                    </button>
                </td>
            </tr>
        `;
    }).join('');
    
    const moreCount = uniqueRequests.length > 20 ? uniqueRequests.length - 20 : 0;
    
    return `
        <div class="table-responsive mb-2">
            <table class="table table-sm detail-table mb-0">
                <thead>
                    <tr>
                        <th style="width: 5rem;">Метод</th>
                        <th>Ресурс</th>
                        <th style="width: 6rem;">Полная ссылка</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
            ${moreCount > 0 ? `<div class="text-muted small mt-1">+ ещё ${moreCount} запросов</div>` : ''}
        </div>
    `;
}

function generateHttpResponseTable(responses) {
    if (!responses || responses.length === 0) {
        return '';
    }
    
    const rows = responses.slice(0, 12).map(resp => `
        <tr>
            <td><span class="badge bg-secondary">${resp.status_code || '-'}</span> ${resp.status_message || ''}</td>
            <td>${resp.content_type || '-'}</td>
            <td>${resp.content_length || '-'}</td>
            <td>${resp.server || '-'}</td>
        </tr>
    `).join('');
    
    return `
        <div class="table-responsive mb-2">
            <table class="table table-sm detail-table mb-0">
                <thead>
                    <tr>
                        <th>Статус</th>
                        <th>Тип контента</th>
                        <th>Размер</th>
                        <th>Сервер</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

/**
 * DNS query list with expandable overflow
 */
function generateDnsQueryList(ip, maxVisible = 8) {
    if (!ip) return '';
    const entries = getDnsQueriesForHost(ip).slice();
    
    if (entries.length === 0) {
        return '';
    }
    
    const uniqueId = 'dns_queries_' + Math.random().toString(36).substr(2, 9);
    const visibleEntries = entries.slice(0, maxVisible);
    const hiddenEntries = entries.slice(maxVisible);
    
    const renderEntry = (entry, extraClass = '', parentId = '', hidden = false) => `
        <div class="dns-query-card ${extraClass}" ${parentId ? `data-parent="${parentId}"` : ''} ${hidden ? 'style="display: none;"' : ''}>
            <span class="dns-query-type badge ${getDNSBadgeClass(entry.type)}">${entry.type}</span>
            <div class="dns-query-body">
                <div class="dns-query-domain">${entry.domain}</div>
                ${entry.serverIp ? `<div class="dns-query-meta text-muted">DNS сервер: <button class="connection-link ms-1" data-ip-target="${entry.serverIp}"><i class="fas fa-server me-1"></i>${entry.serverIp}</button></div>` : ''}
            </div>
        </div>
    `;
    
    let html = `<div class="dns-query-list" id="${uniqueId}">`;
    html += visibleEntries.map(entry => renderEntry(entry)).join('');
    hiddenEntries.forEach(entry => {
        html += renderEntry(entry, 'hidden-row', uniqueId, true);
    });
    html += '</div>';
    
    if (hiddenEntries.length > 0) {
        html += `
            <div class="expand-toggle" data-target="${uniqueId}" data-type="dns">
                <span class="show-text">Показать ещё ${hiddenEntries.length} запросов <i class="fas fa-chevron-down"></i></span>
                <span class="hide-text" style="display: none;">Скрыть <i class="fas fa-chevron-up"></i></span>
            </div>
        `;
    }
    
    return html;
}

/**
 * Helpers for DNS metadata
 */
function parseDnsQueryString(queryStr = '') {
    const match = queryStr.match(/^(.+?)\s*\(([^)]+)\)$/);
    if (match) {
        return {
            domain: match[1].trim(),
            type: match[2].trim()
        };
    }
    return { domain: queryStr, type: '' };
}

function getFirstDnsQuery(details) {
    if (!details || !details.dns) {
        return null;
    }
    if (details.dns.origin_query && details.dns.origin_query.domain) {
        return {
            server: details.dns.origin_query.server_ip || '',
            domain: details.dns.origin_query.domain,
            type: details.dns.origin_query.type || 'A'
        };
    }
    const clientQueries = getDnsQueriesForHost(details.ip || '');
    if (clientQueries.length > 0) {
        const sorted = clientQueries.slice().sort((a, b) => a.domain.localeCompare(b.domain));
        const first = sorted[0];
        return {
            server: first.serverIp || '',
            domain: first.domain,
            type: first.type || 'A'
        };
    }
    if (!details.dns.queries_by_server) {
        return null;
    }
    const entries = [];
    Object.entries(details.dns.queries_by_server).forEach(([serverIp, queries]) => {
        (queries || []).forEach(query => {
            const parsed = parseDnsQueryString(query);
            if (parsed.domain) {
                entries.push({
                    server: serverIp,
                    domain: parsed.domain,
                    type: parsed.type || 'A'
                });
            }
        });
    });
    if (entries.length === 0) {
        return null;
    }
    entries.sort((a, b) => a.domain.localeCompare(b.domain));
    return entries[0];
}

function getDnsNodeName(details) {
    if (!details || !details.dns) {
        return '';
    }
    if (details.dns.origin_query && details.dns.origin_query.domain) {
        return details.dns.origin_query.domain;
    }
    const primary = getPrimaryDnsResource(details);
    if (primary && (primary.name || primary.label)) {
        return primary.name || primary.label;
    }
    const firstQuery = getFirstDnsQuery(details);
    if (firstQuery) {
        return firstQuery.domain;
    }
    return '';
}

function getPrimaryDnsResource(details) {
    if (!details || !details.dns) return null;
    const responses = (details.dns.responses || []).slice().sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    if (responses.length > 0) {
        const record = responses[0];
        const labelTarget = record.resolution || record.name || '';
        return {
            label: `${labelTarget} (${record.type || 'UNKNOWN'})`,
            name: record.name || labelTarget,
            resolution: record.resolution || '',
            type: record.type || 'UNKNOWN'
        };
    }
    if ((details.dns.associations || []).length > 0) {
        const assoc = details.dns.associations[0];
        return {
            label: assoc,
            name: assoc
        };
    }
    const firstQuery = getFirstDnsQuery(details);
    if (firstQuery) {
        return {
            label: `${firstQuery.domain} (${firstQuery.type})`,
            name: firstQuery.domain,
            type: firstQuery.type
        };
    }
    return null;
}

function buildDnsClientLookup() {
    dnsClientQueriesMap = {};
    if (!networkData || !networkData.DNS_Queries) {
        return;
    }
    Object.values(networkData.DNS_Queries).forEach(entry => {
        if (!entry || !entry.domain || !entry.queries) return;
        (entry.queries || []).forEach(query => {
            if (!query || !query.client_ip) return;
            const clientIp = query.client_ip;
            const serverIp = query.server_ip || '';
            const type = query.type || entry.type || 'A';
            const key = `${entry.domain}|${type}|${serverIp}`;
            if (!dnsClientQueriesMap[clientIp]) {
                dnsClientQueriesMap[clientIp] = new Map();
            }
            if (!dnsClientQueriesMap[clientIp].has(key)) {
                dnsClientQueriesMap[clientIp].set(key, {
                    domain: entry.domain,
                    type,
                    serverIp
                });
            }
        });
    });
    Object.keys(dnsClientQueriesMap).forEach(clientIp => {
        dnsClientQueriesMap[clientIp] = Array.from(dnsClientQueriesMap[clientIp].values());
    });
}

function getDnsQueriesForHost(ip) {
    if (!ip) {
        return [];
    }
    const queries = dnsClientQueriesMap[ip];
    if (!queries) {
        return [];
    }
    return queries;
}

/**
 * Build URL for copy buttons
 */
function buildFullUrl(host = '', uri = '') {
    const cleanHost = (host || '').trim();
    const cleanUri = (uri || '').trim();
    if (/^https?:\/\//i.test(cleanUri)) {
        return cleanUri;
    }
    if (!cleanHost && !cleanUri) {
        return '';
    }
    const base = cleanHost ? `https://${cleanHost}` : '';
    if (!cleanUri || cleanUri === '/') {
        return base || cleanUri;
    }
    if (cleanUri.startsWith('/')) {
        return `${base}${cleanUri}`;
    }
    return base ? `${base}/${cleanUri}` : cleanUri;
}

/**
 * Clipboard helpers
 */
function copyTextToClipboard(text, successMessage = 'Скопировано') {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
            .then(() => showCopyToast(successMessage))
            .catch(() => fallbackCopy(text, successMessage));
    } else {
        fallbackCopy(text, successMessage);
    }
}

function fallbackCopy(text, successMessage) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    try {
        document.execCommand('copy');
        showCopyToast(successMessage);
    } catch (err) {
        console.error('Clipboard copy failed', err);
    }
    document.body.removeChild(textarea);
}

function showCopyToast(message) {
    if (!message) return;
    const toast = document.createElement('div');
    toast.className = 'copy-toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2000);
}

/**
 * Navigation helpers
 */
function jumpToIP(targetIp) {
    if (!targetIp || !networkData || !networkData.IP_Details || !networkData.IP_Details[targetIp]) {
        showCopyToast('Нет данных по IP');
        return;
    }
    selectIP(targetIp);
    showIPDetails(targetIp, networkData.IP_Details[targetIp]);
    highlightNodeConnections(targetIp);
    if (cyGraph) {
        const node = cyGraph.getElementById(targetIp);
        if (node && node.isNode()) {
            cyGraph.animate({
                center: { eles: node },
                zoom: 1.5
            }, { duration: 400 });
        }
    }
    const analysisSection = $('#analysis-section');
    if (analysisSection.length) {
        $('html, body').animate({ scrollTop: analysisSection.offset().top }, 500);
    }
}

/**
 * Initialize expandable lists handlers
 */
function initExpandableHandlers() {
    $(document).on('click', '.expand-toggle', function() {
        const target = $(this).data('target');
        const type = $(this).data('type');
        const showText = $(this).find('.show-text');
        const hideText = $(this).find('.hide-text');
        
        if (type === 'table') {
            // Обработка таблиц
            const hiddenRows = $(`.expandable-row[data-parent="${target}"]`);
            
            if (hiddenRows.first().is(':visible')) {
                // Скрываем
                hiddenRows.hide();
                showText.show();
                hideText.hide();
            } else {
                // Показываем
                hiddenRows.show();
                showText.hide();
                hideText.show();
            }
        } else if (type === 'dns') {
            const hiddenRows = $(`.dns-query-card.hidden-row[data-parent="${target}"]`);
            
            if (hiddenRows.first().is(':visible')) {
                // Скрываем
                hiddenRows.hide();
                showText.show();
                hideText.hide();
            } else {
                // Показываем
                hiddenRows.show();
                showText.hide();
                hideText.show();
            }
        } else {
            // Обработка списков badges
            const container = $(`#${target}`);
            const hiddenBadges = container.find('.hidden-item');
            
            if (hiddenBadges.first().is(':visible')) {
                // Сворачиваем
                hiddenBadges.hide();
                showText.show();
                hideText.hide();
            } else {
                // Разворачиваем
                hiddenBadges.show();
                showText.hide();
                hideText.show();
            }
        }
    });
} 
function getCytoscapeStyles() {
    return [
        {
            selector: 'node',
            style: {
                'background-color': ele => ele.data('isBlacklisted') ? '#ef4444' : '#10b981',
                'border-width': 2,
                'border-color': '#ffffff',
                'width': ele => calculateNodeSize(ele.data('packets')),
                'height': ele => calculateNodeSize(ele.data('packets')),
                'label': ele => showNodeLabels ? ele.data('label') : '',
                'font-size': 12,
                'text-valign': 'center',
                'text-halign': 'center',
                'color': '#ffffff',
                'text-outline-width': 2,
                'text-outline-color': ele => ele.data('isBlacklisted') ? '#ef4444' : '#10b981',
                'text-wrap': 'wrap',
                'text-max-width': 100,
                'opacity': 0.95,
                'transition-duration': '250ms',
                'transition-property': 'background-color, border-width, border-color, opacity, width, height'
            }
        },
        {
            selector: 'node.highlight',
            style: {
                'border-color': '#f97316',
                'border-width': 4,
                'background-color': '#f97316'
            }
        },
        {
            selector: 'node.neighbor',
            style: {
                'border-color': '#fb923c',
                'border-width': 3
            }
        },
        {
            selector: 'edge',
            style: {
                'width': ele => calculateEdgeWidth(ele.data('weight')),
                'line-color': ele => determineEdgeColor(ele.data('weight')),
                'target-arrow-color': ele => determineEdgeColor(ele.data('weight')),
                'curve-style': 'unbundled-bezier',
                'control-point-distances': 20,
                'control-point-weights': 0.5,
                'target-arrow-shape': 'triangle',
                'opacity': showTrafficParticles ? 0.95 : 0.75,
                'line-style': showTrafficParticles ? 'solid' : 'dashed'
            }
        },
        {
            selector: 'edge.highlight',
            style: {
                'line-color': '#f97316',
                'target-arrow-color': '#f97316',
                'width': ele => calculateEdgeWidth(ele.data('weight')) + 1
            }
        },
        {
            selector: '.hidden',
            style: {
                'display': 'none'
            }
        }
    ];
}

function calculateNodeSize(packets = 0) {
    if (!packets) return 30;
    return Math.max(24, Math.min(80, Math.log10(packets + 1) * 12 + 24));
}

function calculateEdgeWidth(weight = 1) {
    const base = Math.max(1, Math.log10(weight + 1) + 1);
    return base * edgeThicknessMultiplier;
}

function determineEdgeColor(weight = 1) {
    if (weight > 1000) return '#ef4444';
    if (weight > 100) return '#f59e0b';
    return '#94a3b8';
}
