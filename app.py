#!/usr/bin/env python3
import os
import json
import logging
import multiprocessing
import ipaddress
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file
from netparser import NetParser
from utils import compare_traffic, generate_simple_html_report
from collections import defaultdict

app = Flask(__name__)
LATEST_RESULT_PATH = os.path.join('static', 'data', 'latest_result.json')

# Setup logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filename='app.log',
                    filemode='a')
logger = logging.getLogger(__name__)

# Определяем оптимальное количество потоков
CPU_COUNT = multiprocessing.cpu_count()
DEFAULT_THREADS = max(1, min(CPU_COUNT - 1, 8))  # Оставляем как минимум 1 ядро для ОС и не более 8 потоков

def transform_data_for_frontend(raw_data):
    """
    Преобразует данные из формата NetParser в формат, ожидаемый frontend
    """
    logger.info("Starting data transformation")
    result = {
        'IP_Details': {},  # Объединенная информация по IP
        'DNS_Queries': {},
        'Protocol_Statistics': {},
        'Network_Graph': {
            'nodes': [],
            'edges': []
        },
        'Overall_Packet_Statistics': raw_data.get('Overall Packet Statistics', {})
    }
    
    # Построение карты соответствия IP -> исходный DNS запрос из цепочек разрешения
    resolution_origins = {}

    def extract_ips_from_resolution(resolution_value):
        """Возвращает список IP из строки разрешения DNS."""
        if not resolution_value:
            return []
        normalized = resolution_value.replace(';', ',')
        ips = []
        for token in normalized.split(','):
            candidate = token.strip()
            if not candidate:
                continue
            try:
                ipaddress.ip_address(candidate)
                ips.append(candidate)
            except ValueError:
                continue
        return ips
    for dns_ip, dns_data in raw_data.items():
        if dns_ip == 'Overall Packet Statistics':
            continue
        chains = dns_data.get('DNS Resolution Chains') or []
        for chain_entry in chains:
            chain_steps = chain_entry.get('chain') or []
            origin_name = chain_entry.get('domain') or (chain_steps[0] if chain_steps else '')
            if not origin_name:
                continue
            origin_name = origin_name.rstrip('.')
            resolved_ips = chain_entry.get('resolved_ips') or []
            timestamp = chain_entry.get('timestamp')
            for resolved_ip in resolved_ips:
                if not resolved_ip:
                    continue
                should_update = False
                existing = resolution_origins.get(resolved_ip)
                if existing is None:
                    should_update = True
                elif timestamp is not None:
                    existing_ts = existing.get('timestamp')
                    if existing_ts is None or timestamp < existing_ts:
                        should_update = True
                if should_update:
                    resolution_origins[resolved_ip] = {
                        'domain': origin_name,
                        'chain': list(chain_steps),
                        'server_ip': dns_ip,
                        'timestamp': timestamp,
                    'type': 'A'
                }

        # Если цепочки отсутствуют, используем прямые DNS ответы
        responses = dns_data.get('DNS Responses', []) or []
        for response in responses:
            record_type = (response.get('type') or '').upper()
            if record_type not in ('A', 'AAAA'):
                continue
            domain_name = (response.get('name') or '').rstrip('.')
            if not domain_name:
                continue
            resolved_ips = extract_ips_from_resolution(response.get('resolution', ''))
            if not resolved_ips:
                continue
            timestamp = response.get('timestamp')
            for resolved_ip in resolved_ips:
                should_update = False
                existing = resolution_origins.get(resolved_ip)
                if existing is None:
                    should_update = True
                elif timestamp is not None:
                    existing_ts = existing.get('timestamp')
                    if existing_ts is None or (timestamp is not None and timestamp < existing_ts):
                        should_update = True
                if should_update:
                    resolution_origins[resolved_ip] = {
                        'domain': domain_name,
                        'chain': [domain_name],
                        'server_ip': dns_ip,
                        'timestamp': timestamp,
                        'type': record_type
                    }
    
    # Добавляем статистику протоколов
    if 'Overall Packet Statistics' in raw_data:
        logger.info("Processing protocol statistics")
        protocol_stats = {}
        for key, value in raw_data['Overall Packet Statistics'].items():
            if key.endswith('_count'):
                protocol_name = key.replace('_count', '').upper()
                protocol_stats[protocol_name] = value
        
        result['Protocol_Statistics'] = protocol_stats
    
    # Обрабатываем IP-адреса, исключая 'Overall Packet Statistics'
    logger.info(f"Processing {len(raw_data) - 1} IP addresses")
    ip_count = 0
    all_connections = set()
    
    for ip, ip_data in raw_data.items():
        if ip == 'Overall Packet Statistics':
            continue
        
        ip_count += 1
        if ip_count % 10 == 0:
            logger.debug(f"Processed {ip_count} IPs")
            
        # Обрабатываем данные о IP - объединяем всю информацию
        ip_detail = {
            'ip': ip,
            'asn': ip_data.get('ASN', 'Неизвестно'),
            'first_seen': ip_data.get('First Seen'),
            'last_seen': ip_data.get('Last Seen'),
            
            # Трафик
            'traffic': {
                'incoming_bytes': ip_data.get('Traffic', {}).get('bytes_in', 0),
                'outgoing_bytes': ip_data.get('Traffic', {}).get('bytes_out', 0),
                'incoming_packets': ip_data.get('Traffic', {}).get('packets_in', 0),
                'outgoing_packets': ip_data.get('Traffic', {}).get('packets_out', 0),
                'total_bytes': ip_data.get('Traffic', {}).get('bytes_in', 0) + ip_data.get('Traffic', {}).get('bytes_out', 0),
                'total_packets': ip_data.get('Traffic', {}).get('packets_in', 0) + ip_data.get('Traffic', {}).get('packets_out', 0)
            },
            
            # Соединения
            'connections': {
                'outgoing': ip_data.get('Connections', {}).get('Outgoing', []),
                'incoming': ip_data.get('Connections', {}).get('Incoming', [])
            },
            
            # DNS информация
            'dns': {
                'associations': ip_data.get('DNS Associations', []),
                'queries_by_server': ip_data.get('DNS Queries by Server', {}),
                'responses': ip_data.get('DNS Responses', []),
                'resolution_chains': ip_data.get('DNS Resolution Chains', []),
                'origin_query': resolution_origins.get(ip)
            },
            
            # HTTP информация
            'http': {
                'domains': ip_data.get('HTTP Domains', []),
                'requests': ip_data.get('HTTP Requests', []),
                'responses': ip_data.get('HTTP Responses', []),
                'by_domain': ip_data.get('HTTP By Domain', {})
            },
            
            # TLS информация
            'tls': {
                'sni_records': ip_data.get('SNI Records', []),
                'info': ip_data.get('TLS Info', {})
            },
            
            # Информация о угрозе
            'threat_info': ip_data.get('Threat Info', {
                'is_blacklisted': False,
                'threat_score': 0,
                'threat_level': 'Безопасный'
            })
        }
        
        result['IP_Details'][ip] = ip_detail
        
        # Создаем узел для графа
        node = {
            'id': ip,
            'label': ip,
            'title': f"IP: {ip}\nASN: {ip_detail['asn']}\nТрафик: {format_bytes(ip_detail['traffic']['total_bytes'])}\nПакеты: {ip_detail['traffic']['total_packets']}",
            'value': max(1, ip_detail['traffic']['total_packets'] / 100),  # Размер узла зависит от количества пакетов
            'color': '#ef4444' if ip_detail['threat_info']['is_blacklisted'] else '#10b981',
            'font': {'size': 12},
            'borderWidth': 2,
            'borderWidthSelected': 4
        }
        result['Network_Graph']['nodes'].append(node)
        
        # Добавляем ребра графа для исходящих соединений
        for target_ip in ip_detail['connections']['outgoing']:
            connection_key = f"{ip}->{target_ip}"
            if connection_key not in all_connections:
                all_connections.add(connection_key)
                
                # Вычисляем вес соединения на основе трафика
                source_outgoing = ip_detail['traffic']['outgoing_bytes']
                target_data = raw_data.get(target_ip, {})
                target_incoming = target_data.get('Traffic', {}).get('bytes_in', 0)
                connection_weight = min(source_outgoing, target_incoming) if target_incoming > 0 else source_outgoing
                
                edge = {
                    'from': ip,
                    'to': target_ip,
                    'value': max(1, connection_weight / 1000),  # Ширина ребра зависит от трафика
                    'title': f"Соединение: {ip} → {target_ip}\nТрафик: {format_bytes(connection_weight)}",
                    'arrows': {'to': True},
                    'color': {
                        'color': '#94a3b8',
                        'highlight': '#4361ee',
                        'hover': '#7490ff'
                    },
                    'smooth': {'type': 'continuous'}
                }
                result['Network_Graph']['edges'].append(edge)
    
    # Обрабатываем DNS запросы глобально
    import re
    dns_queries = {}
    for ip, ip_data in result['IP_Details'].items():
        # DNS ответы (когда IP является DNS сервером)
        for response in ip_data['dns']['responses']:
            domain = response.get('name', '').rstrip('.')
            if not domain or domain == '<UNKNOWN>':
                continue
            
            entry = dns_queries.setdefault(domain, {
                'domain': domain,
                'type': response.get('type', 'UNKNOWN'),
                'resolution': response.get('resolution', ''),
                'ttl': response.get('ttl', 0),
                'server_ip': ip,
                'timestamp': response.get('timestamp'),
                'queries': [],
                'responses': [],
                'clients': [],
                'servers': []
            })
            
            entry['responses'].append({
                'type': response.get('type', 'UNKNOWN'),
                'resolution': response.get('resolution', ''),
                'ttl': response.get('ttl', 0),
                'server_ip': ip,
                'timestamp': response.get('timestamp')
            })
            if ip not in entry['servers']:
                entry['servers'].append(ip)
            
            # Обновляем краткую информацию по домену
            if not entry.get('resolution'):
                entry['resolution'] = response.get('resolution', '')
            if not entry.get('timestamp'):
                entry['timestamp'] = response.get('timestamp')
            entry['type'] = response.get('type', entry.get('type', 'UNKNOWN'))
            entry['server_ip'] = ip
            entry['ttl'] = response.get('ttl', entry.get('ttl', 0))
            
            alias = response.get('resolution', '').rstrip('.')
            if alias:
                aliases = set(entry.get('alias_names', []))
                if alias not in aliases:
                    aliases.add(alias)
                    entry['alias_names'] = sorted(aliases)
        
        # DNS запросы (когда IP делает запросы к DNS серверам)
        for server_ip, queries in ip_data['dns']['queries_by_server'].items():
            for query_str in queries:
                match = re.match(r'^(.+?)\s*\(([^)]+)\)$', query_str)
                if not match:
                    continue
                
                domain, query_type = match.groups()
                domain = domain.strip().rstrip('.')
                entry = dns_queries.setdefault(domain, {
                    'domain': domain,
                    'type': query_type,
                    'resolution': '',
                    'ttl': 0,
                    'server_ip': server_ip,
                    'timestamp': None,
                    'queries': [],
                    'responses': [],
                    'clients': [],
                    'servers': []
                })
                
                entry['queries'].append({
                    'client_ip': ip,
                    'server_ip': server_ip,
                    'type': query_type
                })
                if ip not in entry['clients']:
                    entry['clients'].append(ip)
                
                # Если тип не задан, используем информацию из запроса
                if not entry.get('type'):
                    entry['type'] = query_type
                if not entry.get('server_ip'):
                    entry['server_ip'] = server_ip
    
    result['DNS_Queries'] = dns_queries
    
    logger.info("Data transformation completed successfully")
    return result

def format_bytes(bytes_value):
    """Форматирует размер в байтах в человекочитаемый формат"""
    if bytes_value == 0:
        return "0 B"
    
    sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while bytes_value >= 1024 and i < len(sizes) - 1:
        bytes_value /= 1024.0
        i += 1
    
    return f"{bytes_value:.1f} {sizes[i]}"


def save_latest_result(data_url, report_url=None):
    """Сохраняет ссылку на последний результат анализа/сравнения."""
    os.makedirs(os.path.dirname(LATEST_RESULT_PATH), exist_ok=True)
    with open(LATEST_RESULT_PATH, 'w', encoding='utf-8') as result_file:
        payload = {'dataUrl': data_url}
        if report_url:
            payload['reportUrl'] = report_url
        json.dump(payload, result_file, ensure_ascii=False, indent=2)

@app.route('/')
def index():
    """Render the main dashboard."""
    return render_template('dashboard.html', cpu_count=CPU_COUNT, default_threads=DEFAULT_THREADS)


@app.route('/graph')
def graph_page():
    """Render standalone network graph page."""
    return render_template('graph.html', cpu_count=CPU_COUNT, default_threads=DEFAULT_THREADS)

@app.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    """Analyze a PCAP file and return the results."""
    if 'file' not in request.files:
        logger.warning("No file provided in request")
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        logger.warning("Empty filename in request")
        return jsonify({'error': 'No file selected'}), 400
    
    logger.info(f"Processing file: {file.filename}")
    
    # Save the file temporarily
    upload_folder = 'uploads'
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, file.filename)
    file.save(filepath)
    
    # Process the file
    check_blacklists = request.form.get('checkBlacklists', 'true').lower() == 'true'
    threads = int(request.form.get('threads', str(DEFAULT_THREADS)))
    # Устанавливаем ограничение на максимальное количество потоков
    if threads > CPU_COUNT:
        threads = DEFAULT_THREADS
    
    logger.info(f"Analysis starting with {threads} threads, blacklist checking: {check_blacklists}")
    
    try:
        net_parser = NetParser(check_blacklists=check_blacklists)
        net_parser.analyze(filepath, num_threads=threads)
        raw_data = net_parser.get_dict()
        
        logger.info("NetParser analysis completed, transforming data for frontend")
        
        # Transform data into frontend-friendly format
        transformed_data = transform_data_for_frontend(raw_data)
        
        # Save the results
        data_folder = 'static/data'
        os.makedirs(data_folder, exist_ok=True)
        data_path = os.path.join(data_folder, 'analysis_result.json')
        logger.info(f"Saving results to {data_path}")
        
        with open(data_path, 'w', encoding='utf-8') as f:
            json.dump(transformed_data, f, ensure_ascii=False, indent=2)

        report_path = os.path.join(data_folder, 'analysis_report.html')
        generate_simple_html_report(report_path, raw_data, title=f"NetParser Analysis Report: {file.filename}")
        report_url = '/static/data/analysis_report.html'
        
        logger.info("Analysis complete, returning success response")
        save_latest_result('/static/data/analysis_result.json', report_url=report_url)
        return jsonify({
            'success': True,
            'dataUrl': '/static/data/analysis_result.json',
            'reportUrl': report_url,
            'cpuCount': CPU_COUNT,
            'threadsUsed': threads
        })
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        # Cleanup
        if os.path.exists(filepath):
            os.remove(filepath)

@app.route('/api/compare', methods=['POST'])
def compare_pcaps():
    """Compare two PCAP files and return the differences."""
    logger.info("Received request to compare PCAP files")
    
    if 'baseFile' not in request.files or 'compareFile' not in request.files:
        logger.warning("Missing files in compare request")
        return jsonify({'error': 'Both files are required'}), 400
    
    base_file = request.files['baseFile']
    compare_file = request.files['compareFile']
    
    if base_file.filename == '' or compare_file.filename == '':
        logger.warning("Empty filename in compare request")
        return jsonify({'error': 'Both files must be selected'}), 400
    
    logger.info(f"Comparing files: {base_file.filename} and {compare_file.filename}")
    
    # Save the files temporarily
    upload_folder = 'uploads'
    os.makedirs(upload_folder, exist_ok=True)
    base_filepath = os.path.join(upload_folder, base_file.filename)
    compare_filepath = os.path.join(upload_folder, compare_file.filename)
    base_file.save(base_filepath)
    compare_file.save(compare_filepath)
    
    try:
        # Compare the files
        logger.info("Starting comparison")
        result = compare_traffic(base_filepath, compare_filepath)
        
        # Transform data into frontend-friendly format
        logger.info("Comparison complete, transforming data for frontend")
        transformed_data = transform_data_for_frontend(result)
        
        # Save the results
        data_folder = 'static/data'
        os.makedirs(data_folder, exist_ok=True)
        data_path = os.path.join(data_folder, 'comparison_result.json')
        logger.info(f"Saving comparison results to {data_path}")
        
        with open(data_path, 'w', encoding='utf-8') as f:
            json.dump(transformed_data, f, ensure_ascii=False, indent=2)

        report_path = os.path.join(data_folder, 'comparison_report.html')
        generate_simple_html_report(report_path, result, title=f"NetParser Compare Report: {base_file.filename} vs {compare_file.filename}")
        report_url = '/static/data/comparison_report.html'
        
        logger.info("Comparison complete, returning success response")
        save_latest_result('/static/data/comparison_result.json', report_url=report_url)
        return jsonify({
            'success': True,
            'dataUrl': '/static/data/comparison_result.json',
            'reportUrl': report_url
        })
    except Exception as e:
        logger.error(f"Error during comparison: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        # Cleanup
        if os.path.exists(base_filepath):
            os.remove(base_filepath)
        if os.path.exists(compare_filepath):
            os.remove(compare_filepath)

@app.route('/api/data/<filename>')
def get_data(filename):
    """Get the data from a JSON file."""
    logger.info(f"Request for data file: {filename}")
    
    data_folder = 'static/data'
    data_path = os.path.join(data_folder, filename)
    
    if not os.path.exists(data_path):
        logger.warning(f"Data file not found: {data_path}")
        return jsonify({'error': 'Data not found'}), 404
    
    logger.info(f"Reading data from {data_path}")
    with open(data_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    logger.info(f"Successfully returned data file: {filename}")
    return jsonify(data)

@app.route('/api/system-info')
def get_system_info():
    """Get system information for the dashboard."""
    logger.info("Request for system information")
    return jsonify({
        'cpuCount': CPU_COUNT,
        'recommendedThreads': DEFAULT_THREADS
    })


@app.route('/api/latest-result')
def get_latest_result():
    """Returns the latest analysis result URL for graph page."""
    logger.debug("Latest result requested by frontend")
    if not os.path.exists(LATEST_RESULT_PATH):
        logger.warning("Latest result file not found")
        return jsonify({'error': 'Latest result not found'}), 404

    with open(LATEST_RESULT_PATH, 'r', encoding='utf-8') as result_file:
        payload = json.load(result_file)

    data_url = payload.get('dataUrl')
    if not data_url:
        logger.warning("Latest result file exists but dataUrl is empty")
        return jsonify({'error': 'Latest result is empty'}), 404
    logger.info(f"Latest result resolved: {data_url}")
    response_payload = {'dataUrl': data_url}
    report_url = payload.get('reportUrl')
    if report_url:
        response_payload['reportUrl'] = report_url
    return jsonify(response_payload)


@app.route('/api/export-report')
def export_report():
    """Export latest (or provided) HTML report as file attachment."""
    requested_report_url = request.args.get('reportUrl', '').strip()

    if requested_report_url:
        report_url = requested_report_url
    else:
        if not os.path.exists(LATEST_RESULT_PATH):
            return jsonify({'error': 'Latest result not found'}), 404
        with open(LATEST_RESULT_PATH, 'r', encoding='utf-8') as result_file:
            payload = json.load(result_file)
        report_url = (payload.get('reportUrl') or '').strip()

    if not report_url:
        return jsonify({'error': 'Report URL not found'}), 404

    if not report_url.startswith('/static/data/') or not report_url.endswith('.html'):
        logger.warning(f"Invalid report URL requested for export: {report_url}")
        return jsonify({'error': 'Invalid report path'}), 400

    report_abs = os.path.abspath(report_url.lstrip('/'))
    allowed_root = os.path.abspath(os.path.join('static', 'data'))
    if not report_abs.startswith(allowed_root + os.sep):
        logger.warning(f"Blocked export path outside static/data: {report_abs}")
        return jsonify({'error': 'Forbidden report path'}), 403

    if not os.path.exists(report_abs):
        logger.warning(f"Report file not found for export: {report_abs}")
        return jsonify({'error': 'Report file not found'}), 404

    download_name = os.path.basename(report_abs)
    logger.info(f"Exporting HTML report: {download_name}")
    return send_file(report_abs, as_attachment=True, download_name=download_name, mimetype='text/html')


@app.route('/api/frontend-log', methods=['POST'])
def frontend_log():
    """Receives frontend logs for troubleshooting in app.log."""
    payload = request.get_json(silent=True) or {}
    source = payload.get('source', 'frontend')
    level = str(payload.get('level', 'info')).lower()
    message = payload.get('message', '')
    meta = payload.get('meta', {})

    log_text = f"[{source}] {message} | meta={meta}"
    if level == 'error':
        logger.error(log_text)
    elif level == 'warning':
        logger.warning(log_text)
    else:
        logger.info(log_text)

    return jsonify({'ok': True})

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('static/data', exist_ok=True)
    
    logger.info(f"Starting Flask app on port 5000 with {CPU_COUNT} CPU cores detected")
    app.run(debug=True, host='0.0.0.0', port=5000) 
