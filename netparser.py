#!/usr/bin/env python3
import logging
import sys
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Callable, Any, Dict, Set, Generator, List, Union, Tuple
import threading
import os
import requests
import tempfile
import time
from scapy.all import IP, TCP, UDP, ICMP, DNS, PcapReader, Packet, Raw
from tqdm import tqdm
import pyasn
import hashlib
import datetime
import json

class NetParserError(Exception):
    """Базовый класс для исключений NetParser."""
    pass

class PCAPFileError(NetParserError):
    """Исключение для ошибок, связанных с PCAP файлами."""
    pass

class ASNDatabaseError(NetParserError):
    """Исключение для ошибок, связанных с базой ASN."""
    pass

class PacketProcessingError(NetParserError):
    """Исключение для ошибок обработки пакетов."""
    pass

class ValidationError(NetParserError):
    """Исключение для ошибок валидации данных."""
    pass

DNS_TYPE_MAP = {
    1: "A",           # IPv4 адрес
    2: "NS",          # Авторитетный сервер имен
    5: "CNAME",       # Каноническое имя
    6: "SOA",         # Начало зоны
    12: "PTR",        # Указатель
    15: "MX",         # Почтовый обменник
    16: "TXT",        # Текстовые записи
    17: "RP",         # Ответственное лицо
    18: "AFSDB",      # AFS база данных
    24: "SIG",        # Подпись
    25: "KEY",        # Ключ
    28: "AAAA",       # IPv6 адрес
    29: "LOC",        # Географическое местоположение
    33: "SRV",        # Сервис
    35: "NAPTR",      # Naming Authority Pointer
    36: "KX",         # Key Exchanger
    37: "CERT",       # Сертификат
    39: "DNAME",      # Delegation Name
    42: "APL",        # Address Prefix List
    43: "DS",         # Delegation Signer
    44: "SSHFP",      # SSH Fingerprint
    45: "IPSECKEY",   # IPSEC Key
    46: "RRSIG",      # DNSSEC Signature
    47: "NSEC",       # Next Secure
    48: "DNSKEY",     # DNS Key
    49: "DHCID",      # DHCP Identifier
    50: "NSEC3",      # Next Secure v3
    51: "NSEC3PARAM", # NSEC3 Parameters
    52: "TLSA",       # TLSA Certificate Association
    55: "HIP",        # Host Identity Protocol
    59: "CDS",        # Child DS
    60: "CDNSKEY",    # Child DNSKEY
    65: "HTTPS",      # HTTPS RR (SVCB)
    99: "SPF",        # Sender Policy Framework
    108: "EUI48",     # EUI-48 Identifier
    109: "EUI64",     # EUI-64 Identifier
    249: "TKEY",      # Transaction Key
    250: "TSIG",      # Transaction Signature
    251: "IXFR",      # Incremental Zone Transfer
    252: "AXFR",      # Zone Transfer
    257: "CAA",       # Certification Authority Authorization
    32768: "TA",      # DNSSEC Trust Authorities
    32769: "DLV",     # DNSSEC Lookaside Validation
}

class Logger:
    """
    Класс для настройки логирования.
    Выводит сообщения в консоль и записывает предупреждения и ошибки в файл.
    """
    @staticmethod
    def setup_logger() -> logging.Logger:
        logger = logging.getLogger("NetParser")
        logger.setLevel(logging.DEBUG)
        info_console_handler = logging.StreamHandler(sys.stdout)
        info_console_handler.setLevel(logging.INFO)
        file_handler = logging.FileHandler('error.log', mode='w', encoding='utf-8')
        file_handler.setLevel(logging.WARNING)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        info_console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        if logger.hasHandlers():
            logger.handlers.clear()
        logger.addHandler(info_console_handler)
        logger.addHandler(file_handler)
        return logger

class ASNDatabase:
    """
    Класс для работы с базой ASN.
    Использует библиотеку pyasn для поиска информации по ASN.
    """
    def __init__(self, asndb_path: str, as_names_file: str) -> None:
        if not os.path.exists(asndb_path) or not os.path.exists(as_names_file):
            raise ASNDatabaseError(f"ASN database files not found: {asndb_path}, {as_names_file}")
        try:
            self.asndb = pyasn.pyasn(asndb_path, as_names_file=as_names_file)
        except Exception as e:
            raise ASNDatabaseError(f"Failed to initialize ASN database: {str(e)}")
        self.asn_cache: Dict[str, str] = {}
        self.lock = threading.Lock()

    def lookup_asn(self, ip: str) -> str:
        if not self._is_valid_ipv4(ip):
            raise ValidationError(f"Invalid IP address format: {ip}")
        with self.lock:
            if ip in self.asn_cache:
                return self.asn_cache[ip]
        try:
            asn_info = self.asndb.lookup(ip)
            asn_name = self.asndb.get_as_name(asn_info[0]) if asn_info else '<NOT FOUND>'
        except Exception as e:
            self.logger.warning(f"ASN lookup failed for IP {ip}: {str(e)}")
            asn_name = '<NOT FOUND>'
        with self.lock:
            self.asn_cache[ip] = asn_name
        return asn_name

    @staticmethod
    def _is_valid_ipv4(ip: str) -> bool:
        """Проверяет, является ли строка корректным IPv4 адресом."""
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))

class IpsumBlacklist:
    """
    Класс для работы с базой черных IP из репозитория ipsum.
    Загружает список подозрительных/вредоносных IP-адресов и предоставляет методы для их проверки.
    """
    IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    CACHE_TTL = 86400  # 24 часа (в секундах)
    
    def __init__(self, cache_dir: Optional[str] = None, async_load: bool = True):
        self.logger = Logger.setup_logger()
        self.blacklist: Dict[str, int] = {}
        self.lock = threading.Lock()
        self.last_update = 0
        self.cache_dir = cache_dir or tempfile.gettempdir()
        self.cache_file = os.path.join(self.cache_dir, "ipsum_blacklist.txt")
        self.loading_complete = threading.Event()
        self._loading_thread = None
        
        # Загружаем черный список асинхронно, если включено
        if async_load:
            self._start_async_loading()
        else:
            self._load_blacklist()
            self.loading_complete.set()
    
    def _start_async_loading(self) -> None:
        """Запускает асинхронную загрузку черного списка в отдельном потоке."""
        self._loading_thread = threading.Thread(target=self._async_load_blacklist)
        self._loading_thread.daemon = True
        self._loading_thread.start()
    
    def _async_load_blacklist(self) -> None:
        """Выполняет загрузку черного списка в отдельном потоке."""
        try:
            self._load_blacklist()
        except Exception as e:
            self.logger.error(f"Error in async blacklist loading: {str(e)}")
        finally:
            self.loading_complete.set()
    
    def _load_blacklist(self) -> None:
        """Загружает черный список IP-адресов."""
        with self.lock:
            try:
                # Проверяем, нужно ли обновить кэш
                if os.path.exists(self.cache_file):
                    file_mod_time = os.path.getmtime(self.cache_file)
                    if time.time() - file_mod_time < self.CACHE_TTL:
                        self._parse_blacklist_file()
                        self.logger.info(f"Loaded IP blacklist from cache ({len(self.blacklist)} entries)")
                        return
                
                # Загружаем свежий список
                self.logger.info("Updating IP blacklist from repository...")
                response = requests.get(self.IPSUM_URL, timeout=30)
                response.raise_for_status()
                
                # Сохраняем в кэш
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                
                self._parse_blacklist_file()
                self.last_update = time.time()
                self.logger.info(f"Successfully updated IP blacklist ({len(self.blacklist)} entries)")
            except Exception as e:
                self.logger.warning(f"Failed to update IP blacklist: {str(e)}")
                # Пытаемся загрузить из кэша, если он существует
                if os.path.exists(self.cache_file):
                    self._parse_blacklist_file()
                    self.logger.info(f"Loaded IP blacklist from cache ({len(self.blacklist)} entries)")
    
    def _parse_blacklist_file(self) -> None:
        """Парсит файл с черным списком IP."""
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                self.blacklist.clear()
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            ip = parts[0]
                            try:
                                score = int(parts[1])
                                self.blacklist[ip] = score
                            except ValueError:
                                pass
        except Exception as e:
            self.logger.error(f"Error parsing blacklist file: {str(e)}")
    
    def check_ip(self, ip: str) -> Tuple[bool, int]:
        """
        Проверяет, находится ли IP в черном списке.
        
        Args:
            ip: IP-адрес для проверки
            
        Returns:
            Tuple[bool, int]: (есть_в_черном_списке, счетчик_угрозы)
        """
        # Ждем завершения загрузки черного списка, если она еще идет
        if not self.loading_complete.is_set():
            # Устанавливаем таймаут, чтобы не блокировать обработку надолго
            self.loading_complete.wait(timeout=0.5)
            
        with self.lock:
            score = self.blacklist.get(ip, 0)
            return score > 0, score
    
    def get_threat_level(self, score: int) -> str:
        """
        Определяет уровень угрозы на основе счетчика.
        
        Args:
            score: Счетчик встречаемости IP в черных списках
            
        Returns:
            str: Текстовое описание уровня угрозы
        """
        if score <= 0:
            return "Безопасный"
        elif score <= 2:
            return "Низкий"
        elif score <= 4:
            return "Средний"
        elif score <= 6:
            return "Высокий"
        else:
            return "Критический"

class NetParser:
    """
    Класс для анализа трафика из PCAP файлов.
    Обрабатывает DNS, HTTP, TLS (SNI) пакеты, собирает статистику трафика и ассоциации.
    """
    def __init__(self,
                 asndb_path: str = "./asndb/ipasndb.dat",
                 as_names_file: str = "./asndb/asnname.json",
                 check_blacklists: bool = True) -> None:
        self.logger = Logger.setup_logger()
        self.http_domains: Dict[str, Set[str]] = {}
        self.http_requests: Dict[str, List[Dict[str, str]]] = {}
        # Store HTTP responses separately
        self.http_responses: Dict[str, List[Dict[str, str]]] = {}
        self.dns_associations: Dict[str, Set[str]] = {}
        self.sni_by_ip: Dict[str, Set[str]] = {}
        self.output_data: Dict[str, Dict[str, int]] = {}
        self.ip_list_conn: Set[str] = set()
        self.asn_database = ASNDatabase(asndb_path, as_names_file)
        self.packet_statistics: Dict[str, int] = {
            "total_packets": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "http_count": 0,
            "https_count": 0,
            "dns_count": 0,
            "other_count": 0,
            "total_bytes": 0
        }
        
        # Разделение блокировок для более точной синхронизации
        self.data_lock = threading.Lock()  # Общая блокировка для обратной совместимости
        self.stats_lock = threading.Lock()  # Блокировка для статистики
        self.http_lock = threading.Lock()   # Блокировка для HTTP-данных
        self.dns_lock = threading.Lock()    # Блокировка для DNS-данных
        self.sni_lock = threading.Lock()    # Блокировка для SNI-данных
        self.ip_lock = threading.Lock()     # Блокировка для IP-информации
        
        self.dns_queries_by_server: Dict[str, Dict[str, Set[str]]] = {}
        self.dns_response_table: Dict[str, List[Dict[str, Any]]] = {}
        self.check_blacklists = check_blacklists
        self.ip_blacklist = IpsumBlacklist() if check_blacklists else None
        self.ip_threat_info: Dict[str, Tuple[bool, int]] = {}  # Информация о угрозе {ip: (в_черном_списке, счетчик)}
        # Связи между IP адресами (src -> dst)
        self.ip_connections: Dict[str, Set[str]] = {}
        # Обратные связи (dst -> src)
        self.ip_reverse_connections: Dict[str, Set[str]] = {}
        # Хранит инициатора соединения для пары IP-адресов
        self.connection_initiators: Dict[Tuple[str, str], str] = {}
        
        # Временные метки для первого и последнего пакета
        self.first_seen: Dict[str, float] = {}  # {ip: timestamp}
        self.last_seen: Dict[str, float] = {}   # {ip: timestamp}
        
        # Структуры данных для TCP reassembly
        # stream_id -> list of (sequence_number, payload) tuples
        self.tcp_streams: Dict[Tuple[str, str, int, int], List[Tuple[int, bytes]]] = {}
        # stream_id -> buffer of processed data
        self.tcp_buffer: Dict[Tuple[str, str, int, int], bytes] = {}
        # stream_id -> expected sequence number
        self.tcp_seq_expect: Dict[Tuple[str, str, int, int], int] = {}
        self.tcp_streams_lock = threading.Lock()
        # Флаг для включения сборки TCP потоков
        self.enable_tcp_reassembly = True
        # Максимальный размер TCP буфера (предотвращение утечек памяти)
        self.max_tcp_buffer_size = 10 * 1024 * 1024  # 10 MB
        
        # JA3 и TLS информация
        self.tls_info: Dict[str, List[Dict[str, Any]]] = {}  # {ip: [{ja3, cipher_suites, tls_version, alpn}]}
        self.tls_lock = threading.Lock()

    def _get_or_create_set(self, d: Dict[str, Set[str]], key: str) -> Set[str]:
        """Получает существующий Set или создает новый."""
        if key not in d:
            d[key] = set()
        return d[key]

    def _get_or_create_dict(self, d: Dict[str, Dict[str, Set[str]]], key: str) -> Dict[str, Set[str]]:
        """Получает существующий Dict или создает новый."""
        if key not in d:
            d[key] = {}
        return d[key]

    def _get_or_create_list(self, d: Dict[str, List[Dict[str, str]]], key: str) -> List[Dict[str, str]]:
        """Получает существующий List или создает новый."""
        if key not in d:
            d[key] = []
        return d[key]

    def _get_or_create_int_dict(self, d: Dict[str, Dict[str, int]], key: str) -> Dict[str, int]:
        """Получает существующий Dict[int] или создает новый."""
        if key not in d:
            d[key] = {}
        return d[key]

    @staticmethod
    def _normalize_ipv4(ip: str) -> str:
        """Нормализует IPv4 адрес, если он записан в формате ::ffff:x.x.x.x"""
        if ip and re.match(r"^::ffff:\d+\.\d+\.\d+\.\d+$", ip):
            return ip.split(":")[-1]
        return ip

    @staticmethod
    def _is_valid_ipv4(ip: str) -> bool:
        """Проверяет, является ли строка корректным IPv4 адресом."""
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))

    @staticmethod
    def _ip_sort_key(ip: str) -> tuple:
        """Ключ для сортировки IP адресов по числовому значению."""
        try:
            return tuple(int(part) for part in ip.split('.'))
        except Exception:
            return (9999,)

    def parse_and_process_http(self, payload: str, ip_src: str, ip_dst: str, pkt: Packet,
                             local_http_domains=None, local_http_requests=None, local_http_responses=None) -> None:
        """Расширенный парсинг HTTP-запросов с детальным анализом заголовков и содержимого."""
        try:
            lines = payload.splitlines()
            if not lines:
                return None
            
            # Улучшенное регулярное выражение для REQUEST LINE
            request_line_pattern = re.compile(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+(HTTP/\d\.\d)")
            match_req = request_line_pattern.match(lines[0])
            
            http_data = None
            if match_req:
                # Это HTTP запрос
                http_data = {
                    "type": "request",
                    "method": match_req.group(1),
                    "uri": match_req.group(2),
                    "version": match_req.group(3),
                    "host": "",
                    "user_agent": "",
                    "content_type": "",
                    "content_length": "",
                    "referer": "",
                    "cookies": "",
                    "authorization": "",
                    "origin": "",
                    "x_requested_with": "",
                    "proxy_connection": "",  # Добавляем для CONNECT запросов
                    "is_proxy_request": match_req.group(1) == "CONNECT",  # Флаг для CONNECT запросов
                    "timestamp": float(pkt.time) if hasattr(pkt, 'time') else time.time()
                }
                
                # Парсинг заголовков
                headers_section_ended = False
                body = []
                
                for line in lines[1:]:
                    line = line.strip()
                    if not line and not headers_section_ended:
                        headers_section_ended = True
                        continue
                    
                    if headers_section_ended:
                        body.append(line)
                        continue
                    
                    if ':' in line:
                        header, value = line.split(":", 1)
                        header = header.strip().lower()
                        value = value.strip()
                        
                        if header == "host":
                            http_data["host"] = value
                        elif header == "user-agent":
                            http_data["user_agent"] = value
                        elif header == "content-type":
                            http_data["content_type"] = value
                        elif header == "content-length":
                            http_data["content_length"] = value
                        elif header == "referer":
                            http_data["referer"] = value
                        elif header == "cookie":
                            http_data["cookies"] = value
                        elif header == "authorization":
                            # Маскируем данные авторизации для безопасности
                            if value.startswith("Basic"):
                                http_data["authorization"] = "Basic [MASKED]"
                            elif value.startswith("Bearer"):
                                http_data["authorization"] = "Bearer [MASKED]"
                            else:
                                http_data["authorization"] = "[MASKED]"
                        elif header == "origin":
                            http_data["origin"] = value
                        elif header == "x-requested-with":
                            http_data["x_requested_with"] = value
                        elif header == "proxy-connection":
                            http_data["proxy_connection"] = value
                
                # Специальная обработка для CONNECT запросов
                if http_data["method"] == "CONNECT":
                    # CONNECT обычно содержит хост и порт в URI
                    # Пример: CONNECT example.com:443 HTTP/1.1
                    if ":" in http_data["uri"] and not http_data["host"]:
                        host_part = http_data["uri"].split(":")[0]
                        http_data["host"] = host_part
                
                # Добавляем тело запроса, если есть POST или PUT и Content-Length > 0
                if (http_data["method"] in ["POST", "PUT"]) and body and http_data.get("content_length"):
                    try:
                        content_length = int(http_data["content_length"])
                        if content_length > 0:
                            body_content = "\n".join(body)
                            # Маскируем потенциально чувствительные данные в теле запроса
                            if "password" in body_content.lower() or "token" in body_content.lower():
                                http_data["body"] = "[SENSITIVE CONTENT MASKED]"
                            else:
                                # Ограничиваем размер сохраняемого тела запроса
                                max_body_length = 1024  # Максимальная длина тела запроса для сохранения
                                if len(body_content) > max_body_length:
                                    http_data["body"] = body_content[:max_body_length] + "... [TRUNCATED]"
                                else:
                                    http_data["body"] = body_content
                                    
                            # Если это URL-encoded форма, парсим её в словарь для удобства анализа
                            if http_data.get("content_type") == "application/x-www-form-urlencoded":
                                try:
                                    from urllib.parse import parse_qs
                                    form_data = parse_qs(body_content)
                                    # Маскируем пароли
                                    safe_form_data = {}
                                    for key, value in form_data.items():
                                        if any(sensitive in key.lower() for sensitive in ["pass", "token", "secret", "key"]):
                                            safe_form_data[key] = ["[MASKED]"]
                                        else:
                                            safe_form_data[key] = value
                                    http_data["form_data"] = safe_form_data
                                except Exception as e:
                                    self.logger.debug(f"Error parsing form data: {str(e)}")
                    except ValueError:
                        pass
                
                # Парсинг URL-параметров для GET-запросов
                if "?" in http_data["uri"]:
                    try:
                        from urllib.parse import urlparse, parse_qs
                        parsed_url = urlparse(http_data["uri"])
                        query_params = parse_qs(parsed_url.query)
                        # Маскируем чувствительные данные
                        safe_query_params = {}
                        for key, value in query_params.items():
                            if any(sensitive in key.lower() for sensitive in ["pass", "token", "secret", "key"]):
                                safe_query_params[key] = ["[MASKED]"]
                            else:
                                safe_query_params[key] = value
                        http_data["query_params"] = safe_query_params
                    except Exception as e:
                        self.logger.debug(f"Error parsing query parameters: {str(e)}")
            
            # Проверяем, не является ли это HTTP ответом
            response_line_pattern = re.compile(r"^(HTTP/\d\.\d)\s+(\d+)\s+(.+)$")
            match_resp = response_line_pattern.match(lines[0])
            response_data = None
            if match_resp:
                # Это HTTP ответ
                response_data = {
                    "type": "response",
                    "status_version": match_resp.group(1),
                    "status_code": match_resp.group(2),
                    "status_message": match_resp.group(3),
                    "is_proxy_response": False,
                    "timestamp": float(pkt.time) if hasattr(pkt, 'time') else time.time(),
                    "headers": {}
                }
                
                # Парсинг заголовков ответа
                headers_section_ended = False
                body = []
                
                for line in lines[1:]:
                    line = line.strip()
                    if not line and not headers_section_ended:
                        headers_section_ended = True
                        continue
                        
                    if headers_section_ended:
                        body.append(line)
                        continue
                    
                    if ':' in line:
                        header, value = line.split(":", 1)
                        header = header.strip().lower()
                        value = value.strip()
                        
                        # Сохраняем все заголовки для анализа
                        response_data["headers"][header] = value
                        
                        if header == "proxy-connection":
                            response_data["is_proxy_response"] = True
                        elif header == "content-type":
                            response_data["content_type"] = value
                        elif header == "content-length":
                            response_data["content_length"] = value
                        elif header == "server":
                            response_data["server"] = value
                
                # Добавляем тело ответа, если есть
                if body and response_data.get("content_length"):
                    try:
                        content_length = int(response_data["content_length"])
                        if content_length > 0:
                            body_content = "\n".join(body)
                            # Ограничиваем размер сохраняемого тела
                            max_body_length = 1024
                            if len(body_content) > max_body_length:
                                # Сохраняем начало и конец для контекста
                                head_length = max_body_length // 2
                                tail_length = max_body_length // 2
                                response_data["body"] = body_content[:head_length] + "... [TRUNCATED] ..." + body_content[-tail_length:]
                            else:
                                response_data["body"] = body_content
                    except ValueError:
                        pass
            
            # Save parsed HTTP data, differentiate request/response, and count methods/status classes
            if local_http_domains is not None and local_http_requests is not None and local_http_responses is not None:
                # Используем локальные структуры данных для потокобезопасности
                if http_data:
                    http_type = http_data.get("type")
                    if http_type == "request":
                        # Count by HTTP method будет обрабатываться в вызывающем коде
                        # Record domain у клиента и сервера (для привязки ответов к домену)
                        if http_data.get("host"):
                            local_http_domains[ip_src].add(http_data["host"])
                            local_http_domains[ip_dst].add(http_data["host"])
                        # peer_ip — сервер, к которому идёт запрос (для ссылки-якоря)
                        http_data["peer_ip"] = ip_dst
                        # Store request
                        local_http_requests[ip_src].append(http_data)
                elif response_data:
                    http_type = response_data.get("type")
                    if http_type == "response":
                        # Count by status code class будет обрабатываться в вызывающем коде
                        # peer_ip — клиент, которому отправляется ответ (для ссылки-якоря)
                        response_data["peer_ip"] = ip_dst
                        # Store response
                        local_http_responses[ip_src].append(response_data)
            else:
                # Для обратной совместимости - синхронная обработка
                with self.http_lock:
                    if http_data:
                        http_type = http_data.get("type")
                        if http_type == "request":
                            # Count by HTTP method
                            method = http_data.get("method", "").lower()
                            stat_name = f"http_{method}"
                            with self.stats_lock:
                                self.packet_statistics.setdefault(stat_name, 0)
                                self.packet_statistics[stat_name] += 1
                                
                            with self.ip_lock:
                                src_stats = self._get_or_create_int_dict(self.output_data, ip_src)
                                src_stats[stat_name] = src_stats.get(stat_name, 0) + 1
                            
                            # Record domain у клиента и сервера
                            if http_data.get("host"):
                                self._get_or_create_set(self.http_domains, ip_src).add(http_data["host"])
                                self._get_or_create_set(self.http_domains, ip_dst).add(http_data["host"])
                            http_data = dict(http_data)
                            http_data["peer_ip"] = ip_dst
                            # Store request
                            self._get_or_create_list(self.http_requests, ip_src).append(http_data)
                    elif response_data:
                        http_type = response_data.get("type")
                        if http_type == "response":
                            # Count by status code class (2xx, 3xx, etc.)
                            status_code = response_data.get("status_code", "")
                            if status_code:
                                status_class = f"http_{status_code[0]}xx"
                                with self.stats_lock:
                                    self.packet_statistics.setdefault(status_class, 0)
                                    self.packet_statistics[status_class] += 1
                                
                                with self.ip_lock:
                                    dst_stats = self._get_or_create_int_dict(self.output_data, ip_dst)
                                    dst_stats[status_class] = dst_stats.get(status_class, 0) + 1
                            
                            response_data = dict(response_data)
                            response_data["peer_ip"] = ip_dst
                            # Store response
                            self._get_or_create_list(self.http_responses, ip_src).append(response_data)
        
        except Exception as e:
            self.logger.debug(f"Error in parse_and_process_http: {str(e)}")
            return None

    def handle_tls_pkt(self, pkt: Packet, payload: Optional[bytes] = None, local_sni_by_ip = None) -> None:
        """
        Обрабатывает TLS пакет и извлекает SNI, JA3 и другую информацию из ClientHello.
        
        Args:
            pkt: Пакет для обработки
            payload: Опционально - уже извлеченная полезная нагрузка (если есть)
            local_sni_by_ip: Опционально - локальный словарь для хранения SNI (для потокобезопасности)
        """
        try:
            if TCP in pkt:
                raw_payload = payload if payload is not None else (pkt[Raw].load if pkt.haslayer(Raw) else None)
                
                if not raw_payload:
                    return
                
                # Извлекаем SNI из ClientHello
                sni = self.extract_sni_from_tls(raw_payload)
                
                # Извлекаем JA3 фингерпринт, ALPN и другую информацию
                tls_info = self.extract_tls_info(raw_payload)
                
                if sni or tls_info:
                    ip = self._normalize_ipv4(pkt[IP].dst) if IP in pkt else '<UNKNOWN>'
                    
                    # Обработка SNI
                    if sni:
                        if local_sni_by_ip is not None:
                            # Используем локальное хранилище (для потокобезопасности)
                            local_sni_by_ip[ip].add(sni)
                        else:
                            # Глобальное хранилище
                            with self.sni_lock:
                                self._get_or_create_set(self.sni_by_ip, ip).add(sni)
                                
                                # Обновляем счетчик HTTPS пакетов
                                with self.stats_lock:
                                    self.packet_statistics["https_count"] = self.packet_statistics.get("https_count", 0) + 1
                                
                                with self.ip_lock:
                                    src_stats = self._get_or_create_int_dict(self.output_data, self._normalize_ipv4(pkt[IP].src))
                                    dst_stats = self._get_or_create_int_dict(self.output_data, ip)
                                    src_stats["https_count"] = src_stats.get("https_count", 0) + 1
                                    dst_stats["https_count"] = dst_stats.get("https_count", 0) + 1
                    
                    # Обновляем информацию о TLS (JA3, ALPN, и т.д.)
                    if tls_info:
                        with self.tls_lock:
                            if ip not in self.tls_info:
                                self.tls_info[ip] = []
                            self.tls_info[ip].append(tls_info)
        except Exception as e:
            self.logger.debug(f"Error processing TLS packet: {str(e)}")
    
    def extract_tls_info(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Извлекает информацию о TLS соединении, включая JA3 фингерпринт и ALPN.
        
        Args:
            data: Байты TLS-пакета
            
        Returns:
            Optional[Dict[str, Any]]: Словарь с информацией о TLS или None
        """
        try:
            # Проверяем, является ли это ClientHello
            if not data or len(data) < 5 or data[0] != 0x16:  # 0x16 - это HANDSHAKE
                return None
            
            pos = 0
            content_type = data[pos]
            if content_type != 0x16:  # Handshake
                return None
            
            # Пропускаем TLS версию и длину
            pos += 5
            
            # Проверяем, что это ClientHello
            if pos + 4 > len(data) or data[pos] != 0x01:  # ClientHello
                return None
            
            # Получаем длину handshake
            handshake_length = int.from_bytes(data[pos+1:pos+4], 'big')
            if pos + 4 + handshake_length > len(data):
                return None
            
            # Сохраняем начало для вычисления JA3
            client_hello_start = pos
            
            # Пропускаем ClientHello тип и длину
            pos += 4
            
            # Получаем TLS версию клиента
            if pos + 2 > len(data):
                return None
            tls_version = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            
            # Преобразуем версию в строку
            tls_version_str = None
            if tls_version == 0x0301:
                tls_version_str = "TLS 1.0"
            elif tls_version == 0x0302:
                tls_version_str = "TLS 1.1"
            elif tls_version == 0x0303:
                tls_version_str = "TLS 1.2"
            elif tls_version == 0x0304:
                tls_version_str = "TLS 1.3"
            else:
                tls_version_str = f"Unknown (0x{tls_version:04x})"
            
            # Пропускаем случайные данные
            pos += 32
            
            # Пропускаем идентификатор сессии
            if pos + 1 > len(data):
                return None
            session_id_length = data[pos]
            pos += 1 + session_id_length
            
            # Получаем список шифронаборов
            if pos + 2 > len(data):
                return None
            cipher_suites_length = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            cipher_suites = []
            
            if cipher_suites_length % 2 != 0:
                return None
            
            for i in range(0, cipher_suites_length, 2):
                if pos + i + 2 > len(data):
                    break
                cipher_suite = int.from_bytes(data[pos+i:pos+i+2], 'big')
                cipher_suites.append(cipher_suite)
            
            pos += cipher_suites_length
            
            # Пропускаем методы сжатия
            if pos + 1 > len(data):
                return None
            compression_methods_length = data[pos]
            pos += 1 + compression_methods_length
            
            # Обрабатываем TLS расширения
            alpn_protocols = []
            if pos + 2 <= len(data):
                extensions_length = int.from_bytes(data[pos:pos+2], 'big')
                pos += 2
                end_ext = pos + extensions_length
                
                while pos + 4 <= end_ext:
                    ext_type = int.from_bytes(data[pos:pos+2], 'big')
                    ext_length = int.from_bytes(data[pos+2:pos+4], 'big')
                    pos += 4
                    
                    # Обрабатываем расширение ALPN
                    if ext_type == 16:  # ALPN
                        if pos + ext_length <= end_ext:
                            alpn_list_length = int.from_bytes(data[pos:pos+2], 'big')
                            alpn_pos = pos + 2
                            alpn_end = pos + ext_length
                            
                            while alpn_pos + 1 <= alpn_end:
                                proto_len = data[alpn_pos]
                                alpn_pos += 1
                                
                                if alpn_pos + proto_len <= alpn_end:
                                    try:
                                        proto = data[alpn_pos:alpn_pos+proto_len].decode('ascii')
                                        alpn_protocols.append(proto)
                                    except UnicodeDecodeError:
                                        pass
                                    alpn_pos += proto_len
                                else:
                                    break
                    
                    pos += ext_length
            
            # Вычисляем JA3 фингерпринт
            ja3_parts = [
                str(tls_version),
                ",".join(str(cs) for cs in cipher_suites),
                # Здесь можно добавить другие компоненты JA3, но для базовой версии достаточно
            ]
            ja3_string = ",".join(ja3_parts)
            
            # Вычисляем MD5 хеш
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
            
            # Создаем информацию о TLS
            return {
                "timestamp": time.time(),
                "tls_version": tls_version_str,
                "cipher_suites": cipher_suites,
                "alpn_protocols": alpn_protocols,
                "ja3_string": ja3_string,
                "ja3_hash": ja3_hash
            }
            
        except Exception as e:
            self.logger.debug(f"Error extracting TLS info: {str(e)}")
            return None

    def handle_dns_pkt(self, pkt: Packet, local_dns_queries=None, local_dns_responses=None) -> None:
        """
        Обрабатывает DNS пакет, аккумулируя запросы и ответы.
        
        Args:
            pkt: DNS пакет для обработки
            local_dns_queries: Локальная структура для DNS запросов (для потокобезопасности)
            local_dns_responses: Локальная структура для DNS ответов (для потокобезопасности)
        """
        if UDP in pkt and (pkt[UDP].sport == 5353 or pkt[UDP].dport == 5353):
            return  # Игнорируем mDNS

        dns_layer = pkt.getlayer(DNS)
        if not dns_layer:
            return

        try:
            ip_src = self._normalize_ipv4(pkt[IP].src) if IP in pkt else '<UNKNOWN>'
            ip_dst = self._normalize_ipv4(pkt[IP].dst) if IP in pkt else '<UNKNOWN>'
            
            # Запоминаем время пакета для временных меток
            packet_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()

            # Обработка DNS запросов
            if dns_layer.qdcount and dns_layer.qd:
                queries = dns_layer.qd if isinstance(dns_layer.qd, list) else [dns_layer.qd]
                if local_dns_queries is not None:
                    # Используем локальные структуры данных
                    server_dict = local_dns_queries[ip_src]
                    for query in queries:
                        if hasattr(query, 'qname') and query.qname:
                            qname = query.qname.decode() if isinstance(query.qname, bytes) else query.qname
                            qtype = getattr(query, 'qtype', 1)  # По умолчанию A запрос
                            type_str = DNS_TYPE_MAP.get(qtype, str(qtype))
                            server_dict[ip_dst].add(f"{qname.rstrip('.')} ({type_str})")
                else:
                    # Используем глобальные структуры с блокировкой
                    with self.dns_lock:
                        server_dict = self._get_or_create_dict(self.dns_queries_by_server, ip_src)
                        target_set = self._get_or_create_set(server_dict, ip_dst)
                        for query in queries:
                            if hasattr(query, 'qname') and query.qname:
                                qname = query.qname.decode() if isinstance(query.qname, bytes) else query.qname
                                qtype = getattr(query, 'qtype', 1)  # По умолчанию A запрос
                                type_str = DNS_TYPE_MAP.get(qtype, str(qtype))
                                target_set.add(f"{qname.rstrip('.')} ({type_str})")

            # Обработка DNS ответов
            if dns_layer.qr == 1 and dns_layer.ancount and dns_layer.an:
                dns_server_ip = ip_src
                answers = dns_layer.an if isinstance(dns_layer.an, list) else [dns_layer.an]
                
                # Создаем список для хранения цепочек разрешений
                resolution_chains = {}
                
                # Предварительно извлекаем все CNAME для создания цепочек разрешений
                cname_map = {}
                for answer in answers:
                    try:
                        if not hasattr(answer, 'type'):
                            continue
                            
                        if answer.type == 5:  # CNAME
                            if hasattr(answer, 'rrname') and hasattr(answer, 'rdata'):
                                source = answer.rrname.decode() if isinstance(answer.rrname, bytes) else answer.rrname
                                source = source.rstrip('.')
                                
                                target = answer.rdata.decode() if isinstance(answer.rdata, bytes) else answer.rdata
                                target = target.rstrip('.')
                                
                                cname_map[source] = target
                    except Exception:
                        pass
                
                # Функция для построения цепочки CNAME
                def build_cname_chain(name, visited=None):
                    if visited is None:
                        visited = set()
                    if name in visited:
                        return []  # Избегаем циклических ссылок
                    visited.add(name)
                    
                    if name in cname_map:
                        target = cname_map[name]
                        chain = [name, target]
                        next_chain = build_cname_chain(target, visited)
                        if next_chain:
                            chain.extend(next_chain[1:])  # Пропускаем первый элемент (он уже в chain)
                        return chain
                    return [name]
                
                if local_dns_responses is not None:
                    # Используем локальные структуры данных
                    response_list = local_dns_responses[dns_server_ip]
                    for answer in answers:
                        try:
                            ans_type = getattr(answer, 'type', 'UNKNOWN')
                            type_str = DNS_TYPE_MAP.get(ans_type, str(ans_type))
                            ttl = getattr(answer, 'ttl', 0)
                            
                            # Проверяем наличие rrname для записей HTTPS (тип 65)
                            if ans_type == 65 and not hasattr(answer, 'rrname'):
                                rrname = '<HTTPS_RECORD>'
                            else:
                                rrname = (answer.rrname.decode() if isinstance(answer.rrname, bytes)
                                        else answer.rrname).rstrip('.') if hasattr(answer, 'rrname') and answer.rrname else '<UNKNOWN>'
                            
                            # Получаем данные ответа
                            rdata = getattr(answer, 'rdata', None)
                            if isinstance(rdata, bytes):
                                try:
                                    rdata = rdata.decode(errors='ignore')
                                except Exception:
                                    rdata = str(rdata)
                            
                            # Специальная обработка для HTTPS записей
                            if type_str == "HTTPS":
                                try:
                                    # Пытаемся извлечь данные из HTTPS записи
                                    https_data = []
                                    if hasattr(answer, 'svc_priority'):
                                        https_data.append(f"Priority: {answer.svc_priority}")
                                    if hasattr(answer, 'svc_target'):
                                        target = answer.svc_target.decode() if isinstance(answer.svc_target, bytes) else answer.svc_target
                                        https_data.append(f"Target: {target}")
                                    if hasattr(answer, 'svc_params'):
                                        https_data.append(f"Params: {answer.svc_params}")
                                    
                                    if https_data:
                                        rdata = ", ".join(https_data)
                                    else:
                                        rdata = "<HTTPS Data>"
                                except Exception as e:
                                    self.logger.debug(f"Error parsing HTTPS record: {str(e)}")
                                    rdata = "<HTTPS Parsing Error>"
                            
                            # Специальная обработка для разных типов записей
                            elif type_str == "A" and rdata and self._is_valid_ipv4(rdata):
                                # Построение цепочки разрешений, если есть CNAME
                                cname_chain = build_cname_chain(rrname)
                                if len(cname_chain) > 1:
                                    chain_key = cname_chain[0]
                                    if chain_key not in resolution_chains:
                                        resolution_chains[chain_key] = {
                                            "chain": cname_chain,
                                            "resolved_ips": []
                                        }
                                    resolution_chains[chain_key]["resolved_ips"].append(rdata)
                                    
                                # Проверяем IP из DNS-ответа на наличие в черных списках
                                if self.check_blacklists and self.ip_blacklist:
                                    with self.ip_lock:
                                        if rdata not in self.ip_threat_info:
                                            self.ip_threat_info[rdata] = self.ip_blacklist.check_ip(rdata)
                                
                            # Добавляем запись в локальную структуру
                            response_list.append({
                                "name": rrname,
                                "type": type_str,
                                "ttl": ttl,
                                "resolution": rdata if rdata else "<NO_DATA>",
                                "timestamp": packet_time
                            })
                        except Exception as e:
                            self.logger.debug(f"Error processing DNS answer: {str(e)}")
                            continue
                    
                    # После обработки всех ответов добавляем цепочки разрешений, если они есть
                    if resolution_chains:
                        for chain_data in resolution_chains.values():
                            response_list.append({
                                "name": chain_data["chain"][0],
                                "type": "RESOLUTION_CHAIN",
                                "ttl": 0,  # Для цепочек не устанавливаем TTL
                                "chain": chain_data["chain"],
                                "resolved_ips": chain_data["resolved_ips"],
                                "timestamp": packet_time
                            })
                else:
                    # Используем глобальные структуры с блокировкой
                    with self.dns_lock:
                        response_list = self._get_or_create_list(self.dns_response_table, dns_server_ip)
                        for answer in answers:
                            try:
                                ans_type = getattr(answer, 'type', 'UNKNOWN')
                                type_str = DNS_TYPE_MAP.get(ans_type, str(ans_type))
                                ttl = getattr(answer, 'ttl', 0)
                                
                                # Проверяем наличие rrname для записей HTTPS (тип 65)
                                if ans_type == 65 and not hasattr(answer, 'rrname'):
                                    rrname = '<HTTPS_RECORD>'
                                else:
                                    rrname = (answer.rrname.decode() if isinstance(answer.rrname, bytes)
                                            else answer.rrname).rstrip('.') if hasattr(answer, 'rrname') and answer.rrname else '<UNKNOWN>'
                                
                                # Получаем данные ответа
                                rdata = getattr(answer, 'rdata', None)
                                if isinstance(rdata, bytes):
                                    try:
                                        rdata = rdata.decode(errors='ignore')
                                    except Exception:
                                        rdata = str(rdata)
                                
                                # Специальная обработка для HTTPS записей
                                if type_str == "HTTPS":
                                    try:
                                        # Пытаемся извлечь данные из HTTPS записи
                                        https_data = []
                                        if hasattr(answer, 'svc_priority'):
                                            https_data.append(f"Priority: {answer.svc_priority}")
                                        if hasattr(answer, 'svc_target'):
                                            target = answer.svc_target.decode() if isinstance(answer.svc_target, bytes) else answer.svc_target
                                            https_data.append(f"Target: {target}")
                                        if hasattr(answer, 'svc_params'):
                                            https_data.append(f"Params: {answer.svc_params}")
                                        
                                        if https_data:
                                            rdata = ", ".join(https_data)
                                        else:
                                            rdata = "<HTTPS Data>"
                                    except Exception as e:
                                        self.logger.debug(f"Error parsing HTTPS record: {str(e)}")
                                        rdata = "<HTTPS Parsing Error>"
                                
                                # Специальная обработка для разных типов записей
                                elif type_str == "A" and rdata and self._is_valid_ipv4(rdata):
                                    # Сохраняем ассоциацию DNS <-> IP
                                    self._get_or_create_set(self.dns_associations, rdata).add(rrname)
                                    
                                    # Построение цепочки разрешений, если есть CNAME
                                    cname_chain = build_cname_chain(rrname)
                                    if len(cname_chain) > 1:
                                        chain_key = cname_chain[0]
                                        if chain_key not in resolution_chains:
                                            resolution_chains[chain_key] = {
                                                "chain": cname_chain,
                                                "resolved_ips": []
                                            }
                                        resolution_chains[chain_key]["resolved_ips"].append(rdata)
                                    
                                    # Проверяем IP из DNS-ответа на наличие в черных списках
                                    if self.check_blacklists and self.ip_blacklist and rdata not in self.ip_threat_info:
                                        self.ip_threat_info[rdata] = self.ip_blacklist.check_ip(rdata)
                                
                                elif type_str == "AAAA" and rdata:
                                    # Обработка IPv6 адресов
                                    self._get_or_create_set(self.dns_associations, rdata).add(rrname)
                                
                                # Добавляем запись в глобальную структуру
                                response_list.append({
                                    "name": rrname,
                                    "type": type_str,
                                    "ttl": ttl,
                                    "resolution": rdata if rdata else "<NO_DATA>",
                                    "timestamp": packet_time
                                })
                            except Exception as e:
                                self.logger.debug(f"Error processing DNS answer: {str(e)}")
                                continue
                        
                        # После обработки всех ответов добавляем цепочки разрешений, если они есть
                        if resolution_chains:
                            for chain_data in resolution_chains.values():
                                response_list.append({
                                    "name": chain_data["chain"][0],
                                    "type": "RESOLUTION_CHAIN",
                                    "ttl": 0,  # Для цепочек не устанавливаем TTL
                                    "chain": chain_data["chain"],
                                    "resolved_ips": chain_data["resolved_ips"],
                                    "timestamp": packet_time
                                })
        except Exception as e:
            self.logger.debug(f"Error handling DNS packet: {str(e)}")

    def extract_sni_scapy(self, pcap_file: str) -> None:
        """Извлекает SNI из TLS-пакетов."""
        try:
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    if TCP in pkt and pkt[TCP].dport == 443 and pkt.haslayer(Raw):
                        raw_payload = pkt[Raw].load
                        sni = self.extract_sni_from_tls(raw_payload)
                        if sni:
                            ip = self._normalize_ipv4(pkt[IP].dst) if IP in pkt else '<UNKNOWN>'
                            with self.data_lock:
                                self._get_or_create_set(self.sni_by_ip, ip).add(sni)
        except Exception:
            self.logger.exception("Error extracting SNI using Scapy.")

    def extract_sni_from_tls(self, data: bytes) -> Optional[str]:
        pos = 0
        while pos + 5 <= len(data):
            content_type = data[pos]
            rec_length = int.from_bytes(data[pos+3:pos+5], 'big')
            record_end = pos + 5 + rec_length
            if record_end > len(data):
                break
            if content_type != 22:
                pos = record_end
                continue
            handshake_pos = pos + 5
            while handshake_pos + 4 <= record_end:
                handshake_type = data[handshake_pos]
                handshake_length = int.from_bytes(data[handshake_pos+1:handshake_pos+4], 'big')
                handshake_end = handshake_pos + 4 + handshake_length
                if handshake_end > record_end:
                    break
                if handshake_type == 1:
                    client_hello = data[handshake_pos+4:handshake_end]
                    sni = self._parse_client_hello(client_hello)
                    if sni:
                        return sni
                handshake_pos = handshake_end
            pos = record_end
        return None

    def _parse_client_hello(self, client_hello: bytes) -> Optional[str]:
        pos = 0
        if len(client_hello) < 34:
            return None
        pos += 34
        if pos + 1 > len(client_hello):
            return None
        session_id_length = client_hello[pos]
        pos += 1 + session_id_length
        if pos + 2 > len(client_hello):
            return None
        cipher_suites_length = int.from_bytes(client_hello[pos:pos+2], 'big')
        pos += 2 + cipher_suites_length
        if pos + 1 > len(client_hello):
            return None
        comp_methods_length = client_hello[pos]
        pos += 1 + comp_methods_length
        if pos + 2 > len(client_hello):
            return None
        extensions_length = int.from_bytes(client_hello[pos:pos+2], 'big')
        pos += 2
        if pos + extensions_length > len(client_hello):
            return None
        end_ext = pos + extensions_length
        while pos + 4 <= end_ext:
            ext_type = int.from_bytes(client_hello[pos:pos+2], 'big')
            ext_length = int.from_bytes(client_hello[pos+2:pos+4], 'big')
            pos += 4
            if pos + ext_length > end_ext:
                break
            if ext_type == 0:
                inner_pos = pos + 2
                inner_end = pos + ext_length
                while inner_pos + 3 <= inner_end:
                    name_type = client_hello[inner_pos]
                    name_length = int.from_bytes(client_hello[inner_pos+1:inner_pos+3], 'big')
                    inner_pos += 3
                    if inner_pos + name_length <= inner_end and name_type == 0:
                        try:
                            return client_hello[inner_pos:inner_pos+name_length].decode('utf-8')
                        except UnicodeDecodeError:
                            return None
                    inner_pos += name_length
            pos += ext_length
        return None

    def _get_stream_id(self, pkt: Packet) -> Optional[Tuple[str, str, int, int]]:
        """
        Создает уникальный идентификатор для TCP потока на основе адресов и портов.
        
        Args:
            pkt: Scapy-пакет с TCP данными
            
        Returns:
            Tuple: (src_ip, dst_ip, src_port, dst_port) или None, если это не TCP пакет
        """
        if IP in pkt and TCP in pkt:
            src_ip = self._normalize_ipv4(pkt[IP].src)
            dst_ip = self._normalize_ipv4(pkt[IP].dst)
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            return (src_ip, dst_ip, src_port, dst_port)
        return None

    def _process_tcp_segment(self, pkt: Packet) -> Optional[bytes]:
        """
        Обрабатывает TCP сегмент, выполняя reassembly, если включен.
        
        Args:
            pkt: Scapy-пакет с TCP данными
            
        Returns:
            Optional[bytes]: Собранные данные TCP потока или None
        """
        if not self.enable_tcp_reassembly or not (IP in pkt and TCP in pkt):
            # Если reassembly отключен или это не TCP пакет, просто возвращаем полезную нагрузку
            return pkt[Raw].load if pkt.haslayer(Raw) else None
        
        # Получаем идентификатор потока
        stream_id = self._get_stream_id(pkt)
        if not stream_id:
            return None
        
        # Если нет полезной нагрузки, нечего обрабатывать
        if not pkt.haslayer(Raw):
            return None
        
        tcp_flags = pkt[TCP].flags
        seq_num = pkt[TCP].seq
        payload = pkt[Raw].load
        
        # Обрабатываем с блокировкой, так как этот код может выполняться параллельно
        with self.tcp_streams_lock:
            # Новое соединение (SYN)
            if tcp_flags & 0x02:  # SYN flag
                self.tcp_streams[stream_id] = []
                self.tcp_buffer[stream_id] = b''
                self.tcp_seq_expect[stream_id] = seq_num + 1  # Следующий ожидаемый seq после SYN
                return None
            
            # FIN или RST - завершение соединения
            if tcp_flags & 0x01 or tcp_flags & 0x04:  # FIN or RST
                # Возвращаем собранные данные и очищаем буфер для экономии памяти
                data = self.tcp_buffer.pop(stream_id, b'')
                self.tcp_streams.pop(stream_id, None)
                self.tcp_seq_expect.pop(stream_id, None)
                return data if data else None
            
            # Обычный пакет с данными
            if stream_id not in self.tcp_streams:
                # Пакет из неизвестного потока - создаем новый
                self.tcp_streams[stream_id] = [(seq_num, payload)]
                self.tcp_buffer[stream_id] = payload
                self.tcp_seq_expect[stream_id] = seq_num + len(payload)
                return payload
            
            # Известный поток - добавляем сегмент в правильном порядке
            segments = self.tcp_streams[stream_id]
            expected_seq = self.tcp_seq_expect.get(stream_id)
            
            # Пропускаем повторные пакеты
            if expected_seq and seq_num < expected_seq:
                return None
            
            # Добавляем новый сегмент в отсортированный список
            segments.append((seq_num, payload))
            segments.sort(key=lambda x: x[0])  # Сортируем по seq
            
            # Собираем непрерывные сегменты в буфер
            reassembled = b''
            next_seq = expected_seq if expected_seq else seq_num
            
            for seg_seq, seg_payload in segments[:]:
                if seg_seq == next_seq:
                    reassembled += seg_payload
                    next_seq += len(seg_payload)
                    segments.remove((seg_seq, seg_payload))
            
            # Обновляем буфер и ожидаемый seq
            if reassembled:
                self.tcp_buffer[stream_id] += reassembled
                self.tcp_seq_expect[stream_id] = next_seq
                
                # Проверяем превышение размера буфера
                if len(self.tcp_buffer[stream_id]) > self.max_tcp_buffer_size:
                    data = self.tcp_buffer[stream_id]
                    self.tcp_buffer[stream_id] = b''
                    return data
            
            # Возвращаем буфер только если получили много данных
            # или это последние данные в соединении
            if len(self.tcp_buffer[stream_id]) > 1024 or tcp_flags & 0x10:  # PSH flag
                data = self.tcp_buffer[stream_id]
                self.tcp_buffer[stream_id] = b''
                return data
            
            return None
        
    def process_packets(self, packets: List[Packet],
                        filters: Optional[Callable[[Packet], bool]] = None) -> None:
        # Используем локальную структуру для сбора статистики в этом потоке
        local_stats = {
            "total_packets": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "http_count": 0,
            "https_count": 0,
            "dns_count": 0,
            "other_count": 0,
            "total_bytes": 0
        }
        
        # Локальные структуры для потокобезопасной обработки
        local_ip_connections = defaultdict(set)
        local_ip_reverse_connections = defaultdict(set)
        local_sni_by_ip = defaultdict(set)
        local_http_domains = defaultdict(set)
        local_http_requests = defaultdict(list)
        local_http_responses = defaultdict(list)
        local_dns_queries = defaultdict(lambda: defaultdict(set))
        local_dns_responses = defaultdict(list)
        local_output_data = defaultdict(lambda: defaultdict(int))
        local_first_seen = {}
        local_last_seen = {}
        local_connection_initiators: Dict[Tuple[str, str], str] = {}
        
        for pkt in packets:
            try:
                local_stats["total_packets"] += 1
                local_stats["total_bytes"] += len(pkt)
                
                # Применяем фильтр, если он указан
                if filters and not filters(pkt):
                    continue
                    
                # Записываем временные метки
                packet_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()
                
                if IP in pkt:
                    ip_src = self._normalize_ipv4(pkt[IP].src)
                    ip_dst = self._normalize_ipv4(pkt[IP].dst)

                    if ip_src and ip_dst and ip_src != ip_dst:
                        conn_key = tuple(sorted((ip_src, ip_dst)))
                        if conn_key not in local_connection_initiators:
                            local_connection_initiators[conn_key] = ip_src
                    
                    # Обновляем временные метки для IP
                    for ip in [ip_src, ip_dst]:
                        if ip not in local_first_seen:
                            local_first_seen[ip] = packet_time
                        local_last_seen[ip] = packet_time
                    
                    # Проверяем IP на наличие в черных списках
                    if self.check_blacklists and self.ip_blacklist:
                        with self.ip_lock:
                            if ip_src not in self.ip_threat_info:
                                self.ip_threat_info[ip_src] = self.ip_blacklist.check_ip(ip_src)
                            if ip_dst not in self.ip_threat_info:
                                self.ip_threat_info[ip_dst] = self.ip_blacklist.check_ip(ip_dst)
                    
                    # Обновляем связи между IP адресами
                    local_ip_connections[ip_src].add(ip_dst)
                    local_ip_reverse_connections[ip_dst].add(ip_src)
                    
                    # Обновляем статистику
                    local_output_data[ip_src]["packets_out"] += 1
                    local_output_data[ip_src]["bytes_out"] += len(pkt)
                    local_output_data[ip_dst]["packets_in"] += 1
                    local_output_data[ip_dst]["bytes_in"] += len(pkt)
                    
                    protocol_detected = False
                    
                    if TCP in pkt:
                        local_stats["tcp_count"] += 1
                        local_output_data[ip_src]["tcp_count"] += 1
                        local_output_data[ip_dst]["tcp_count"] += 1
                        
                        protocol_detected = True
                        
                        # Обработка TCP с reassembly
                        if pkt.haslayer(Raw):
                            tcp_data = self._process_tcp_segment(pkt)
                            
                            if tcp_data:
                                # Обработка HTTP (запросы: dport=80, ответы: sport=80)
                                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                                if sport == 80 or dport == 80:
                                    local_stats["http_count"] += 1
                                    local_output_data[ip_src]["http_count"] += 1
                                    local_output_data[ip_dst]["http_count"] += 1
                                    
                                    try:
                                        # Декодируем bytes в строку перед обработкой HTTP
                                        try:
                                            # Сначала пробуем декодировать как UTF-8 (наиболее распространенная кодировка)
                                            tcp_data_str = tcp_data.decode('utf-8')
                                        except UnicodeDecodeError:
                                            # Если не получается, используем latin-1, который может декодировать любые байты
                                            tcp_data_str = tcp_data.decode('latin-1')
                                        
                                        self.parse_and_process_http(tcp_data_str, ip_src, ip_dst, pkt, local_http_domains, local_http_requests, local_http_responses)
                                    except Exception as e:
                                        self.logger.debug(f"Error processing HTTP content: {str(e)}")
                                
                                # Проверяем TLS-рукопожатие (на любом порту)
                                self.handle_tls_pkt(pkt)
                        
                    elif UDP in pkt:
                        local_stats["udp_count"] += 1
                        local_output_data[ip_src]["udp_count"] += 1
                        local_output_data[ip_dst]["udp_count"] += 1
                        
                        protocol_detected = True
                    
                    if ICMP in pkt:
                        local_stats["icmp_count"] += 1
                        local_output_data[ip_src]["icmp_count"] += 1
                        local_output_data[ip_dst]["icmp_count"] += 1
                    
                    if DNS in pkt:
                        local_stats["dns_count"] += 1
                        local_output_data[ip_src]["dns_count"] += 1
                        local_output_data[ip_dst]["dns_count"] += 1
                        
                        protocol_detected = True
                        self.handle_dns_pkt(pkt, local_dns_queries, local_dns_responses)
                    
                    # Если ни один из известных протоколов не обнаружен, считаем как прочее
                    if not protocol_detected:
                        local_stats["other_count"] += 1
                        local_output_data[ip_src]["other_count"] += 1
                        local_output_data[ip_dst]["other_count"] += 1
            
            except Exception as e:
                self.logger.debug(f"Error processing packet: {str(e)}")
                continue
        
        # В конце обработки пакетов объединяем локальные данные с глобальными
        with self.stats_lock:
            for key, value in local_stats.items():
                self.packet_statistics[key] = self.packet_statistics.get(key, 0) + value
        
        with self.ip_lock:
            self.ip_list_conn.update(local_first_seen.keys())
            
            for ip_src, destinations in local_ip_connections.items():
                if ip_src not in self.ip_connections:
                    self.ip_connections[ip_src] = set()
                self.ip_connections[ip_src].update(destinations)
            
            for ip_dst, sources in local_ip_reverse_connections.items():
                if ip_dst not in self.ip_reverse_connections:
                    self.ip_reverse_connections[ip_dst] = set()
                self.ip_reverse_connections[ip_dst].update(sources)

            for conn_key, initiator in local_connection_initiators.items():
                if conn_key not in self.connection_initiators:
                    self.connection_initiators[conn_key] = initiator
            
            for ip, first_time in local_first_seen.items():
                if ip not in self.first_seen or first_time < self.first_seen[ip]:
                    self.first_seen[ip] = first_time
            
            for ip, last_time in local_last_seen.items():
                if ip not in self.last_seen or last_time > self.last_seen[ip]:
                    self.last_seen[ip] = last_time
            
            for ip, stats in local_output_data.items():
                if ip not in self.output_data:
                    self.output_data[ip] = {}
                for stat_name, stat_value in stats.items():
                    self.output_data[ip][stat_name] = self.output_data[ip].get(stat_name, 0) + stat_value
        
        with self.sni_lock:
            for ip, sni_set in local_sni_by_ip.items():
                if ip not in self.sni_by_ip:
                    self.sni_by_ip[ip] = set()
                self.sni_by_ip[ip].update(sni_set)
        
        with self.http_lock:
            for ip, domains in local_http_domains.items():
                if ip not in self.http_domains:
                    self.http_domains[ip] = set()
                self.http_domains[ip].update(domains)
            
            for ip, requests in local_http_requests.items():
                if ip not in self.http_requests:
                    self.http_requests[ip] = []
                self.http_requests[ip].extend(requests)
                
            for ip, responses in local_http_responses.items():
                if ip not in self.http_responses:
                    self.http_responses[ip] = []
                self.http_responses[ip].extend(responses)
        
        with self.dns_lock:
            for src_ip, server_dict in local_dns_queries.items():
                if src_ip not in self.dns_queries_by_server:
                    self.dns_queries_by_server[src_ip] = {}
                
                for dst_ip, queries in server_dict.items():
                    if dst_ip not in self.dns_queries_by_server[src_ip]:
                        self.dns_queries_by_server[src_ip][dst_ip] = set()
                    self.dns_queries_by_server[src_ip][dst_ip].update(queries)
            
            for server_ip, responses in local_dns_responses.items():
                if server_ip not in self.dns_response_table:
                    self.dns_response_table[server_ip] = []
                self.dns_response_table[server_ip].extend(responses)

    def process_in_parallel(self, pcap_file: str,
                           num_threads: int = 4,
                           filters: Optional[Callable[[Packet], bool]] = None) -> None:
        def packet_iterator() -> Generator[Packet, None, None]:
            try:
                with PcapReader(pcap_file) as reader:
                    for pkt in reader:
                        yield pkt
            except FileNotFoundError as e:
                raise PCAPFileError(f"PCAP file not found: {pcap_file}") from e
            except Exception as e:
                raise PacketProcessingError(f"Error reading PCAP file: {str(e)}") from e

        chunk_size = 1000
        futures = []
        chunk: List[Packet] = []
        self.logger.info(f"[*] Используется {num_threads} потоков для обработки")
        executor = ThreadPoolExecutor(max_workers=num_threads)
        try:
            for packet in tqdm(packet_iterator(), desc="Reading packets", unit="pkt"):
                chunk.append(packet)
                if len(chunk) >= chunk_size:
                    futures.append(executor.submit(self.process_packets, chunk, filters))
                    chunk = []
            if chunk:
                futures.append(executor.submit(self.process_packets, chunk, filters))
            for future in futures:
                future.result()
        except Exception as e:
            self.logger.error(f"Error in parallel processing: {str(e)}")
            raise
        finally:
            executor.shutdown()

    def analyze(self, pcap_file: str,
                filters: Optional[Callable[[Packet], bool]] = None,
                num_threads: int = 4) -> Dict[str, Any]:
        self.logger.info("[*] Starting PCAP analysis...")
        try:
            self.process_in_parallel(pcap_file, num_threads=num_threads, filters=filters)
            return self.output_data
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            raise

    def get_dict(self) -> Dict[str, Any]:
        """
        Формирует итоговый словарь с данными по IP.
        Включает временные метки, TLS-информацию и расширенные данные.
        """
        try:
            ip_dns_sni_map: Dict[str, Any] = {}
            
            # Получаем все IP с блокировкой для наилучшей потокобезопасности
            with self.ip_lock:
                ips = sorted(list(self.ip_list_conn), key=self._ip_sort_key)
            
            # Предварительная обработка данных
            for ip in ips:
                ip_norm = self._normalize_ipv4(ip)
                
                # Безопасно извлекаем данные из разных структур с соответствующими блокировками
                with self.dns_lock:
                    dns_assocs = sorted([d.rstrip('.') for d in self.dns_associations.get(ip_norm, [])])
                    dns_queries = self.dns_queries_by_server.get(ip_norm, {})
                    dns_resps = self.dns_response_table.get(ip_norm, [])
                
                with self.sni_lock:
                    sni_records = sorted(list(self.sni_by_ip.get(ip_norm, [])))
                
                with self.http_lock:
                    http_hosts = sorted(list(self.http_domains.get(ip_norm, [])))
                    http_reqs = self.http_requests.get(ip_norm, [])
                    http_resps = self.http_responses.get(ip_norm, [])
                
                with self.ip_lock:
                    raw_stats = dict(self.output_data.get(ip_norm, {}))
                    first_seen_timestamp = self.first_seen.get(ip_norm)
                    last_seen_timestamp = self.last_seen.get(ip_norm)
                    
                    # Получаем информацию о угрозе для IP
                    is_blacklisted, threat_score = False, 0
                    if self.check_blacklists:
                        is_blacklisted, threat_score = self.ip_threat_info.get(ip_norm, (False, 0))
                    
                    # Получаем связи с другими IP
                    outgoing_candidates = set(self.ip_connections.get(ip_norm, set()))
                    incoming_candidates = set(self.ip_reverse_connections.get(ip_norm, set()))
                    peer_ips = outgoing_candidates.union(incoming_candidates)
                    outgoing_connections = []
                    incoming_connections = []
                    for peer_ip in sorted(peer_ips, key=self._ip_sort_key):
                        if peer_ip == ip_norm:
                            continue
                        conn_key = tuple(sorted((ip_norm, peer_ip)))
                        initiator = self.connection_initiators.get(conn_key)
                        if initiator == ip_norm:
                            outgoing_connections.append(peer_ip)
                        elif initiator:
                            incoming_connections.append(peer_ip)
                        else:
                            if peer_ip in outgoing_candidates and peer_ip not in incoming_candidates:
                                outgoing_connections.append(peer_ip)
                            elif peer_ip in incoming_candidates and peer_ip not in outgoing_candidates:
                                incoming_connections.append(peer_ip)
                            else:
                                outgoing_connections.append(peer_ip)
                
                # Получение TLS информации (JA3, ALPN, и т.д.)
                with self.tls_lock:
                    tls_info_records = self.tls_info.get(ip_norm, [])
                
                # Обработка DNS ответов с агрегацией
                dns_aggregated = {}
                dns_chains = []
                
                for resp in dns_resps:
                    # Обработка цепочек разрешения DNS
                    if resp.get("type") == "RESOLUTION_CHAIN":
                        dns_chains.append({
                            "timestamp": resp.get("timestamp"),
                            "domain": resp.get("name", ""),
                            "chain": resp.get("chain", []),
                            "resolved_ips": resp.get("resolved_ips", [])
                        })
                        continue
                    
                    # Обычные DNS-ответы
                    name = resp.get("name", "").rstrip('.')
                    type_str = resp.get("type", "")
                    resolution = resp.get("resolution", "")
                    ttl = resp.get("ttl", 0)
                    timestamp = resp.get("timestamp")
                    
                    if type_str != "A" and isinstance(resolution, str):
                        resolution = resolution.rstrip('.')
                    
                    key = (name, type_str)
                    if key in dns_aggregated:
                        current = dns_aggregated[key]
                        
                        # Обновляем список разрешений
                        new_vals = [x.strip() for x in resolution.split(",") if x.strip()]
                        current["resolutions"].update(new_vals)
                        
                        # Обновляем timestamp, если нужно
                        if timestamp and (current["timestamp"] is None or timestamp > current["timestamp"]):
                            current["timestamp"] = timestamp
                            
                        # Обновляем TTL, выбирая минимальное значение, если оно не ноль
                        if ttl > 0 and (current["ttl"] == 0 or ttl < current["ttl"]):
                            current["ttl"] = ttl
                    else:
                        new_vals = set(x.strip() for x in resolution.split(",") if x.strip())
                        dns_aggregated[key] = {
                            "resolutions": new_vals,
                            "ttl": ttl,
                            "timestamp": timestamp
                        }
                
                # Преобразуем агрегированные DNS-ответы в список
                dns_responses_list = [
                    {
                        "name": name,
                        "type": type_str,
                        "resolution": ", ".join(sorted(data["resolutions"])),
                        "ttl": data["ttl"],
                        "timestamp": data["timestamp"]
                    }
                    for (name, type_str), data in dns_aggregated.items()
                ]
                
                # Сортируем DNS-ответы по имени и типу
                dns_responses_list.sort(key=lambda x: (x["name"], x["type"]))
                
                # Агрегируем TLS данные
                tls_summary = None
                if tls_info_records:
                    # Собираем уникальные значения
                    unique_ja3 = set()
                    unique_tls_versions = set()
                    unique_alpn = set()
                    cipher_counts = defaultdict(int)
                    
                    for record in tls_info_records:
                        if record.get("ja3_hash"):
                            unique_ja3.add(record["ja3_hash"])
                        if record.get("tls_version"):
                            unique_tls_versions.add(record["tls_version"])
                        if record.get("alpn_protocols"):
                            unique_alpn.update(record["alpn_protocols"])
                        for cipher in record.get("cipher_suites", []):
                            cipher_counts[cipher] += 1
                    
                    # Формируем сводную информацию
                    top_ciphers = sorted(cipher_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                    
                    tls_summary = {
                        "ja3_hashes": sorted(unique_ja3),
                        "tls_versions": sorted(unique_tls_versions),
                        "alpn_protocols": sorted(unique_alpn),
                        "top_cipher_suites": [{"cipher": cipher, "count": count} for cipher, count in top_ciphers]
                    }
                
                # Обработка HTTP запросов с группировкой по доменам
                unique_http_reqs = {}
                for req in http_reqs:
                    # Создаем строковое представление запроса вместо использования кортежа словарей
                    key_parts = []
                    for k, v in sorted(req.items()):
                        if v and k not in ["timestamp"]:
                            # Преобразуем любые словари в строки для возможности хеширования
                            if isinstance(v, dict):
                                v_str = json.dumps(v, sort_keys=True)
                                key_parts.append(f"{k}:{v_str}")
                            else:
                                key_parts.append(f"{k}:{v}")
                    key = tuple(key_parts)
                    unique_http_reqs.setdefault(key, req)
                unique_http_reqs_list = list(unique_http_reqs.values())
                
                # Обработка HTTP ответов
                unique_http_resps = {}
                for resp in http_resps:
                    # Аналогично запросам, создаем строковое представление ответа
                    key_parts = []
                    for k, v in sorted(resp.items()):
                        if v and k not in ["timestamp"]:
                            # Преобразуем любые словари в строки
                            if isinstance(v, dict):
                                v_str = json.dumps(v, sort_keys=True)
                                key_parts.append(f"{k}:{v_str}")
                            else:
                                key_parts.append(f"{k}:{v}")
                    key = tuple(key_parts)
                    unique_http_resps.setdefault(key, resp)
                unique_http_resps_list = list(unique_http_resps.values())
                
                # Группируем HTTP запросы и ответы по доменам для удобства анализа
                http_by_domain = defaultdict(lambda: {"requests": [], "responses": []})
                
                for req in unique_http_reqs_list:
                    host = req.get("host", "unknown")
                    http_by_domain[host]["requests"].append(req)
                
                for resp in unique_http_resps_list:
                    # HTTP-ответы не содержат Host (это заголовок запроса).
                    # Берём первый домен IP-сервера, если есть, иначе "unknown"
                    if resp.get("headers", {}).get("host"):
                        host = resp["headers"]["host"]
                    elif http_hosts:
                        host = http_hosts[0]
                    else:
                        host = "unknown"
                    http_by_domain[host]["responses"].append(resp)

                # Получение ASN
                try:
                    asn = self.asn_database.lookup_asn(ip_norm)
                except Exception as e:
                    self.logger.warning(f"Failed to get ASN for IP {ip_norm}: {str(e)}")
                    asn = '<NOT FOUND>'

                # Форматирование временных меток
                first_seen_str, last_seen_str = None, None
                if first_seen_timestamp:
                    first_seen_str = datetime.datetime.fromtimestamp(first_seen_timestamp).strftime("%Y-%m-%d %H:%M:%S")
                if last_seen_timestamp:
                    last_seen_str = datetime.datetime.fromtimestamp(last_seen_timestamp).strftime("%Y-%m-%d %H:%M:%S")
                
                # Формирование итоговых данных
                ip_data = {
                    "ASN": asn,
                    "First Seen": first_seen_str,
                    "Last Seen": last_seen_str,
                    "DNS Associations": dns_assocs,
                    "DNS Resolution Chains": dns_chains if dns_chains else None,
                    "SNI Records": sni_records,
                    "HTTP Domains": http_hosts,
                    "HTTP By Domain": http_by_domain,
                    "HTTP Requests": unique_http_reqs_list,
                    "HTTP Responses": unique_http_resps_list,
                    "Traffic": raw_stats,
                    "TLS Info": tls_summary,
                    "Connections": {
                        "Outgoing": outgoing_connections,
                        "Incoming": incoming_connections
                    }
                }
                
                # Добавляем информацию о наличии в черных списках
                if self.check_blacklists:
                    threat_info = {
                        "is_blacklisted": is_blacklisted,
                        "threat_score": threat_score,
                    }
                    if is_blacklisted and self.ip_blacklist:
                        threat_info["threat_level"] = self.ip_blacklist.get_threat_level(threat_score)
                    ip_data["Threat Info"] = threat_info
                
                # Добавляем DNS информацию
                if dns_responses_list:
                    ip_data["DNS Responses"] = dns_responses_list
                
                if dns_queries:
                    ip_data["DNS Queries by Server"] = {
                        server_ip.rstrip('.'): sorted([q.rstrip('.') for q in queries])
                        for server_ip, queries in dns_queries.items()
                    }
                
                ip_dns_sni_map[ip_norm] = ip_data

            # Добавляем информацию о угрозе для IP-адресов из DNS-ответов, 
            # которые могут не встречаться в сетевом трафике напрямую
            if self.check_blacklists and self.ip_blacklist:
                with self.ip_lock:
                    for ip, (is_blacklisted, threat_score) in self.ip_threat_info.items():
                        if ip not in ip_dns_sni_map and is_blacklisted and self._is_valid_ipv4(ip):
                            # Добавляем информацию о IP только если он находится в черном списке
                            ip_data = {
                                "ASN": "<NOT FOUND>",
                                "DNS Associations": [],
                                "SNI Records": [],
                                "HTTP Domains": [],
                                "HTTP Requests": [],
                                "Traffic": {},
                                "Connections": {
                                    "Outgoing": [],
                                    "Incoming": []
                                },
                                "Threat Info": {
                                    "is_blacklisted": is_blacklisted,
                                    "threat_score": threat_score,
                                    "threat_level": self.ip_blacklist.get_threat_level(threat_score)
                                }
                            }
                            # Пытаемся получить ASN
                            try:
                                ip_data["ASN"] = self.asn_database.lookup_asn(ip)
                            except Exception:
                                pass
                            
                            ip_dns_sni_map[ip] = ip_data
            
            # Добавляем общую статистику пакетов
            with self.stats_lock:
                ip_dns_sni_map["Overall Packet Statistics"] = dict(self.packet_statistics)
            
            return ip_dns_sni_map
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
