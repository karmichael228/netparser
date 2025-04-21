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
    
    def __init__(self, cache_dir: Optional[str] = None):
        self.logger = Logger.setup_logger()
        self.blacklist: Dict[str, int] = {}
        self.lock = threading.Lock()
        self.last_update = 0
        self.cache_dir = cache_dir or tempfile.gettempdir()
        self.cache_file = os.path.join(self.cache_dir, "ipsum_blacklist.txt")
        self._load_blacklist()
    
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
        self.data_lock = threading.Lock()
        self.dns_queries_by_server: Dict[str, Dict[str, Set[str]]] = {}
        self.dns_response_table: Dict[str, List[Dict[str, Any]]] = {}
        self.check_blacklists = check_blacklists
        self.ip_blacklist = IpsumBlacklist() if check_blacklists else None
        self.ip_threat_info: Dict[str, Tuple[bool, int]] = {}  # Информация о угрозе {ip: (в_черном_списке, счетчик)}
        # Связи между IP адресами (src -> dst)
        self.ip_connections: Dict[str, Set[str]] = {}
        # Обратные связи (dst -> src)
        self.ip_reverse_connections: Dict[str, Set[str]] = {}

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

    def parse_http_request(self, payload: str) -> Optional[Dict[str, str]]:
        """Парсит HTTP запрос из полезной нагрузки."""
        try:
            lines = payload.splitlines()
            if not lines:
                return None
            request_line_pattern = re.compile(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)\s+(HTTP/\d\.\d)")
            match = request_line_pattern.match(lines[0])
            if not match:
                return None
            http_data = {
                "method": match.group(1),
                "uri": match.group(2),
                "version": match.group(3),
                "host": "",
                "user_agent": ""
            }
            for line in lines[1:]:
                if ':' not in line:
                    continue
                header, value = line.split(":", 1)
                header = header.strip().lower()
                value = value.strip()
                if header == "host":
                    http_data["host"] = value
                elif header == "user-agent":
                    http_data["user_agent"] = value
            return http_data
        except Exception as e:
            self.logger.debug(f"Error parsing HTTP request: {str(e)}")
            return None

    def handle_tls_pkt(self, pkt: Packet) -> None:
        """Обрабатывает TLS пакет и извлекает SNI, независимо от порта."""
        try:
            if TCP in pkt and pkt.haslayer(Raw):
                raw_payload = pkt[Raw].load
                sni = self.extract_sni_from_tls(raw_payload)
                if sni:
                    ip = self._normalize_ipv4(pkt[IP].dst) if IP in pkt else '<UNKNOWN>'
                    with self.data_lock:
                        self._get_or_create_set(self.sni_by_ip, ip).add(sni)
                        # Обновляем счетчик HTTPS пакетов
                        self.packet_statistics["https_count"] += 1
                        src_stats = self._get_or_create_int_dict(self.output_data, self._normalize_ipv4(pkt[IP].src))
                        dst_stats = self._get_or_create_int_dict(self.output_data, ip)
                        src_stats["https_count"] = src_stats.get("https_count", 0) + 1
                        dst_stats["https_count"] = dst_stats.get("https_count", 0) + 1
        except Exception as e:
            self.logger.debug(f"Error processing TLS packet: {str(e)}")

    def handle_dns_pkt(self, pkt: Packet) -> None:
        """Обрабатывает DNS пакет, аккумулируя запросы и ответы."""
        if UDP in pkt and (pkt[UDP].sport == 5353 or pkt[UDP].dport == 5353):
            return

        dns_layer = pkt.getlayer(DNS)
        if not dns_layer:
            return

        try:
            ip_src = self._normalize_ipv4(pkt[IP].src) if IP in pkt else '<UNKNOWN>'
            ip_dst = self._normalize_ipv4(pkt[IP].dst) if IP in pkt else '<UNKNOWN>'

            # Обработка DNS запросов
            if dns_layer.qdcount and dns_layer.qd:
                queries = dns_layer.qd if isinstance(dns_layer.qd, list) else [dns_layer.qd]
                with self.data_lock:
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
                with self.data_lock:
                    response_list = self._get_or_create_list(self.dns_response_table, dns_server_ip)
                    for answer in answers:
                        try:
                            rrname = (answer.rrname.decode() if isinstance(answer.rrname, bytes)
                                    else answer.rrname).rstrip('.') if answer.rrname else '<UNKNOWN>'
                            rdata = answer.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode(errors='ignore')
                            
                            ans_type = getattr(answer, 'type', 'UNKNOWN')
                            type_str = DNS_TYPE_MAP.get(ans_type, str(ans_type))
                            
                            # Специальная обработка для разных типов записей
                            if type_str == "A" and rdata and self._is_valid_ipv4(rdata):
                                self._get_or_create_set(self.dns_associations, rdata).add(rrname)
                                
                                # Проверяем IP из DNS-ответа на наличие в черных списках
                                if self.check_blacklists and self.ip_blacklist and rdata not in self.ip_threat_info:
                                    self.ip_threat_info[rdata] = self.ip_blacklist.check_ip(rdata)
                                
                            elif type_str == "AAAA" and rdata:
                                # Обработка IPv6 адресов
                                self._get_or_create_set(self.dns_associations, rdata).add(rrname)
                            elif type_str == "CNAME" and rdata:
                                # Обработка CNAME записей
                                rdata = rdata.rstrip('.')
                            elif type_str == "MX" and rdata:
                                # Обработка MX записей
                                try:
                                    priority, server = rdata.split(' ', 1)
                                    rdata = f"Priority: {priority}, Server: {server.rstrip('.')}"
                                except ValueError:
                                    rdata = rdata.rstrip('.')
                            elif type_str == "TXT" and rdata:
                                # Обработка TXT записей
                                rdata = rdata.strip('"')
                            elif type_str == "SRV" and rdata:
                                # Обработка SRV записей
                                try:
                                    priority, weight, port, target = rdata.split(' ', 3)
                                    rdata = f"Priority: {priority}, Weight: {weight}, Port: {port}, Target: {target.rstrip('.')}"
                                except ValueError:
                                    rdata = rdata.rstrip('.')
                            elif type_str == "SOA" and rdata:
                                # Обработка SOA записей
                                try:
                                    mname, rname, serial, refresh, retry, expire, minimum = rdata.split(' ', 6)
                                    rdata = f"MNAME: {mname.rstrip('.')}, RNAME: {rname}, SERIAL: {serial}"
                                except ValueError:
                                    rdata = rdata.rstrip('.')
                            
                            response_list.append({
                                "name": rrname,
                                "type": type_str,
                                "resolution": rdata if rdata else "<NO_DATA>"
                            })
                        except Exception as e:
                            self.logger.debug(f"Error processing DNS answer: {str(e)}")
                            continue
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

    def process_packets(self, packets: List[Packet],
                        filters: Optional[Callable[[Packet], bool]] = None) -> None:
        for pkt in packets:
            try:
                with self.data_lock:
                    self.packet_statistics["total_packets"] += 1
                    self.packet_statistics["total_bytes"] += len(pkt)
                if filters and not filters(pkt):
                    continue
                if IP in pkt:
                    ip_src = self._normalize_ipv4(pkt[IP].src)
                    ip_dst = self._normalize_ipv4(pkt[IP].dst)
                    
                    # Проверяем IP на наличие в черных списках
                    if self.check_blacklists and self.ip_blacklist:
                        with self.data_lock:
                            if ip_src not in self.ip_threat_info:
                                self.ip_threat_info[ip_src] = self.ip_blacklist.check_ip(ip_src)
                            if ip_dst not in self.ip_threat_info:
                                self.ip_threat_info[ip_dst] = self.ip_blacklist.check_ip(ip_dst)
                    
                    with self.data_lock:
                        self.ip_list_conn.update([ip_src, ip_dst])
                        
                        # Обновляем связи между IP адресами
                        self._get_or_create_set(self.ip_connections, ip_src).add(ip_dst)
                        self._get_or_create_set(self.ip_reverse_connections, ip_dst).add(ip_src)
                        
                        src_stats = self._get_or_create_int_dict(self.output_data, ip_src)
                        dst_stats = self._get_or_create_int_dict(self.output_data, ip_dst)
                        src_stats["packets_out"] = src_stats.get("packets_out", 0) + 1
                        src_stats["bytes_out"] = src_stats.get("bytes_out", 0) + len(pkt)
                        dst_stats["packets_in"] = dst_stats.get("packets_in", 0) + 1
                        dst_stats["bytes_in"] = dst_stats.get("bytes_in", 0) + len(pkt)
                    
                    protocol_detected = False
                    
                    if TCP in pkt:
                        with self.data_lock:
                            self.packet_statistics["tcp_count"] += 1
                            src_stats["tcp_count"] = src_stats.get("tcp_count", 0) + 1
                            dst_stats["tcp_count"] = dst_stats.get("tcp_count", 0) + 1
                        
                        protocol_detected = True
                        
                        if pkt[TCP].dport == 80 and pkt.haslayer(Raw):
                            with self.data_lock:
                                self.packet_statistics["http_count"] += 1
                                src_stats["http_count"] = src_stats.get("http_count", 0) + 1
                                dst_stats["http_count"] = dst_stats.get("http_count", 0) + 1
                            try:
                                raw_payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                                # Улучшенный парсинг HTTP запросов
                                self.parse_and_process_http(raw_payload, ip_src, ip_dst, pkt)
                            except Exception as e:
                                self.logger.debug(f"Error processing HTTP request: {str(e)}")
                        
                        # Проверяем TLS-рукопожатие на любом порту
                        if pkt.haslayer(Raw):
                            self.handle_tls_pkt(pkt)
                    
                    elif UDP in pkt:
                        with self.data_lock:
                            self.packet_statistics["udp_count"] += 1
                            src_stats["udp_count"] = src_stats.get("udp_count", 0) + 1
                            dst_stats["udp_count"] = dst_stats.get("udp_count", 0) + 1
                        
                        protocol_detected = True
                        
                        if ICMP in pkt:
                            with self.data_lock:
                                self.packet_statistics["icmp_count"] += 1
                                src_stats["icmp_count"] = src_stats.get("icmp_count", 0) + 1
                                dst_stats["icmp_count"] = dst_stats.get("icmp_count", 0) + 1
                    
                    if DNS in pkt:
                        with self.data_lock:
                            self.packet_statistics["dns_count"] += 1
                            src_stats["dns_count"] = src_stats.get("dns_count", 0) + 1
                            dst_stats["dns_count"] = dst_stats.get("dns_count", 0) + 1
                        
                        protocol_detected = True
                        self.handle_dns_pkt(pkt)
                    
                    # Если ни один из известных протоколов не обнаружен, считаем как other
                    if not protocol_detected:
                        with self.data_lock:
                            self.packet_statistics["other_count"] += 1
                            src_stats["other_count"] = src_stats.get("other_count", 0) + 1
                            dst_stats["other_count"] = dst_stats.get("other_count", 0) + 1
            
            except Exception as e:
                self.logger.debug(f"Error processing packet: {str(e)}")
                continue

    def parse_and_process_http(self, payload: str, ip_src: str, ip_dst: str, pkt: Packet) -> None:
        """Расширенный парсинг HTTP-запросов с детальным анализом заголовков и содержимого."""
        try:
            lines = payload.splitlines()
            if not lines:
                return None
            
            # Улучшенное регулярное выражение для REQUEST LINE
            request_line_pattern = re.compile(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+(HTTP/\d\.\d)")
            match = request_line_pattern.match(lines[0])
            
            if match:
                # Это HTTP запрос
                http_data = {
                    "method": match.group(1),
                    "uri": match.group(2),
                    "version": match.group(3),
                    "host": "",
                    "user_agent": "",
                    "content_type": "",
                    "content_length": "",
                    "referer": "",
                    "cookies": "",
                    "authorization": "",
                    "origin": "",
                    "x_requested_with": ""
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
                    except ValueError:
                        pass
                
                # Сохраняем HTTP запрос
                with self.data_lock:
                    if http_data["host"]:
                        self._get_or_create_set(self.http_domains, ip_dst).add(http_data["host"])
                    self._get_or_create_list(self.http_requests, ip_dst).append(http_data)
            
            # Проверяем, не является ли это HTTP ответом
            response_line_pattern = re.compile(r"^(HTTP/\d\.\d)\s+(\d+)\s+(.+)$")
            match = response_line_pattern.match(lines[0])
            
            if match and not http_data.get("method"):
                # Это HTTP ответ, можно также обрабатывать их при необходимости
                pass
                
        except Exception as e:
            self.logger.debug(f"Error in parse_and_process_http: {str(e)}")
            return None

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
        Оптимизированная версия с предварительной сортировкой и кэшированием.
        """
        try:
            ip_dns_sni_map: Dict[str, Any] = {}
            with self.data_lock:
                ips = sorted(list(self.ip_list_conn), key=self._ip_sort_key)
            
            # Предварительная обработка данных
            for ip in ips:
                ip_norm = self._normalize_ipv4(ip)
                with self.data_lock:
                    dns_assocs = sorted([d.rstrip('.') for d in self.dns_associations.get(ip_norm, [])])
                    sni_records = sorted(list(self.sni_by_ip.get(ip_norm, [])))
                    http_hosts = sorted(list(self.http_domains.get(ip_norm, [])))
                    raw_stats = dict(self.output_data.get(ip_norm, {}))
                    dns_queries = self.dns_queries_by_server.get(ip_norm, {})
                    dns_resps = self.dns_response_table.get(ip_norm, [])
                    
                    # Получаем информацию о угрозе для IP
                    is_blacklisted, threat_score = False, 0
                    if self.check_blacklists:
                        is_blacklisted, threat_score = self.ip_threat_info.get(ip_norm, (False, 0))
                    
                    # Получаем связи с другими IP
                    outgoing_connections = sorted(list(self.ip_connections.get(ip_norm, set())), key=self._ip_sort_key)
                    incoming_connections = sorted(list(self.ip_reverse_connections.get(ip_norm, set())), key=self._ip_sort_key)
                
                # Обработка DNS ответов
                if dns_resps:
                    aggregated = {}
                    for resp in dns_resps:
                        name = resp.get("name", "").rstrip('.')
                        type_str = resp.get("type", "")
                        resolution = resp.get("resolution", "")
                        if type_str != "A" and isinstance(resolution, str):
                            resolution = resolution.rstrip('.')
                        key = (name, type_str)
                        if key in aggregated:
                            current = aggregated[key]
                            new_vals = [x.strip() for x in resolution.split(",") if x.strip()]
                            current.update(new_vals)
                        else:
                            new_vals = set(x.strip() for x in resolution.split(",") if x.strip())
                            aggregated[key] = new_vals
                    
                    aggregated_list = [
                        {
                            "name": name,
                            "type": type_str,
                            "resolution": ", ".join(sorted(res_set))
                        }
                        for (name, type_str), res_set in aggregated.items()
                    ]
                    dns_info = {"DNS Responses": aggregated_list}
                elif dns_queries:
                    dns_info = {
                        "DNS Queries by Server": {
                            server_ip.rstrip('.'): sorted([q.rstrip('.') for q in queries])
                            for server_ip, queries in dns_queries.items()
                        }
                    }
                else:
                    dns_info = {}

                # Формирование данных по IP
                traffic_stats = {
                    k: raw_stats[k] 
                    for k in ["packets_in", "bytes_in", "packets_out", "bytes_out"] 
                    if k in raw_stats
                }
                protocol_stats = {
                    k: v 
                    for k, v in raw_stats.items() 
                    if k not in ["packets_in", "bytes_in", "packets_out", "bytes_out"]
                }

                # Обработка HTTP запросов
                with self.data_lock:
                    http_reqs = self.http_requests.get(ip_norm, [])
                unique_reqs = {}
                for req in http_reqs:
                    key = tuple(sorted((k, v) for k, v in req.items() if v))
                    unique_reqs.setdefault(key, req)
                unique_http_reqs = list(unique_reqs.values())

                # Получение ASN
                try:
                    asn = self.asn_database.lookup_asn(ip_norm)
                except Exception as e:
                    self.logger.warning(f"Failed to get ASN for IP {ip_norm}: {str(e)}")
                    asn = '<NOT FOUND>'

                # Формирование итоговых данных
                ip_data = {
                    "ASN": asn,
                    "DNS Associations": dns_assocs,
                    "SNI Records": sni_records,
                    "HTTP Domains": http_hosts,
                    "HTTP Requests": unique_http_reqs,
                    "Traffic": traffic_stats,
                    "Protocols": protocol_stats,
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
                
                ip_data.update(dns_info)
                ip_dns_sni_map[ip_norm] = ip_data

            # Добавляем информацию о угрозе для IP-адресов из DNS-ответов, 
            # которые могут не встречаться в сетевом трафике напрямую
            if self.check_blacklists and self.ip_blacklist:
                with self.data_lock:
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
                                "Protocols": {},
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
            
            with self.data_lock:
                ip_dns_sni_map["Overall Packet Statistics"] = dict(self.packet_statistics)
            
            return ip_dns_sni_map
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
