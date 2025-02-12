#!/usr/bin/env python3
import logging
import sys
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Callable, Any, Dict, Set, Generator, List

# Импортируем необходимые классы из Scapy
from scapy.all import (
    IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, PcapReader, Packet, Raw
)
from tqdm import tqdm
import pyasn
import pyshark
import threading
import os


class Logger:
    """
    Logger class for setting up logging.
    Provides different logging levels for console and file output.
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
    Class to interact with ASN database.
    Uses pyasn library to lookup ASN information.
    """
    def __init__(self, asndb_path: str, as_names_file: str) -> None:
        if not os.path.exists(asndb_path) or not os.path.exists(as_names_file):
            raise FileNotFoundError("ASN database files not found.")
        self.asndb = pyasn.pyasn(asndb_path, as_names_file=as_names_file)
        self.asn_cache: Dict[str, str] = {}
        self.lock = threading.Lock()

    def lookup_asn(self, ip: str) -> str:
        with self.lock:
            if ip in self.asn_cache:
                return self.asn_cache[ip]
        try:
            asn_info = self.asndb.lookup(ip)
            asn_name = self.asndb.get_as_name(asn_info[0]) if asn_info else '<NOT FOUND>'
        except Exception:
            asn_name = '<NOT FOUND>'
        with self.lock:
            self.asn_cache[ip] = asn_name
        return asn_name


class NetParser:
    """
    Class for parsing and analyzing network traffic from PCAP files.
    Processes various packet types including DNS, HTTP, SNI (TLS) and collects statistics.
    """
    def __init__(self,
                 asndb_path: str = "./asndb/ipasndb.dat",
                 as_names_file: str = "./asndb/asnname.json") -> None:
        self.logger = Logger.setup_logger()
        self.dns_records: Dict[str, Set[Any]] = defaultdict(set)
        self.ip_list_conn: Set[str] = set()
        self.g_ip_sni: Dict[str, Set[str]] = defaultdict(set)
        self.http_domains: Dict[str, Set[str]] = defaultdict(set)
        self.http_requests: Dict[str, List[Dict[str, str]]] = defaultdict(list)
        self.asn_database = ASNDatabase(asndb_path, as_names_file)
        self.packet_statistics: Dict[str, int] = {
            "total_packets": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "http_count": 0,
            "https_count": 0,
            "dns_count": 0,
            "total_bytes": 0
        }
        # Для каждого IP будет храниться протокольная статистика, а также трафик (вход/выход)
        self.output_data: Dict[str, Dict[str, int]] = {}
        self.data_lock = threading.Lock()

    @staticmethod
    def _normalize_ipv4(ip: str) -> str:
        """Нормализует IPv4 адрес, если он записан в формате ::ffff:x.x.x.x"""
        if re.match(r"^::ffff:\d+\.\d+\.\d+\.\d+$", ip):
            return ip.split(":")[-1]
        return ip

    def parse_http_request(self, payload: str) -> Optional[Dict[str, str]]:
        """
        Парсит HTTP запрос из полезной нагрузки и извлекает основные поля.
        Возвращает словарь с ключами: method, uri, version, host, user_agent.
        Если строка не соответствует формату HTTP запроса, возвращает None.
        """
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

    def handle_dns_pkt(self, pkt: Packet) -> None:
        """Извлекает DNS записи из пакета."""
        try:
            if DNSQR in pkt:
                for query in pkt[DNSQR]:
                    qname = query.qname.decode() if query.qname else '<UNKNOWN>'
                    with self.data_lock:
                        self.dns_records.setdefault(qname, set())
            if DNSRR in pkt:
                for answer in pkt[DNSRR]:
                    rrname = answer.rrname.decode() if answer.rrname else '<UNKNOWN>'
                    rdata = answer.rdata if hasattr(answer, 'rdata') else '<NO DATA>'
                    with self.data_lock:
                        self.dns_records[rrname].add(rdata)
        except Exception:
            self.logger.exception("Error handling DNS packet:")

    def extract_sni_pyshark(self, pcap_file: str) -> None:
        """Извлекает SNI из TLS пакетов с помощью pyshark."""
        try:
            cap = pyshark.FileCapture(
                pcap_file,
                display_filter="tls.handshake.extensions_server_name",
                keep_packets=False
            )
            for pkt in cap:
                try:
                    sni = pkt.tls.handshake_extensions_server_name
                    ip = self._normalize_ipv4(pkt.ip.dst)
                    with self.data_lock:
                        self.g_ip_sni[ip].add(sni)
                except AttributeError:
                    continue
                except Exception:
                    self.logger.exception("Unexpected error while processing SNI in packet:")
        except pyshark.capture.capture.TSharkCrashException as e:
            self.logger.error(f"TShark crashed while processing the file {pcap_file}: {e}")
        except FileNotFoundError as e:
            self.logger.error(f"File {pcap_file} not found: {e}")
        except Exception:
            self.logger.exception(f"Unexpected error processing file {pcap_file}:")
        finally:
            try:
                cap.close()
            except Exception:
                self.logger.warning(f"Error while closing capture object for {pcap_file}")

    def process_packets(self, packets: List[Packet],
                        filters: Optional[Callable[[Packet], bool]] = None) -> None:
        """
        Обрабатывает пакеты, обновляет общую статистику, а также статистику по каждому IP.
        Сохраняет информацию по входящему/исходящему трафику и протоколам.
        """
        for pkt in packets:
            with self.data_lock:
                self.packet_statistics["total_packets"] += 1
                self.packet_statistics["total_bytes"] += len(pkt)
            if filters and not filters(pkt):
                continue
            if IP in pkt:
                ip_src = self._normalize_ipv4(pkt[IP].src)
                ip_dst = self._normalize_ipv4(pkt[IP].dst)
                with self.data_lock:
                    self.ip_list_conn.update([ip_src, ip_dst])
                    self.output_data.setdefault(ip_src, defaultdict(int))
                    self.output_data.setdefault(ip_dst, defaultdict(int))
                    # Обновляем счетчики трафика по направлениям
                    self.output_data[ip_src]["packets_out"] += 1
                    self.output_data[ip_src]["bytes_out"] += len(pkt)
                    self.output_data[ip_dst]["packets_in"] += 1
                    self.output_data[ip_dst]["bytes_in"] += len(pkt)
                if TCP in pkt:
                    with self.data_lock:
                        self.packet_statistics["tcp_count"] += 1
                        self.output_data[ip_src]["tcp_count"] += 1
                        self.output_data[ip_dst]["tcp_count"] += 1
                    if pkt[TCP].dport == 80:
                        with self.data_lock:
                            self.packet_statistics["http_count"] += 1
                        if pkt.haslayer(Raw):
                            try:
                                raw_payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                                host_match = re.search(r"Host:\s*([^\r\n]+)", raw_payload, re.IGNORECASE)
                                if host_match:
                                    host = host_match.group(1).strip()
                                    with self.data_lock:
                                        self.http_domains[ip_dst].add(host)
                                http_data = self.parse_http_request(raw_payload)
                                if http_data:
                                    with self.data_lock:
                                        self.http_requests[ip_dst].append(http_data)
                            except Exception:
                                self.logger.exception("Error extracting HTTP request details:")
                    elif pkt[TCP].dport == 443:
                        with self.data_lock:
                            self.packet_statistics["https_count"] += 1
                elif UDP in pkt:
                    with self.data_lock:
                        self.packet_statistics["udp_count"] += 1
                        self.output_data[ip_src]["udp_count"] += 1
                        self.output_data[ip_dst]["udp_count"] += 1
                elif ICMP in pkt:
                    with self.data_lock:
                        self.packet_statistics["icmp_count"] += 1
                        self.output_data[ip_src]["icmp_count"] += 1
                        self.output_data[ip_dst]["icmp_count"] += 1
                if DNS in pkt:
                    with self.data_lock:
                        self.packet_statistics["dns_count"] += 1
                        self.output_data[ip_src]["dns_count"] += 1
                        self.output_data[ip_dst]["dns_count"] += 1
                    self.handle_dns_pkt(pkt)

    def process_in_parallel(self, pcap_file: str,
                            num_threads: int = 4,
                            filters: Optional[Callable[[Packet], bool]] = None) -> None:
        """
        Обрабатывает пакеты в параллельном режиме с использованием нескольких потоков и отображает progress bar.
        """
        def packet_iterator() -> Generator[Packet, None, None]:
            try:
                with PcapReader(pcap_file) as reader:
                    for pkt in reader:
                        yield pkt
            except FileNotFoundError as e:
                self.logger.error(f"PCAP file not found: {pcap_file}")
                raise e
            except Exception:
                self.logger.exception("Error while reading PCAP file:")
                raise

        chunk_size = 1000
        futures = []
        chunk: List[Packet] = []
        for packet in tqdm(packet_iterator(), desc="Reading packets", unit="pkt"):
            chunk.append(packet)
            if len(chunk) >= chunk_size:
                futures.append(ThreadPoolExecutor(max_workers=1).submit(self.process_packets, chunk, filters))
                chunk = []
        if chunk:
            futures.append(ThreadPoolExecutor(max_workers=1).submit(self.process_packets, chunk, filters))
        for future in futures:
            future.result()

    def analyze(self, pcap_file: str,
                filters: Optional[Callable[[Packet], bool]] = None) -> Dict[str, Any]:
        """
        Основной метод для анализа PCAP файла.
        """
        self.logger.info("[*] Starting PCAP analysis...")
        self.process_in_parallel(pcap_file, filters=filters)
        self.extract_sni_pyshark(pcap_file)
        return self.output_data

    def get_dict(self) -> Dict[str, Any]:
        """
        Возвращает итоговый словарь, содержащий для каждого IP:
         - "Traffic": статистика входящих/исходящих пакетов и байтов,
         - "Protocols": статистика по протоколам.
        Также включается общая статистика по всем пакетам и детальные HTTP запросы (с удалением дубликатов).
        """
        ip_dns_sni_map: Dict[str, Any] = {}
        with self.data_lock:
            ips = list(self.ip_list_conn)
        for ip in ips:
            ip_norm = self._normalize_ipv4(ip)
            with self.data_lock:
                dns_associations = sorted(qname for qname, records in self.dns_records.items() if ip_norm in records)
                sni_records = sorted(self.g_ip_sni.get(ip_norm, []))
                http_hosts = sorted(self.http_domains.get(ip_norm, []))
                # Разбиваем статистику: трафик и протоколы
                raw_stats = dict(self.output_data.get(ip_norm, {}))
            traffic_stats = {k: raw_stats[k] for k in ["packets_in", "bytes_in", "packets_out", "bytes_out"] if k in raw_stats}
            protocol_stats = {k: v for k, v in raw_stats.items() if k not in ["packets_in", "bytes_in", "packets_out", "bytes_out"]}
            with self.data_lock:
                http_reqs = self.http_requests.get(ip_norm, [])
            # Удаляем дубликаты HTTP запросов
            unique_reqs = {}
            for req in http_reqs:
                key = tuple(sorted(req.items()))
                if key not in unique_reqs:
                    unique_reqs[key] = req
            unique_http_reqs = list(unique_reqs.values())
            asn = self.asn_database.lookup_asn(ip_norm)
            ip_dns_sni_map[ip_norm] = {
                "ASN": asn,
                "DNS Associations": dns_associations,
                "SNI Records": sni_records,
                "HTTP Domains": http_hosts,
                "HTTP Requests": unique_http_reqs,
                "Traffic": traffic_stats,
                "Protocols": protocol_stats
            }
        with self.data_lock:
            ip_dns_sni_map["Overall Packet Statistics"] = dict(self.packet_statistics)
        return ip_dns_sni_map
