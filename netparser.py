import json
import logging
import sys
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
from tqdm import tqdm
import pyasn
import pyshark
import threading

class Logger:
    """
    Класс для настройки логирования.
    Предоставляет различные уровни логирования для вывода в консоль и в файл.
    """
    @staticmethod
    def setup_logger():
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
    Класс для работы с базой данных ASN.
    Использует библиотеку pyasn для поиска информации по ASN.
    """
    def __init__(self, asndb_path, as_names_file):
        self.asndb = pyasn.pyasn(asndb_path, as_names_file=as_names_file)
        self.asn_cache = {}
        self.lock = threading.Lock()

    def lookup_asn(self, ip):
        with self.lock:
            if ip in self.asn_cache:
                return self.asn_cache[ip]
            try:
                asn = self.asndb.lookup(ip)
                asn_name = self.asndb.get_as_name(asn[0]) if asn else '<NOT FOUND>'
                self.asn_cache[ip] = asn_name
                return asn_name
            except Exception as e:
                return '<NOT FOUND>'


class NetParser:
    """
    Класс для парсинга и анализа сетевого трафика из PCAP файлов.
    Реализует обработку различных типов пакетов, включая DNS, SNI и статистику.
    """
    def __init__(self, asndb_path="./asndb/ipasndb.dat", as_names_file="./asndb/asnname.json"):
        self.logger = Logger.setup_logger()
        self.dns_records = defaultdict(set)
        self.ip_list_conn = set()
        self.g_ip_sni = defaultdict(set)
        self.asn_database = ASNDatabase(asndb_path, as_names_file)
        self.packet_statistics = {
            "total_packets": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "http_count": 0,
            "https_count": 0,
            "dns_count": 0,
            "total_bytes": 0
        }
        self.output_data = {}

    @staticmethod
    def _normalize_ipv4(ip):
        """
        Нормализует IPv4 адрес, если он представлен в формате ::ffff:.
        """
        if re.match(r"^::ffff:\d+\.\d+\.\d+\.\d+$", ip):
            return ip.split(":")[-1]
        return ip

    def handle_dns_pkt(self, pkt):
        """
        Обрабатывает DNS пакеты для извлечения DNS записей.
        """
        try:
            if DNSQR in pkt:
                for query in pkt[DNSQR]:
                    qname = query.qname.decode() if query.qname else '<UNKNOWN>'
                    self.dns_records[qname]
            if DNSRR in pkt:
                for answer in pkt[DNSRR]:
                    rrname = answer.rrname.decode() if answer.rrname else '<UNKNOWN>'
                    rdata = answer.rdata if hasattr(answer, 'rdata') else '<NO DATA>'
                    self.dns_records[rrname].add(rdata)
        except Exception as e:
            self.logger.warning(f"Error handling DNS packet: {e}")

    def extract_sni_pyshark(self, pcap_file):
        """
        Извлекает SNI из TLS пакетов с использованием pyshark.
        """
        try:
            cap = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.extensions_server_name", keep_packets=False)
            cap.set_debug()

            for pkt in cap:
                try:
                    sni = pkt.tls.handshake_extensions_server_name
                    ip = self._normalize_ipv4(pkt.ip.dst)
                    self.g_ip_sni[ip].add(sni)
                except AttributeError as e:
                    self.logger.warning(f"Attribute error while processing SNI in packet: {e}")
                except Exception as e:
                    self.logger.warning(f"Unexpected error while handling packet: {e}")
        
        except pyshark.capture.capture.TSharkCrashException as e:
            self.logger.error(f"TShark crashed while processing the file {pcap_file}: {e}")
        except FileNotFoundError as e:
            self.logger.error(f"File {pcap_file} not found: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error processing file {pcap_file}: {e}")
        finally:
            try:
                cap.close()
            except Exception as e:
                self.logger.warning(f"Error while closing capture object for {pcap_file}: {e}")

    def process_packets(self, packets, filters=None):
        """
        Обрабатывает пакеты с учетом фильтров и обновляет статистику.
        """
        for pkt in tqdm(packets, desc="Processing packets"):
            self.packet_statistics["total_packets"] += 1
            if filters and not filters(pkt):
                continue
            if IP in pkt:
                ip_src = self._normalize_ipv4(pkt[IP].src)
                ip_dst = self._normalize_ipv4(pkt[IP].dst)
                self.ip_list_conn.update([ip_src, ip_dst])
                
                self.output_data.setdefault(ip_src, defaultdict(int))
                self.output_data.setdefault(ip_dst, defaultdict(int))
                
                if TCP in pkt:
                    self.output_data[ip_src]["tcp_count"] += 1
                    self.output_data[ip_dst]["tcp_count"] += 1
                    if pkt[TCP].dport == 80:
                        self.output_data[ip_src]["http_count"] += 1
                        self.output_data[ip_dst]["http_count"] += 1
                    elif pkt[TCP].dport == 443:
                        self.output_data[ip_src]["https_count"] += 1
                        self.output_data[ip_dst]["https_count"] += 1
                elif UDP in pkt:
                    self.output_data[ip_src]["udp_count"] += 1
                    self.output_data[ip_dst]["udp_count"] += 1
                elif ICMP in pkt:
                    self.output_data[ip_src]["icmp_count"] += 1
                    self.output_data[ip_dst]["icmp_count"] += 1
                if DNS in pkt:
                    self.output_data[ip_src]["dns_count"] += 1
                    self.output_data[ip_dst]["dns_count"] += 1
            self.packet_statistics["total_bytes"] += len(pkt)

    def process_in_parallel(self, pcap_file, num_threads=4, filters=None):
        """
        Обрабатывает пакеты параллельно с использованием нескольких потоков.
        """
        def packet_iterator():
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    yield pkt

        chunk_size = 1000
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            chunk = []
            for packet in packet_iterator():
                chunk.append(packet)
                if len(chunk) == chunk_size:
                    executor.submit(self.process_packets, chunk, filters)
                    chunk = []
            if chunk:
                executor.submit(self.process_packets, chunk, filters)

    def analyze(self, pcap_file, filters=None):
        """
        Основной метод для анализа PCAP файла.
        """
        self.logger.info("[*] Starting PCAP analysis...")
        self.process_in_parallel(pcap_file, filters=filters)
        self.extract_sni_pyshark(pcap_file)
        return self.output_data

    def get_dict(self):
        """
        Возвращает словарь, содержащий IP адреса, их ассоциации с DNS, SNI и ASN.
        Также включает статистику по пакетам.
        """
        ip_dns_sni_map = {}
        for ip in self.ip_list_conn:
            ip = self._normalize_ipv4(ip)
            dns_associations = sorted(qname for qname, ips in self.dns_records.items() if ip in ips)
            sni_records = sorted(self.g_ip_sni.get(ip, []))
            asn = self.asn_database.lookup_asn(ip)
            ip_dns_sni_map[ip] = {
                "ASN": asn,
                "DNS Associations": dns_associations,
                "SNI Records": sni_records,
                "Packet Statistics": self.output_data.get(ip, {})
            }
        return ip_dns_sni_map
