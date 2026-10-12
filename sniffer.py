
"""A small, terminal-based IPv4 packet sniffer for the CodeAlpha internship."""

from __future__ import annotations

import csv
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

CSV_COLUMNS = ["Packet Number", "Timestamp", "Source IP", "Destination IP",
               "Protocol", "Source Port", "Destination Port", "Packet Size"]
DEFAULT_PACKET_COUNT = 30
MAX_PACKET_COUNT = 1_000_000
FILTERS = {"1": ("All IPv4 packets", "ip"), "2": ("TCP packets", "tcp and ip"),
           "3": ("UDP packets", "udp and ip"), "4": ("ICMP packets", "icmp and ip")}


@dataclass
class PacketMetadata:
    """Safe, CSV-ready metadata extracted from one IPv4 packet."""
    number: int
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | str = ""
    destination_port: int | str = ""
    packet_size: int = 0
    payload_preview: str = "No raw payload"

    def csv_row(self) -> list[Any]:
        """Return metadata without the display-only payload preview."""
        return [self.number, self.timestamp, self.source_ip, self.destination_ip,
                self.protocol, self.source_port, self.destination_port, self.packet_size]


@dataclass
class CaptureStats:
    """Counters accumulated for a capture session."""
    packets: list[PacketMetadata] = field(default_factory=list)
    duration: float = 0.0

    @property
    def total_bytes(self) -> int:
        return sum(packet.packet_size for packet in self.packets)

    @property
    def protocol_counts(self) -> Counter[str]:
        return Counter(packet.protocol for packet in self.packets)


def validate_packet_count(value: str | int) -> int:
    """Validate and return a positive maximum packet count."""
    try:
        count = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("Packet count must be a whole number.") from exc
    if not 1 <= count <= MAX_PACKET_COUNT:
        raise ValueError(f"Packet count must be between 1 and {MAX_PACKET_COUNT:,}.")
    return count


def _layers() -> tuple[Any, Any, Any, Any, Any]:
    """Load Scapy classes lazily so the CLI can report a useful error."""
    try:
        from scapy.all import ICMP, IP, Raw, TCP, UDP
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Run: python -m pip install -r requirements.txt") from exc
    return IP, TCP, UDP, ICMP, Raw


def classify_protocol(packet: Any) -> str:
    """Return TCP, UDP, ICMP, or the numeric IPv4 protocol name."""
    IP, TCP, UDP, ICMP, _ = _layers()
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    return f"IP-{packet[IP].proto}"


def extract_ports(packet: Any) -> tuple[int | str, int | str]:
    """Extract TCP/UDP ports, returning blanks for protocols without ports."""
    _, TCP, UDP, _, _ = _layers()
    if TCP in packet:
        return packet[TCP].sport, packet[TCP].dport
    if UDP in packet:
        return packet[UDP].sport, packet[UDP].dport
    return "", ""


def packet_to_metadata(packet: Any, number: int) -> PacketMetadata | None:
    """Convert an IPv4 Scapy packet to safe display/export metadata."""
    IP, _, _, _, Raw = _layers()
    if IP not in packet:
        return None
    source_port, destination_port = extract_ports(packet)
    payload_preview = "No raw payload"
    if Raw in packet:
        payload_preview = bytes(packet[Raw].load)[:16].hex(" ") or "Empty payload"
    return PacketMetadata(
        number=number,
        timestamp=datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S"),
        source_ip=packet[IP].src,
        destination_ip=packet[IP].dst,
        protocol=classify_protocol(packet),
        source_port=source_port,
        destination_port=destination_port,
        packet_size=len(packet),
        payload_preview=payload_preview,
    )


def print_packet(metadata: PacketMetadata) -> None:
    """Print one packet in a readable, privacy-conscious format."""
    print("\n" + "=" * 55)
    print(f"Packet Number : {metadata.number}\nTimestamp     : {metadata.timestamp}")
    print(f"Source IP     : {metadata.source_ip}\nDestination IP: {metadata.destination_ip}")
    print(f"Protocol      : {metadata.protocol}\nSource Port   : {metadata.source_port}")
    print(f"Dest Port     : {metadata.destination_port}\nPacket Size   : {metadata.packet_size} bytes")
    print(f"Payload (hex) : {metadata.payload_preview}")


def export_csv(packets: Iterable[PacketMetadata], output_dir: str | Path = "captures") -> Path:
    """Write packet metadata to a unique timestamp-based CSV file."""
    directory = Path(output_dir)
    path = directory / datetime.now().strftime("capture_%Y%m%d_%H%M%S_%f.csv")
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(CSV_COLUMNS)
            writer.writerows(packet.csv_row() for packet in packets)
    except OSError as exc:
        raise RuntimeError(f"Could not write CSV file '{path}': {exc}") from exc
    return path


def capture_packets(packet_filter: str, maximum: int) -> CaptureStats:
    """Capture packets until the limit or Ctrl+C, then return statistics."""
    try:
        from scapy.all import sniff
        from scapy.error import Scapy_Exception
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Run: python -m pip install -r requirements.txt") from exc
    maximum = validate_packet_count(maximum)
    stats = CaptureStats()

    def handle_packet(packet: Any) -> None:
        metadata = packet_to_metadata(packet, len(stats.packets) + 1)
        if metadata is not None:
            stats.packets.append(metadata)
            print_packet(metadata)

    started = time.monotonic()
    try:
        sniff(filter=packet_filter, prn=handle_packet, store=False, count=maximum)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError as exc:
        raise RuntimeError("Capture permission denied. Try an elevated terminal or check Npcap.") from exc
    except OSError as exc:
        raise RuntimeError(f"Npcap or network interface error: {exc}") from exc
    except Scapy_Exception as exc:
        raise RuntimeError(f"Scapy/Npcap capture error: {exc}") from exc
    finally:
        stats.duration = time.monotonic() - started
    return stats


def print_summary(stats: CaptureStats) -> None:
    """Print calculated capture totals."""
    counts = stats.protocol_counts
    print("\n========== CAPTURE SUMMARY ==========")
    print(f"Total Packets : {len(stats.packets)}\nTCP Packets   : {counts.get('TCP', 0)}")
    print(f"UDP Packets   : {counts.get('UDP', 0)}\nICMP Packets  : {counts.get('ICMP', 0)}")
    print(f"\nCapture Duration : {stats.duration:.1f} seconds")
    print(f"Total Bytes      : {stats.total_bytes} bytes")
    print("\n=====================================")


def choose_packet_count(input_func: Callable[[str], str] = input) -> int:
    """Prompt for a packet count, using the documented default when blank."""
    while True:
        value = input_func(f"Maximum packets [{DEFAULT_PACKET_COUNT}]: ")
        if not value.strip():
            return DEFAULT_PACKET_COUNT
        try:
            return validate_packet_count(value)
        except ValueError as exc:
            print(f"Invalid packet count: {exc}")


def main() -> None:
    """Run the interactive terminal interface."""
    print("\n========================================\n       CODEALPHA NETWORK SNIFFER\n========================================")
    print("\n1. Capture All IPv4 Packets\n2. Capture TCP Packets\n3. Capture UDP Packets\n4. Capture ICMP Packets\n5. Exit")
    choice = input("\nSelect an option: ").strip()
    if choice == "5":
        print("Goodbye.")
        return
    if choice not in FILTERS:
        print("Invalid menu selection. Please choose an option from 1 to 5.")
        return
    maximum = choose_packet_count()
    label, packet_filter = FILTERS[choice]
    print(f"\nCapturing {label} (maximum {maximum} packets). Press Ctrl+C to stop.\n")
    try:
        stats = capture_packets(packet_filter, maximum)
        print_summary(stats)
        path = export_csv(stats.packets)
        print(f"Metadata saved to: {path}")
        print("Note: HTTPS payloads are generally encrypted and are not readable as plaintext here.")
    except RuntimeError as exc:
        print(f"Capture error: {exc}")


if __name__ == "__main__":
    main()
