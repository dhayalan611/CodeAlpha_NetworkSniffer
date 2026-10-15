import csv
import shutil
import unittest
from unittest.mock import patch
from pathlib import Path

from scapy.all import ICMP, IP, Raw, TCP, UDP

from sniffer import (CaptureStats, PacketMetadata, classify_protocol,
                     demo_stats_for_filter, export_csv, extract_ports,
                     generate_demo_stats, packet_to_metadata, run_demo,
                     validate_packet_count)


class SnifferTests(unittest.TestCase):
    def test_protocol_classification_and_ports(self):
        tcp = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1234, dport=443)
        udp = IP() / UDP(sport=5353, dport=53)
        icmp = IP() / ICMP()
        self.assertEqual(classify_protocol(tcp), "TCP")
        self.assertEqual(extract_ports(tcp), (1234, 443))
        self.assertEqual(classify_protocol(udp), "UDP")
        self.assertEqual(extract_ports(udp), (5353, 53))
        self.assertEqual(classify_protocol(icmp), "ICMP")
        self.assertEqual(extract_ports(icmp), ("", ""))

    def test_metadata_and_safe_payload_preview(self):
        packet = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1, dport=2) / Raw(load=b"0123456789abcdefEXTRA")
        metadata = packet_to_metadata(packet, 7)
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.number, 7)
        self.assertEqual(metadata.payload_preview, "30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66")
        self.assertEqual(len(metadata.payload_preview.split()), 16)
        self.assertIsNone(packet_to_metadata(UDP(sport=1, dport=2), 1))

    def test_metadata_without_raw_payload(self):
        metadata = packet_to_metadata(IP(src="192.0.2.1", dst="198.51.100.2") / ICMP(), 1)
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.payload_preview, "No raw payload")

    def test_input_validation(self):
        self.assertEqual(validate_packet_count(" 4 "), 4)
        for value in ("", "zero", "0", "-1"):
            with self.assertRaises(ValueError):
                validate_packet_count(value)

    def test_capture_statistics(self):
        packets = [
            PacketMetadata(1, "t", "a", "b", "TCP", 1, 2, 100),
            PacketMetadata(2, "t", "a", "b", "UDP", 3, 4, 50),
            PacketMetadata(3, "t", "a", "b", "ICMP", "", "", 30),
        ]
        stats = CaptureStats(packets, 1.25)
        self.assertEqual(len(stats.packets), 3)
        self.assertEqual(stats.protocol_counts, {"TCP": 1, "UDP": 1, "ICMP": 1})
        self.assertEqual(stats.total_bytes, 180)

    def test_demo_contains_only_documentation_addresses_and_all_protocols(self):
        stats = generate_demo_stats()
        self.assertEqual([packet.protocol for packet in stats.packets], ["TCP", "UDP", "ICMP"])
        self.assertEqual(
            {(packet.source_ip, packet.destination_ip) for packet in stats.packets},
            {("192.0.2.10", "203.0.113.20"), ("198.51.100.5", "203.0.113.20")},
        )
        self.assertEqual(stats.protocol_counts, {"TCP": 1, "UDP": 1, "ICMP": 1})

    def test_demo_does_not_call_live_capture(self):
        with patch("sniffer.capture_packets", side_effect=AssertionError("live capture called")):
            stats = generate_demo_stats()
        self.assertEqual(len(stats.packets), 3)

    def test_demo_filters_reuse_the_protocol_filters(self):
        self.assertEqual(len(demo_stats_for_filter("ip").packets), 3)
        self.assertEqual(demo_stats_for_filter("tcp and ip").protocol_counts, {"TCP": 1})
        self.assertEqual(demo_stats_for_filter("udp and ip").protocol_counts, {"UDP": 1})
        self.assertEqual(demo_stats_for_filter("icmp and ip").protocol_counts, {"ICMP": 1})

    def test_demo_exports_csv_without_live_capture(self):
        output_dir = Path(__file__).parent / "_tmp_demo_capture_test"
        try:
            with patch("scapy.all.sniff", side_effect=AssertionError("live interface opened")), \
                    patch("sniffer.DEMO_OUTPUT_DIR", output_dir), \
                    patch("sniffer.export_csv", return_value=output_dir / "demo_capture.csv") as export:
                path = run_demo()
            export.assert_called_once()
            self.assertEqual(path.name, "demo_capture.csv")
            self.assertEqual(export.call_args.args[1], output_dir)
            self.assertEqual(export.call_args.kwargs["filename_prefix"], "demo_capture")
        finally:
            if output_dir.exists():
                shutil.rmtree(output_dir)

    def test_csv_export_omits_payload(self):
        output_dir = Path(__file__).parent / "_tmp_capture_test"
        try:
            packet = PacketMetadata(1, "2026-01-01 00:00:00", "192.0.2.1", "198.51.100.2", "TCP", 1, 2, 60, "secret")
            path = export_csv([packet], output_dir)
            with path.open(newline="", encoding="utf-8") as csv_file:
                rows = list(csv.reader(csv_file))
            self.assertEqual(rows[0], ["Packet Number", "Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Packet Size"])
            self.assertEqual(rows[1], ["1", "2026-01-01 00:00:00", "192.0.2.1", "198.51.100.2", "TCP", "1", "2", "60"])
            self.assertNotIn("secret", path.read_text(encoding="utf-8"))
        finally:
            if output_dir.exists():
                shutil.rmtree(output_dir)

    def test_csv_export_reports_directory_error(self):
        blocked_path = Path(__file__).parent / "_tmp_csv_block"
        blocked_path.write_text("not a directory", encoding="utf-8")
        try:
            with self.assertRaises(RuntimeError):
                export_csv([], blocked_path)
        finally:
            blocked_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
