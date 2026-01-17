"""Wrapper for lightweight packet capture tools (tcpdump, ngrep, tcpflow)."""

import contextlib
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..core.exceptions import CaptureError, DependencyError
from ..core.utils import check_dependency, is_root


@dataclass
class TcpdumpPacket:
    """Single packet from tcpdump output."""

    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "length": self.length,
            "info": self.info,
        }


@dataclass
class TcpdumpResult:
    """tcpdump capture result."""

    interface: str
    packet_count: int
    packets: list[TcpdumpPacket]
    output_file: str | None
    start_time: datetime
    end_time: datetime
    bpf_filter: str | None

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "packet_count": self.packet_count,
            "packets": [p.to_dict() for p in self.packets[:100]],  # Limit to first 100
            "output_file": self.output_file,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
            "bpf_filter": self.bpf_filter,
        }


@dataclass
class NgrepMatch:
    """Single match from ngrep output."""

    interface: str | None
    timestamp: str | None
    protocol: str
    source: str
    destination: str
    payload: str

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "source": self.source,
            "destination": self.destination,
            "payload": self.payload,
        }


@dataclass
class NgrepResult:
    """ngrep search result."""

    pattern: str
    interface: str | None
    pcap_file: str | None
    match_count: int
    matches: list[NgrepMatch]
    start_time: datetime
    end_time: datetime

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern,
            "interface": self.interface,
            "pcap_file": self.pcap_file,
            "match_count": self.match_count,
            "matches": [m.to_dict() for m in self.matches[:100]],  # Limit to first 100
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
        }


@dataclass
class TcpflowStream:
    """Reconstructed TCP stream from tcpflow."""

    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    filename: str
    size_bytes: int
    content_preview: str | None

    def to_dict(self) -> dict:
        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "content_preview": self.content_preview,
        }


@dataclass
class TcpflowResult:
    """tcpflow extraction result."""

    pcap_file: str
    output_dir: str
    stream_count: int
    streams: list[TcpflowStream]
    total_bytes: int

    def to_dict(self) -> dict:
        return {
            "pcap_file": self.pcap_file,
            "output_dir": self.output_dir,
            "stream_count": self.stream_count,
            "streams": [s.to_dict() for s in self.streams],
            "total_bytes": self.total_bytes,
        }


class TcpdumpCapture:
    """Wrapper for tcpdump packet capture.

    tcpdump is a lightweight command-line packet analyzer. It's faster
    and more resource-efficient than tshark for simple captures.
    """

    def __init__(self) -> None:
        if not check_dependency("tcpdump"):
            raise DependencyError(
                "tcpdump",
                "Usually pre-installed. Install with: apt install tcpdump (Linux)",
            )

    def capture(
        self,
        interface: str,
        count: int = 100,
        timeout: int = 60,
        bpf_filter: str | None = None,
        output_file: str | None = None,
        verbose: bool = False,
    ) -> TcpdumpResult:
        """
        Capture packets using tcpdump.

        Args:
            interface: Network interface to capture on
            count: Maximum number of packets to capture
            timeout: Capture timeout in seconds
            bpf_filter: BPF filter expression
            output_file: Output pcap file path
            verbose: Enable verbose output

        Returns:
            TcpdumpResult with captured packets
        """
        if not is_root():
            raise CaptureError("tcpdump capture requires root privileges")

        start_time = datetime.now()

        cmd = ["tcpdump", "-i", interface, "-c", str(count), "-tttt"]

        if verbose:
            cmd.append("-v")

        if output_file:
            cmd.extend(["-w", output_file])
        else:
            # Output to stdout for parsing
            cmd.append("-l")

        if bpf_filter:
            cmd.append(bpf_filter)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            packets = []
            if not output_file:
                packets = self._parse_output(result.stdout + result.stderr)

            end_time = datetime.now()

            return TcpdumpResult(
                interface=interface,
                packet_count=len(packets) if packets else count,
                packets=packets,
                output_file=output_file,
                start_time=start_time,
                end_time=end_time,
                bpf_filter=bpf_filter,
            )

        except subprocess.TimeoutExpired as e:
            raise CaptureError(f"tcpdump capture timed out on {interface}", str(e)) from e
        except Exception as e:
            raise CaptureError(f"tcpdump capture failed on {interface}", str(e)) from e

    def read_pcap(
        self,
        pcap_file: str,
        bpf_filter: str | None = None,
        count: int | None = None,
    ) -> TcpdumpResult:
        """
        Read and parse packets from a pcap file.

        Args:
            pcap_file: Path to pcap file
            bpf_filter: BPF filter expression
            count: Maximum number of packets to read

        Returns:
            TcpdumpResult with parsed packets
        """
        if not Path(pcap_file).exists():
            raise CaptureError(f"Pcap file not found: {pcap_file}")

        start_time = datetime.now()

        cmd = ["tcpdump", "-r", pcap_file, "-tttt"]

        if count:
            cmd.extend(["-c", str(count)])

        if bpf_filter:
            cmd.append(bpf_filter)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            packets = self._parse_output(result.stdout)
            end_time = datetime.now()

            return TcpdumpResult(
                interface="file",
                packet_count=len(packets),
                packets=packets,
                output_file=pcap_file,
                start_time=start_time,
                end_time=end_time,
                bpf_filter=bpf_filter,
            )

        except Exception as e:
            raise CaptureError(f"Failed to read pcap file: {pcap_file}", str(e)) from e

    def _parse_output(self, output: str) -> list[TcpdumpPacket]:
        """Parse tcpdump text output into packet objects."""
        packets = []
        lines = output.strip().split("\n")

        for line in lines:
            if not line.strip():
                continue

            # Skip summary lines
            if "packets captured" in line or "packets received" in line:
                continue

            packet = self._parse_packet_line(line)
            if packet:
                packets.append(packet)

        return packets

    def _parse_packet_line(self, line: str) -> TcpdumpPacket | None:
        """Parse a single tcpdump output line."""
        # Format: 2024-01-15 10:30:45.123456 IP 192.168.1.1.443 > 192.168.1.2.12345: ...
        match = re.match(
            r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
            r"(\w+)\s+"
            r"(\S+)\s+>\s+(\S+):\s*(.*)",
            line,
        )

        if match:
            return TcpdumpPacket(
                timestamp=match.group(1),
                protocol=match.group(2),
                source=match.group(3).rstrip(","),
                destination=match.group(4).rstrip(":"),
                length=self._extract_length(match.group(5)),
                info=match.group(5)[:200],  # Truncate long info
            )

        return None

    def _extract_length(self, info: str) -> int:
        """Extract packet length from info string."""
        match = re.search(r"length\s+(\d+)", info)
        return int(match.group(1)) if match else 0


class NgrepSearch:
    """Wrapper for ngrep network grep.

    ngrep allows searching network traffic for patterns using
    regular expressions. Useful for finding specific content in packets.
    """

    def __init__(self) -> None:
        if not check_dependency("ngrep"):
            raise DependencyError(
                "ngrep",
                "Install with: brew install ngrep (macOS) or apt install ngrep (Linux)",
            )

    def search_live(
        self,
        pattern: str,
        interface: str,
        count: int = 100,
        timeout: int = 60,
        bpf_filter: str | None = None,
        case_insensitive: bool = False,
    ) -> NgrepResult:
        """
        Search live traffic for pattern.

        Args:
            pattern: Regex pattern to search for
            interface: Network interface to capture on
            count: Maximum number of matches
            timeout: Capture timeout in seconds
            bpf_filter: BPF filter expression
            case_insensitive: Case insensitive matching

        Returns:
            NgrepResult with matches
        """
        if not is_root():
            raise CaptureError("ngrep live capture requires root privileges")

        start_time = datetime.now()

        cmd = ["ngrep", "-q", "-W", "byline"]

        if case_insensitive:
            cmd.append("-i")

        cmd.extend(["-d", interface, pattern])

        if bpf_filter:
            cmd.append(bpf_filter)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            matches = self._parse_output(result.stdout, interface=interface)
            end_time = datetime.now()

            return NgrepResult(
                pattern=pattern,
                interface=interface,
                pcap_file=None,
                match_count=len(matches),
                matches=matches[:count],
                start_time=start_time,
                end_time=end_time,
            )

        except subprocess.TimeoutExpired:
            end_time = datetime.now()
            return NgrepResult(
                pattern=pattern,
                interface=interface,
                pcap_file=None,
                match_count=0,
                matches=[],
                start_time=start_time,
                end_time=end_time,
            )
        except Exception as e:
            raise CaptureError(f"ngrep search failed on {interface}", str(e)) from e

    def search_pcap(
        self,
        pattern: str,
        pcap_file: str,
        case_insensitive: bool = False,
    ) -> NgrepResult:
        """
        Search pcap file for pattern.

        Args:
            pattern: Regex pattern to search for
            pcap_file: Path to pcap file
            case_insensitive: Case insensitive matching

        Returns:
            NgrepResult with matches
        """
        if not Path(pcap_file).exists():
            raise CaptureError(f"Pcap file not found: {pcap_file}")

        start_time = datetime.now()

        cmd = ["ngrep", "-q", "-W", "byline", "-I", pcap_file]

        if case_insensitive:
            cmd.append("-i")

        cmd.append(pattern)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            matches = self._parse_output(result.stdout)
            end_time = datetime.now()

            return NgrepResult(
                pattern=pattern,
                interface=None,
                pcap_file=pcap_file,
                match_count=len(matches),
                matches=matches,
                start_time=start_time,
                end_time=end_time,
            )

        except Exception as e:
            raise CaptureError(f"ngrep search failed in {pcap_file}", str(e)) from e

    def _parse_output(
        self,
        output: str,
        interface: str | None = None,
    ) -> list[NgrepMatch]:
        """Parse ngrep output into match objects."""
        matches = []
        current_match: dict | None = None

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                if current_match:
                    matches.append(
                        NgrepMatch(
                            interface=interface,
                            timestamp=current_match.get("timestamp"),
                            protocol=current_match.get("protocol", "unknown"),
                            source=current_match.get("source", ""),
                            destination=current_match.get("destination", ""),
                            payload=current_match.get("payload", ""),
                        )
                    )
                    current_match = None
                continue

            # Header line: T 192.168.1.1:443 -> 192.168.1.2:12345 [AP]
            header_match = re.match(
                r"^([TU])\s+(\S+)\s+->\s+(\S+)\s+\[.*\]",
                line,
            )

            if header_match:
                current_match = {
                    "protocol": "TCP" if header_match.group(1) == "T" else "UDP",
                    "source": header_match.group(2),
                    "destination": header_match.group(3),
                    "payload": "",
                }
            elif current_match:
                # Payload line
                if current_match["payload"]:
                    current_match["payload"] += "\n"
                current_match["payload"] += line

        # Handle last match
        if current_match:
            matches.append(
                NgrepMatch(
                    interface=interface,
                    timestamp=None,
                    protocol=current_match.get("protocol", "unknown"),
                    source=current_match.get("source", ""),
                    destination=current_match.get("destination", ""),
                    payload=current_match.get("payload", ""),
                )
            )

        return matches


class TcpflowExtractor:
    """Wrapper for tcpflow TCP stream reconstruction.

    tcpflow captures and reconstructs TCP streams from network traffic,
    saving each flow to a separate file. Useful for extracting files
    and analyzing application-layer data.
    """

    def __init__(self) -> None:
        if not check_dependency("tcpflow"):
            raise DependencyError(
                "tcpflow",
                "Install with: brew install tcpflow (macOS) or apt install tcpflow (Linux)",
            )

    def extract_from_pcap(
        self,
        pcap_file: str,
        output_dir: str | None = None,
        max_files: int = 100,
    ) -> TcpflowResult:
        """
        Extract TCP streams from pcap file.

        Args:
            pcap_file: Path to pcap file
            output_dir: Output directory for stream files
            max_files: Maximum number of stream files to process

        Returns:
            TcpflowResult with extracted streams
        """
        if not Path(pcap_file).exists():
            raise CaptureError(f"Pcap file not found: {pcap_file}")

        # Create output directory
        if output_dir is None:
            output_dir = f"tcpflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        Path(output_dir).mkdir(parents=True, exist_ok=True)

        cmd = ["tcpflow", "-r", pcap_file, "-o", output_dir]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            streams = self._parse_output_dir(output_dir, max_files)

            total_bytes = sum(s.size_bytes for s in streams)

            return TcpflowResult(
                pcap_file=pcap_file,
                output_dir=output_dir,
                stream_count=len(streams),
                streams=streams,
                total_bytes=total_bytes,
            )

        except Exception as e:
            raise CaptureError(f"tcpflow extraction failed for {pcap_file}", str(e)) from e

    def extract_live(
        self,
        interface: str,
        output_dir: str | None = None,
        timeout: int = 60,
    ) -> TcpflowResult:
        """
        Extract TCP streams from live traffic.

        Args:
            interface: Network interface to capture on
            output_dir: Output directory for stream files
            timeout: Capture timeout in seconds

        Returns:
            TcpflowResult with extracted streams
        """
        if not is_root():
            raise CaptureError("tcpflow live capture requires root privileges")

        if output_dir is None:
            output_dir = f"tcpflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        Path(output_dir).mkdir(parents=True, exist_ok=True)

        cmd = ["tcpflow", "-i", interface, "-o", output_dir]

        # TimeoutExpired is expected when timeout is reached during live capture
        with contextlib.suppress(subprocess.TimeoutExpired):
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

        streams = self._parse_output_dir(output_dir, 100)
        total_bytes = sum(s.size_bytes for s in streams)

        return TcpflowResult(
            pcap_file="live",
            output_dir=output_dir,
            stream_count=len(streams),
            streams=streams,
            total_bytes=total_bytes,
        )

    def _parse_output_dir(self, output_dir: str, max_files: int) -> list[TcpflowStream]:
        """Parse tcpflow output directory for stream files."""
        streams = []
        output_path = Path(output_dir)

        for i, filepath in enumerate(sorted(output_path.iterdir())):
            if i >= max_files:
                break

            if not filepath.is_file():
                continue

            # Skip report files
            if filepath.suffix in (".xml", ".txt"):
                continue

            # Parse filename: 192.168.001.001.00443-192.168.001.002.12345
            stream = self._parse_stream_file(filepath)
            if stream:
                streams.append(stream)

        return streams

    def _parse_stream_file(self, filepath: Path) -> TcpflowStream | None:
        """Parse a single tcpflow stream file."""
        filename = filepath.name

        # Format: srcip.srcport-dstip.dstport
        match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\.(\d+)-(\d+\.\d+\.\d+\.\d+)\.(\d+)$",
            filename,
        )

        if not match:
            return None

        # Read preview
        try:
            size = filepath.stat().st_size
            with open(filepath, "rb") as f:
                preview_bytes = f.read(256)
                try:
                    preview = preview_bytes.decode("utf-8", errors="replace")
                except Exception:
                    preview = preview_bytes.hex()[:256]
        except Exception:
            size = 0
            preview = None

        # Normalize IP format (remove leading zeros)
        def normalize_ip(ip: str) -> str:
            return ".".join(str(int(x)) for x in ip.split("."))

        return TcpflowStream(
            source_ip=normalize_ip(match.group(1)),
            source_port=int(match.group(2)),
            dest_ip=normalize_ip(match.group(3)),
            dest_port=int(match.group(4)),
            filename=str(filepath),
            size_bytes=size,
            content_preview=preview,
        )
