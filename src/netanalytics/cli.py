"""CLI entry point for Network Analytics Toolkit."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .core.config import get_config
from .core.utils import get_default_interface, get_interfaces, is_root

console = Console()


def print_error(message: str) -> None:
    """Print error message in red."""
    console.print(f"[red]Error:[/red] {message}")


def print_success(message: str) -> None:
    """Print success message in green."""
    console.print(f"[green]✓[/green] {message}")


def print_warning(message: str) -> None:
    """Print warning message in yellow."""
    console.print(f"[yellow]Warning:[/yellow] {message}")


@click.group()
@click.version_option(version=__version__, prog_name="netanalytics")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("--fast", is_flag=True, help="Disable rate limiting for faster scans")
@click.pass_context
def main(ctx: click.Context, verbose: bool, fast: bool) -> None:
    """Network Analytics Toolkit - Discovery, scanning, traffic analysis, and topology mapping."""
    ctx.ensure_object(dict)
    config = get_config()
    config.verbose = verbose
    config.fast_mode = fast
    ctx.obj["config"] = config


@main.command()
@click.argument("network")
@click.option(
    "--method",
    type=click.Choice(["arp", "icmp"]),
    default="arp",
    help="Discovery method (default: arp)",
)
@click.option("--timeout", type=float, default=2.0, help="Timeout per host in seconds")
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON)")
@click.pass_context
def discover(
    ctx: click.Context,
    network: str,
    method: str,
    timeout: float,
    output: str | None,
) -> None:
    """Discover hosts on a network using ARP or ICMP scanning."""
    from .discovery import arp_scan

    if method == "arp" and not is_root():
        print_error("ARP scan requires root privileges. Run with sudo.")
        sys.exit(1)

    if method == "icmp" and not is_root():
        print_error("ICMP scan requires root privileges. Run with sudo.")
        sys.exit(1)

    console.print(f"[bold]Discovering hosts on {network} using {method.upper()}...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)

        try:
            if method == "arp":
                results = arp_scan(network, timeout=timeout)
            else:
                from .discovery.icmp_scan import icmp_scan_alive_only

                results = icmp_scan_alive_only(network, timeout=timeout)

            progress.update(task, completed=True)
        except Exception as e:
            print_error(str(e))
            sys.exit(1)

    if not results:
        console.print("[yellow]No hosts discovered.[/yellow]")
        return

    # Display results
    table = Table(title=f"Discovered Hosts ({len(results)})")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="green")
    table.add_column("Hostname", style="yellow")
    table.add_column("Vendor", style="magenta")

    for result in results:
        if method == "arp":
            table.add_row(
                result.ip,
                result.mac,
                result.hostname or "-",
                result.vendor or "-",
            )
        else:
            table.add_row(result.ip, "-", result.hostname or "-", "-")

    console.print(table)

    # Save to file if requested
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"network": network, "method": method, "hosts": [r.to_dict() for r in results]}
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print_success(f"Results saved to {output_path}")


@main.command()
@click.argument("target")
@click.option("--ports", "-p", default="1-1000", help="Port range (e.g., '1-1000' or '22,80,443')")
@click.option(
    "--type",
    "scan_type",
    type=click.Choice(["syn", "connect"]),
    default="connect",
    help="Scan type (default: connect)",
)
@click.option("--timeout", type=float, default=2.0, help="Timeout per port in seconds")
@click.option("--banner", is_flag=True, help="Grab service banners (connect scan only)")
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON)")
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    ports: str,
    scan_type: str,
    timeout: float,
    banner: bool,
    output: str | None,
) -> None:
    """Scan ports on a target host."""
    from .discovery import port_scan

    if scan_type == "syn" and not is_root():
        print_error("SYN scan requires root privileges. Run with sudo or use --type connect.")
        sys.exit(1)

    console.print(f"[bold]Scanning {target} ports {ports} ({scan_type} scan)...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning ports...", total=None)

        try:
            result = port_scan(
                target,
                ports=ports,
                scan_type=scan_type,
                timeout=timeout,
                grab_banner=banner,
            )
            progress.update(task, completed=True)
        except Exception as e:
            print_error(str(e))
            sys.exit(1)

    open_ports = result.get_open_ports()

    if not open_ports:
        console.print("[yellow]No open ports found.[/yellow]")
    else:
        table = Table(title=f"Open Ports on {target} ({len(open_ports)} found)")
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Banner", style="dim")

        for port in open_ports:
            banner_display = "-"
            if port.banner:
                banner_display = (
                    port.banner[:50] + "..."
                    if len(port.banner) > 50
                    else port.banner
                )
            table.add_row(
                str(port.port),
                port.state.value,
                port.service or "-",
                banner_display,
            )

        console.print(table)

    # Summary
    console.print(
        Panel(
            f"[green]Open: {result.open_count}[/green] | "
            f"[red]Closed: {result.closed_count}[/red] | "
            f"[yellow]Filtered: {result.filtered_count}[/yellow] | "
            f"Duration: {(result.end_time - result.start_time).total_seconds():.2f}s",
            title="Scan Summary",
        )
    )

    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        print_success(f"Results saved to {output_path}")


@main.command()
@click.argument("interface", required=False)
@click.option("--count", "-c", type=int, default=100, help="Number of packets to capture")
@click.option("--timeout", "-t", type=int, default=60, help="Capture timeout in seconds")
@click.option("--filter", "-f", "bpf_filter", help="BPF filter expression")
@click.option("--output", "-o", type=click.Path(), help="Output pcap file")
@click.pass_context
def capture(
    ctx: click.Context,
    interface: str | None,
    count: int,
    timeout: int,
    bpf_filter: str | None,
    output: str | None,
) -> None:
    """Capture network traffic on an interface."""
    from .traffic import capture_packets

    if not is_root():
        print_error("Packet capture requires root privileges. Run with sudo.")
        sys.exit(1)

    interface = interface or get_default_interface()
    if not interface:
        print_error("No network interface specified and could not detect default.")
        sys.exit(1)

    console.print(
        f"[bold]Capturing on {interface} (max {count} packets, {timeout}s timeout)...[/bold]"
    )
    if bpf_filter:
        console.print(f"[dim]Filter: {bpf_filter}[/dim]")

    try:
        packets = capture_packets(
            interface=interface,
            count=count,
            timeout=timeout,
            bpf_filter=bpf_filter,
            output_file=output,
        )
        print_success(f"Captured {len(packets)} packets")

        if output:
            print_success(f"Saved to {output}")

    except Exception as e:
        print_error(str(e))
        sys.exit(1)


@main.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "--protocol",
    type=click.Choice(["all", "http", "dns", "tcp", "udp"]),
    default="all",
    help="Protocol to analyze",
)
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON)")
@click.pass_context
def analyze(
    ctx: click.Context,
    pcap_file: str,
    protocol: str,
    output: str | None,
) -> None:
    """Analyze a pcap file."""
    from .traffic import analyze_pcap

    console.print(f"[bold]Analyzing {pcap_file}...[/bold]")

    try:
        stats = analyze_pcap(pcap_file, protocol_filter=protocol)
        console.print(Panel(str(stats), title="Packet Analysis"))

        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(stats.to_dict(), f, indent=2)
            print_success(f"Results saved to {output_path}")

    except Exception as e:
        print_error(str(e))
        sys.exit(1)


@main.command()
@click.argument("network")
@click.option("--output", "-o", type=click.Path(), help="Output image file (PNG)")
@click.option(
    "--layout",
    type=click.Choice(["spring", "circular", "shell", "kamada_kawai"]),
    default="spring",
    help="Graph layout algorithm",
)
@click.option("--show", is_flag=True, help="Display graph interactively")
@click.pass_context
def topology(
    ctx: click.Context,
    network: str,
    output: str | None,
    layout: str,
    show: bool,
) -> None:
    """Generate network topology map."""
    from .topology import build_topology, visualize_topology

    if not is_root():
        print_error("Topology discovery requires root privileges. Run with sudo.")
        sys.exit(1)

    console.print(f"[bold]Discovering topology for {network}...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Building topology...", total=None)

        try:
            graph = build_topology(network)
            progress.update(task, completed=True)
        except Exception as e:
            print_error(str(e))
            sys.exit(1)

    console.print(
        f"[green]Discovered {graph.number_of_nodes()} nodes "
        f"and {graph.number_of_edges()} connections[/green]"
    )

    if output or show:
        visualize_topology(graph, output_file=output, layout=layout, show=show)
        if output:
            print_success(f"Topology saved to {output}")


@main.command()
@click.argument("target")
@click.option(
    "--level",
    type=click.Choice(["basic", "full"]),
    default="basic",
    help="Assessment level",
)
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON)")
@click.pass_context
def security(ctx: click.Context, target: str, level: str, output: str | None) -> None:
    """Run security assessment on a target."""
    from .security import security_assessment

    console.print(f"[bold]Running {level} security assessment on {target}...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Assessing...", total=None)

        try:
            result = security_assessment(target, level=level)
            progress.update(task, completed=True)
        except Exception as e:
            print_error(str(e))
            sys.exit(1)

    console.print(Panel(str(result), title="Security Assessment"))

    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        print_success(f"Results saved to {output_path}")


@main.command()
@click.argument("target")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["html", "md", "json"]),
    default="html",
    help="Report format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.pass_context
def report(ctx: click.Context, target: str, output_format: str, output: str | None) -> None:
    """Generate comprehensive network report."""
    from .output import generate_report

    console.print(f"[bold]Generating {output_format.upper()} report for {target}...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating report...", total=None)

        try:
            report_path = generate_report(target, output_format=output_format, output_file=output)
            progress.update(task, completed=True)
        except Exception as e:
            print_error(str(e))
            sys.exit(1)

    print_success(f"Report saved to {report_path}")


@main.command("list-interfaces")
def list_interfaces() -> None:
    """List available network interfaces."""
    interfaces = get_interfaces()

    table = Table(title="Network Interfaces")
    table.add_column("Interface", style="cyan")
    table.add_column("IPv4", style="green")
    table.add_column("MAC", style="yellow")
    table.add_column("Status", style="magenta")

    for name, info in interfaces.items():
        status = "[green]UP[/green]" if info.get("is_up") else "[red]DOWN[/red]"
        table.add_row(
            name,
            info.get("ipv4") or "-",
            info.get("mac") or "-",
            status,
        )

    console.print(table)


if __name__ == "__main__":
    main()
