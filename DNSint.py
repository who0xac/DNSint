#!/usr/bin/env python3
"""
DNSint v1.1 - DNS Intelligence Toolkit
A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis
Created by wh0xac
"""

import argparse
import json
import socket
import sys
import re
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple

import dns.resolver
import dns.query
import dns.zone
import dns.exception
import dns.reversename
import dns.message
import dns.rdatatype
import requests
import whois as whois_lib
from ipwhois import IPWhois
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.layout import Layout
from rich.syntax import Syntax
from rich import box
from rich.text import Text
from bs4 import BeautifulSoup

console = Console()

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "NAPTR", "DNSKEY", "DS"]

PUBLIC_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9"
}

def get_desktop_path() -> Path:
    """Get the desktop directory path cross-platform (Windows/Mac/Linux)"""
    home = Path.home()
    
    if sys.platform == "win32":
        desktop = home / "Desktop"
    elif sys.platform == "darwin":
        desktop = home / "Desktop"
    else:
        desktop = home / "Desktop"
        if not desktop.exists():
            desktop = home
    
    if not desktop.exists():
        desktop = home
    
    return desktop

def print_banner():
    """Display the enhanced ASCII banner with version and creator"""
    banner = """
[bold cyan]     ▗▄▄▄  ▗▖  ▗▖ ▗▄▄▖                                [/bold cyan]
[bold cyan]     ▐▌  ▐▌▐▛▚▖▐▌▐▌                                   [/bold cyan]
[bold cyan]     ▐▌  ▐▌▐▌ ▝▜▌ ▝▀▚▖                                [/bold cyan]
[bold cyan]     ▐▙▄▄▀ ▐▌  ▐▌▗▄▄▞▘  [/bold cyan][bold white]int[/bold white]

[bold cyan]    ═══════════════════════════════ [/bold cyan]
[bold yellow]    v1.1, by wh0xac                                [/bold yellow]
"""
    
    console.print(banner)


def join_txt_chunks(txt_value: str) -> str:
    """Join multi-chunk TXT records (quoted strings) into a single string"""
    parts = re.findall(r'"([^"]*)"', txt_value)
    if parts:
        return ''.join(parts)
    return txt_value.strip('"')

def create_resolver(timeout: int = 5, dns_server: Optional[str] = None) -> dns.resolver.Resolver:
    """Create a DNS resolver with optional custom DNS server"""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    if dns_server:
        resolver.nameservers = [dns_server]
    return resolver


def update_tool():
    """Update DNSint to the latest version from GitHub"""
    console.print("\n[bold cyan]Checking for updates...[/bold cyan]\n")

    try:
        import subprocess

        # Check if we're in a git repository
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            console.print("[red]Error:[/red] Not a git repository. Please clone from GitHub:")
            console.print("[cyan]git clone https://github.com/who0xac/DNSint.git[/cyan]\n")
            sys.exit(1)

        # Fetch latest changes
        console.print("[yellow]Fetching latest changes...[/yellow]")
        subprocess.run(["git", "fetch", "origin"], check=True, timeout=30)

        # Check if there are updates
        result = subprocess.run(
            ["git", "rev-list", "HEAD...origin/main", "--count"],
            capture_output=True,
            text=True,
            timeout=5
        )

        commits_behind = int(result.stdout.strip())

        if commits_behind == 0:
            console.print("[green]✓ You're already on the latest version![/green]\n")
            sys.exit(0)

        console.print(f"[yellow]Found {commits_behind} new commit(s)[/yellow]\n")

        # Show what will be updated
        console.print("[cyan]Latest changes:[/cyan]")
        subprocess.run(
            ["git", "log", "HEAD..origin/main", "--oneline", "--no-decorate"],
            timeout=5
        )
        console.print()

        # Pull updates
        console.print("[yellow]Updating DNSint...[/yellow]")
        subprocess.run(["git", "pull", "origin", "main"], check=True, timeout=30)

        console.print("\n[green]✓ DNSint updated successfully![/green]")
        console.print("[dim]You may need to reinstall dependencies: pip install -r requirements.txt[/dim]\n")
        sys.exit(0)

    except subprocess.TimeoutExpired:
        console.print("[red]Error:[/red] Update timed out. Please try again.\n")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error:[/red] Update failed: {e}\n")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}\n")
        sys.exit(1)

def get_parent_zone(domain: str) -> Optional[str]:
    """Get the parent zone for a domain (for DS record lookup)"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[1:])
    return None


def detect_technologies(domain: str, timeout: int, verbose: bool) -> Dict[str, Any]:
    """Detect web technologies, frameworks, CMS, and server information"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Detecting web technologies and server info...", total=None)
        
        tech_data = {
            "web_server": None,
            "frameworks": [],
            "cms": None,
            "analytics": [],
            "cdn": None,
            "hosting_provider": None,
            "technologies": [],
            "security_headers": {},
            "ssl_info": {},
            "checked": False,
            "error": None
        }
        
        try:
            protocols = ["https://", "http://"]
            response = None
            
            for protocol in protocols:
                try:
                    url = f"{protocol}{domain}"
                    response = requests.get(url, timeout=timeout, allow_redirects=True, 
                                          headers={'User-Agent': 'DNSint/1.0 Security Scanner'})
                    tech_data["checked"] = True
                    break
                except requests.exceptions.SSLError:
                    if protocol == "https://":
                        continue
                except requests.exceptions.ConnectionError:
                    continue
                except requests.exceptions.Timeout:
                    continue
            
            if not response:
                tech_data["error"] = "Could not connect to web server"
                return tech_data
            
            headers = response.headers
            
            if 'Server' in headers:
                tech_data["web_server"] = headers['Server']
            
            tech_data["security_headers"] = {
                "X-Frame-Options": headers.get("X-Frame-Options", "Not Set"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Not Set"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not Set"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not Set"),
                "X-XSS-Protection": headers.get("X-XSS-Protection", "Not Set"),
                "Referrer-Policy": headers.get("Referrer-Policy", "Not Set"),
                "Permissions-Policy": headers.get("Permissions-Policy", "Not Set")
            }
            
            if 'X-Powered-By' in headers:
                tech_data["technologies"].append(f"X-Powered-By: {headers['X-Powered-By']}")
            
            if 'CF-Ray' in headers or 'cf-ray' in headers:
                tech_data["cdn"] = "Cloudflare"
            elif 'X-Amz-Cf-Id' in headers:
                tech_data["cdn"] = "Amazon CloudFront"
            elif 'X-CDN' in headers:
                tech_data["cdn"] = headers['X-CDN']
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                if meta.get('name', '').lower() == 'generator':
                    content = meta.get('content', '')
                    if 'WordPress' in content:
                        tech_data["cms"] = f"WordPress ({content})"
                    elif 'Drupal' in content:
                        tech_data["cms"] = f"Drupal ({content})"
                    elif 'Joomla' in content:
                        tech_data["cms"] = f"Joomla ({content})"
                    else:
                        tech_data["cms"] = content
            
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src', '')
                
                if 'react' in src.lower():
                    if 'React' not in tech_data["frameworks"]:
                        tech_data["frameworks"].append("React")
                elif 'vue' in src.lower():
                    if 'Vue.js' not in tech_data["frameworks"]:
                        tech_data["frameworks"].append("Vue.js")
                elif 'angular' in src.lower():
                    if 'Angular' not in tech_data["frameworks"]:
                        tech_data["frameworks"].append("Angular")
                elif 'jquery' in src.lower():
                    if 'jQuery' not in tech_data["frameworks"]:
                        tech_data["frameworks"].append("jQuery")
                elif 'bootstrap' in src.lower():
                    if 'Bootstrap' not in tech_data["frameworks"]:
                        tech_data["frameworks"].append("Bootstrap")
                
                if 'google-analytics' in src or 'analytics.js' in src or 'gtag' in src:
                    if 'Google Analytics' not in tech_data["analytics"]:
                        tech_data["analytics"].append("Google Analytics")
                elif 'googletagmanager' in src:
                    if 'Google Tag Manager' not in tech_data["analytics"]:
                        tech_data["analytics"].append("Google Tag Manager")
                elif 'facebook.net' in src or 'fbevents.js' in src:
                    if 'Facebook Pixel' not in tech_data["analytics"]:
                        tech_data["analytics"].append("Facebook Pixel")
                elif 'hotjar' in src:
                    if 'Hotjar' not in tech_data["analytics"]:
                        tech_data["analytics"].append("Hotjar")
            
            page_content = response.text.lower()
            
            if 'wp-content' in page_content or 'wp-includes' in page_content:
                if not tech_data["cms"] or 'WordPress' not in tech_data["cms"]:
                    tech_data["cms"] = "WordPress"
            elif '/sites/default/' in page_content or 'drupal' in page_content:
                if not tech_data["cms"]:
                    tech_data["cms"] = "Drupal"
            elif 'shopify' in page_content:
                if not tech_data["cms"]:
                    tech_data["cms"] = "Shopify"
            elif 'wix.com' in page_content:
                tech_data["hosting_provider"] = "Wix"
            elif 'squarespace' in page_content:
                tech_data["hosting_provider"] = "Squarespace"
            
            if response.url:
                tech_data["ssl_info"]["protocol_used"] = "HTTPS" if response.url.startswith("https") else "HTTP"
        
        except Exception as e:
            tech_data["error"] = f"Error detecting technologies: {str(e)}"
    
    return tech_data


def display_technology_info(tech_data: Dict[str, Any], quiet: bool):
    """Display detected technologies and server information"""
    if quiet or not tech_data.get("checked"):
        return
    
    if tech_data.get("error"):
        console.print(f"\n[yellow]⚠ Technology Detection: {tech_data['error']}[/yellow]\n")
        return
    
    tree = Tree("[bold cyan]🔧 Technology Stack & Server Analysis[/bold cyan]", guide_style="cyan")
    
    if tech_data.get("web_server"):
        server_branch = tree.add("[bold]Web Server[/bold]")
        server_branch.add(f"[green]{tech_data['web_server']}[/green]")
    
    if tech_data.get("cms"):
        cms_branch = tree.add("[bold]Content Management System (CMS)[/bold]")
        cms_branch.add(f"[green]{tech_data['cms']}[/green]")
    
    if tech_data.get("frameworks"):
        framework_branch = tree.add(f"[bold]Frameworks & Libraries ({len(tech_data['frameworks'])})[/bold]")
        for framework in tech_data["frameworks"]:
            framework_branch.add(f"[cyan]• {framework}[/cyan]")
    
    if tech_data.get("analytics"):
        analytics_branch = tree.add(f"[bold]Analytics & Tracking ({len(tech_data['analytics'])})[/bold]")
        for analytic in tech_data["analytics"]:
            analytics_branch.add(f"[yellow]• {analytic}[/yellow]")
    
    if tech_data.get("cdn"):
        cdn_branch = tree.add("[bold]Content Delivery Network (CDN)[/bold]")
        cdn_branch.add(f"[magenta]{tech_data['cdn']}[/magenta]")
    
    if tech_data.get("hosting_provider"):
        hosting_branch = tree.add("[bold]Hosting Provider[/bold]")
        hosting_branch.add(f"[blue]{tech_data['hosting_provider']}[/blue]")
    
    if tech_data.get("technologies"):
        tech_branch = tree.add("[bold]Additional Technologies[/bold]")
        for tech in tech_data["technologies"]:
            tech_branch.add(f"[dim]• {tech}[/dim]")
    
    security_headers = tech_data.get("security_headers", {})
    if security_headers:
        sec_branch = tree.add("[bold]HTTP Security Headers[/bold]")
        for header, value in security_headers.items():
            if value == "Not Set":
                sec_branch.add(f"[red]✗ {header}: {value}[/red]")
            else:
                short_value = value[:50] + "..." if len(value) > 50 else value
                sec_branch.add(f"[green]✓ {header}: {short_value}[/green]")
    
    if tech_data.get("ssl_info", {}).get("protocol_used"):
        ssl_branch = tree.add("[bold]Protocol[/bold]")
        protocol = tech_data["ssl_info"]["protocol_used"]
        if protocol == "HTTPS":
            ssl_branch.add(f"[green]✓ {protocol}[/green]")
        else:
            ssl_branch.add(f"[red]✗ {protocol} (Not Secure)[/red]")
    
    console.print()
    console.print(Panel(tree, border_style="cyan", box=box.ROUNDED))
    console.print()


def display_dns_records_table(records: Dict[str, List[Any]], quiet: bool):
    """Display DNS records in a beautiful table"""
    if quiet:
        return
    
    table = Table(
        title="[bold cyan]DNS Records Discovery[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="cyan"
    )
    
    table.add_column("Type", style="cyan bold", width=10)
    table.add_column("Value", style="white", max_width=50)
    table.add_column("TTL", style="yellow", width=8)
    table.add_column("Extra", style="green", width=20)
    
    total_records = 0
    for rtype in RECORD_TYPES:
        record_list = records.get(rtype, [])
        if record_list:
            for idx, record in enumerate(record_list):
                total_records += 1
                value = record.get("value", "")
                ttl = str(record.get("ttl", "N/A"))
                
                extra = ""
                if rtype == "MX" and "priority" in record:
                    extra = f"Priority: {record['priority']}"
                elif rtype == "SRV":
                    extra = f"P:{record.get('priority')} W:{record.get('weight')} Port:{record.get('port')}"
                
                type_display = rtype if idx == 0 else ""
                
                if len(value) > 50:
                    value = value[:47] + "..."
                
                table.add_row(type_display, value, ttl, extra)
            
            if len(record_list) > 1:
                table.add_row("", "", "", "", end_section=True)
    
    if total_records == 0:
        table.add_row("[dim]No records found[/dim]", "", "", "")
    
    console.print()
    console.print(table)
    console.print(f"[dim]Total: {total_records} DNS records found[/dim]\n")


def display_ptr_table(ptr_results: Dict[str, List[str]], quiet: bool):
    """Display PTR lookups in a beautiful table"""
    if quiet or not ptr_results:
        return
    
    table = Table(
        title="[bold cyan]Reverse PTR Lookups[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="cyan"
    )
    
    table.add_column("IP Address", style="cyan bold", width=20)
    table.add_column("PTR Record", style="white")
    table.add_column("Status", style="green", width=12)
    
    for ip, ptrs in sorted(ptr_results.items()):
        if ptrs:
            status = "[green]✓ Found[/green]"
            ptr_display = ", ".join(ptrs)
        else:
            status = "[dim]○ None[/dim]"
            ptr_display = "[dim]No PTR record[/dim]"
        
        table.add_row(ip, ptr_display, status)
    
    console.print(table)
    console.print()


def display_axfr_results(axfr_results: Dict[str, Any], quiet: bool):
    """Display AXFR results in a beautiful table"""
    if quiet or not axfr_results:
        return
    
    table = Table(
        title="[bold cyan]Zone Transfer (AXFR) Security Test[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="cyan"
    )
    
    table.add_column("Nameserver", style="cyan bold", width=30)
    table.add_column("IP Addresses", style="white", width=20)
    table.add_column("AXFR Status", style="white", width=20)
    table.add_column("Risk", style="white", width=15)
    
    for ns, data in sorted(axfr_results.items()):
        ips = ", ".join(data.get("ips", []))
        
        if data.get("axfr_allowed"):
            status = "[red bold]✗ ALLOWED[/red bold]"
            risk = "[red]CRITICAL[/red]"
        else:
            status = "[green]✓ Denied[/green]"
            risk = "[green]Secure[/green]"
        
        zone_count = len(data.get("zone_records", []))
        if zone_count > 0:
            status += f"\n[red]({zone_count} records exposed)[/red]"
        
        table.add_row(ns, ips, status, risk)
    
    console.print(table)
    console.print()


def display_email_security(email_sec: Dict[str, Any], quiet: bool):
    """Display email security analysis in beautiful panels"""
    if quiet:
        return
    
    tree = Tree("[bold cyan]📧 Email Security Analysis[/bold cyan]", guide_style="cyan")
    
    spf_branch = tree.add("[bold]SPF (Sender Policy Framework)[/bold]")
    if email_sec["spf"]["present"]:
        spf_branch.add(f"[green]✓ SPF Record Found[/green]")
        spf_record = email_sec['spf']['record']
        if len(spf_record) > 80:
            spf_record = spf_record[:80] + "..."
        spf_branch.add(f"[dim]Record:[/dim] {spf_record}")
        spf_branch.add(f"[yellow]DNS Lookups:[/yellow] {email_sec['spf']['total_lookups']} (limit: 10)")
        
        if email_sec['spf']['includes']:
            includes_tree = spf_branch.add(f"[cyan]Includes ({len(email_sec['spf']['includes'])}):[/cyan]")
            for inc in email_sec['spf']['includes'][:5]:
                includes_tree.add(f"• {inc}")
        
        if email_sec['spf']['issues']:
            issues_tree = spf_branch.add("[yellow]⚠ Issues:[/yellow]")
            for issue in email_sec['spf']['issues']:
                issues_tree.add(f"[yellow]• {issue}[/yellow]")
    else:
        spf_branch.add("[red]✗ No SPF Record Found[/red]")
    
    dmarc_branch = tree.add("[bold]DMARC (Domain-based Message Authentication)[/bold]")
    if email_sec["dmarc"]["present"]:
        policy = email_sec["dmarc"]["policy"]
        if policy == "reject":
            policy_color = "green"
        elif policy == "quarantine":
            policy_color = "yellow"
        else:
            policy_color = "red"
        
        dmarc_branch.add(f"[green]✓ DMARC Record Found[/green]")
        dmarc_branch.add(f"[{policy_color}]Policy: {policy}[/{policy_color}]")
        
        if email_sec['dmarc']['issues']:
            issues_tree = dmarc_branch.add("[yellow]⚠ Issues:[/yellow]")
            for issue in email_sec['dmarc']['issues']:
                issues_tree.add(f"[yellow]• {issue}[/yellow]")
    else:
        dmarc_branch.add("[red]✗ No DMARC Record Found[/red]")
    
    dkim_branch = tree.add("[bold]DKIM (DomainKeys Identified Mail)[/bold]")
    if email_sec["dkim"]["selectors_found"]:
        dkim_branch.add(f"[green]✓ DKIM Selectors Found: {len(email_sec['dkim']['selectors_found'])}[/green]")
        for selector in email_sec['dkim']['selectors_found']:
            dkim_branch.add(f"[cyan]• {selector}[/cyan]")
    else:
        dkim_branch.add("[dim]○ No common DKIM selectors detected[/dim]")
    
    console.print()
    console.print(Panel(tree, border_style="cyan", box=box.ROUNDED))
    console.print()


def display_whois_info(whois_data: Dict[str, Any], quiet: bool):
    """Display enhanced WHOIS information in a beautiful panel"""
    if quiet:
        return
    
    table = Table(
        title="[bold cyan]WHOIS Registration Information[/bold cyan]",
        box=box.ROUNDED,
        show_header=False,
        border_style="cyan"
    )
    
    table.add_column("Field", style="cyan bold", width=25)
    table.add_column("Value", style="white")
    
    table.add_row("Domain Name", whois_data.get("domain_name") or "[dim]Unknown[/dim]")
    table.add_row("Registrar", whois_data.get("registrar") or "[dim]Unknown[/dim]")
    
    if whois_data.get("registrant_org"):
        org = whois_data["registrant_org"]
        if isinstance(org, list):
            org = org[0] if org else "Unknown"
        table.add_row("Registrant Organization", str(org))

    if whois_data.get("registrant_country"):
        country = whois_data["registrant_country"]
        if isinstance(country, list):
            country = country[0] if country else "Unknown"
        table.add_row("Registrant Country", str(country))
    
    table.add_row("Created", whois_data.get("creation_date") or "[dim]Unknown[/dim]")
    table.add_row("Updated", whois_data.get("updated_date") or "[dim]Unknown[/dim]")
    
    expiry = whois_data.get("expiration_date") or "[dim]Unknown[/dim]"
    days = whois_data.get("days_until_expiry")
    if days is not None:
        if days < 30:
            expiry += f" [red]({days} days left!)[/red]"
        elif days < 90:
            expiry += f" [yellow]({days} days left)[/yellow]"
        else:
            expiry += f" [green]({days} days left)[/green]"
    table.add_row("Expires", expiry)
    
    privacy = "[yellow]Yes[/yellow]" if whois_data.get("privacy") else "[green]No[/green]"
    table.add_row("Privacy Protection", privacy)
    
    if whois_data.get("status"):
        status_list = whois_data["status"][:3]
        table.add_row("Status", ", ".join(status_list))
    
    if whois_data.get("admin_email"):
        table.add_row("Admin Email", whois_data["admin_email"])
    
    if whois_data.get("tech_email"):
        table.add_row("Tech Email", whois_data["tech_email"])
    
    if whois_data.get("name_servers"):
        ns_list = whois_data["name_servers"][:5]
        table.add_row("Name Servers", ", ".join(ns_list))
        if len(whois_data["name_servers"]) > 5:
            table.add_row("", f"[dim]... and {len(whois_data['name_servers']) - 5} more[/dim]")
    
    console.print(table)
    console.print()


def display_nameserver_analysis(ns_info: Dict[str, Any], quiet: bool):
    """Display nameserver analysis in beautiful format"""
    if quiet:
        return
    
    table = Table(
        title="[bold cyan]Nameserver Infrastructure Analysis[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="cyan"
    )
    
    table.add_column("Nameserver", style="cyan bold", width=30)
    table.add_column("IP Address", style="white", width=18)
    table.add_column("SOA Serial", style="yellow", width=12)
    table.add_column("ASN", style="green", width=12)
    table.add_column("Country", style="blue", width=8)
    
    for ns_host, ns_data in ns_info["nameservers"].items():
        ips = ns_data.get("ips", [])
        ip_display = ips[0] if ips else "[dim]N/A[/dim]"
        
        soa_serial = str(ns_data.get("soa_serial", "N/A"))
        asn = f"AS{ns_data.get('asn')}" if ns_data.get('asn') else "[dim]N/A[/dim]"
        country = ns_data.get("country") or "[dim]--[/dim]"
        
        table.add_row(ns_host, ip_display, soa_serial, asn, country)
    
    console.print(table)
    
    info_panel = ""
    dnssec = ns_info["dnssec"]
    if dnssec["enabled"]:
        info_panel += f"[green]✓ DNSSEC Enabled[/green]\n"
        info_panel += f"  • DNSKEY records: {dnssec['dnskey_count']}\n"
        info_panel += f"  • DS records at parent: {'Yes' if dnssec['has_ds'] else 'No (chain incomplete!)'}\n"
    else:
        info_panel += "[yellow]⚠ DNSSEC Not Enabled[/yellow]\n"
    
    if ns_info["issues"]:
        info_panel += "\n[yellow]⚠ Infrastructure Issues:[/yellow]\n"
        for issue in ns_info["issues"]:
            info_panel += f"  • {issue}\n"
    
    console.print(Panel(info_panel.strip(), border_style="yellow" if ns_info["issues"] else "green", box=box.ROUNDED))
    console.print()


def display_propagation(propagation: Dict[str, Any], quiet: bool):
    """Display DNS propagation status"""
    if quiet:
        return
    
    table = Table(
        title="[bold cyan]DNS Propagation Check[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="cyan"
    )
    
    table.add_column("Resolver", style="cyan bold", width=15)
    table.add_column("Method", style="magenta", width=10)
    table.add_column("A Records", style="green", width=20)
    table.add_column("MX Records", style="yellow", width=12)
    table.add_column("Status", style="white", width=12)
    
    for resolver_name, data in propagation.items():
        method = data.get("method", "UDP")
        method_color = "cyan" if method == "UDP" else "magenta"
        
        a_records = ", ".join(data.get("A", [])) if data.get("A") else "[dim]None[/dim]"
        mx_count = len(data.get("MX", []))
        mx_display = f"{mx_count} record(s)" if mx_count > 0 else "[dim]None[/dim]"
        
        if data["status"] == "success":
            status = "[green]✓ Online[/green]"
        else:
            status = "[red]✗ Failed[/red]"
        
        table.add_row(resolver_name, f"[{method_color}]{method}[/{method_color}]", a_records, mx_display, status)
    
    console.print(table)
    console.print()


def display_security_audit(security: Dict[str, Any], quiet: bool):
    """Display security audit results"""
    if quiet:
        return
    
    tree = Tree("[bold red]🔒 Security Audit Results[/bold red]", guide_style="red")
    
    if security["critical"]:
        critical_branch = tree.add(f"[bold red]Critical Issues ({len(security['critical'])})[/bold red]")
        for issue in security["critical"]:
            critical_branch.add(f"[red]✗ {issue}[/red]")
    
    if security["warnings"]:
        warning_branch = tree.add(f"[bold yellow]Warnings ({len(security['warnings'])})[/bold yellow]")
        for warning in security["warnings"]:
            warning_branch.add(f"[yellow]⚠ {warning}[/yellow]")
    
    if security["info"]:
        info_branch = tree.add(f"[bold blue]Informational ({len(security['info'])})[/bold blue]")
        for info in security["info"][:5]:
            info_branch.add(f"[blue]ℹ {info}[/blue]")
    
    if not security["critical"] and not security["warnings"]:
        tree.add("[green]✓ No security issues detected[/green]")
    
    console.print()
    console.print(Panel(tree, border_style="red" if security["critical"] else "yellow" if security["warnings"] else "green", box=box.DOUBLE))
    console.print()


def display_osint_results(osint: Dict[str, Any], quiet: bool):
    """Display OSINT enrichment results"""
    if quiet:
        return
    
    ct_data = osint.get("cert_transparency", {})
    
    if not ct_data.get("checked"):
        return
    
    domains = ct_data.get("domains", [])
    
    if domains:
        table = Table(
            title=f"[bold cyan]🔍 OSINT - Certificate Transparency Logs ({len(domains)} domains)[/bold cyan]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            border_style="cyan"
        )
        
        table.add_column("#", style="dim", width=5)
        table.add_column("Related Domain", style="cyan")
        table.add_column("Type", style="yellow", width=15)
        
        for idx, domain in enumerate(domains[:15], 1):
            if domain.startswith("*."):
                domain_type = "[yellow]Wildcard[/yellow]"
            elif domain.count('.') > 2:
                domain_type = "[cyan]Subdomain[/cyan]"
            else:
                domain_type = "[green]Domain[/green]"
            
            table.add_row(str(idx), domain, domain_type)
        
        console.print(table)
        
        if len(domains) > 15:
            console.print(f"[dim]... and {len(domains) - 15} more domains (see JSON export for full list)[/dim]")
        console.print()


def get_dns_records(domain: str, timeout: int, verbose: bool, dns_server: Optional[str] = None) -> Dict[str, List[Any]]:
    """Query all major DNS record types"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Querying DNS records...", total=None)

        resolver = create_resolver(timeout, dns_server)
        records = {}
        
        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype, lifetime=timeout)
                record_list = []
                for rdata in answers:
                    record_info = {
                        "value": rdata.to_text(),
                        "ttl": answers.rrset.ttl if answers.rrset else None
                    }
                    
                    if rtype == "MX":
                        parts = rdata.to_text().split()
                        if len(parts) >= 2:
                            record_info["priority"] = parts[0]
                            record_info["value"] = parts[1]
                    
                    if rtype == "SRV":
                        parts = rdata.to_text().split()
                        if len(parts) >= 4:
                            record_info["priority"] = parts[0]
                            record_info["weight"] = parts[1]
                            record_info["port"] = parts[2]
                            record_info["value"] = parts[3]
                    
                    record_list.append(record_info)
                
                records[rtype] = record_list
            
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                records[rtype] = []
            except Exception:
                records[rtype] = []
    
    return records


def reverse_ptr_lookups(records: Dict, timeout: int, verbose: bool, dns_server: Optional[str] = None) -> Dict[str, List[str]]:
    """Perform reverse PTR lookups for discovered IPs"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Performing reverse PTR lookups...", total=None)

        resolver = create_resolver(timeout, dns_server)
        ptr_results = {}
        
        ip_list = []
        for rtype in ["A", "AAAA"]:
            for record in records.get(rtype, []):
                ip = record.get("value", "").split()[0]
                if ip:
                    ip_list.append(ip)
        
        for record in records.get("MX", []):
            mx_host = record.get("value", "").rstrip('.')
            if mx_host:
                try:
                    mx_ips = socket.gethostbyname_ex(mx_host)[2]
                    ip_list.extend(mx_ips)
                except Exception:
                    pass
        
        for ip in set(ip_list):
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(rev_name, "PTR", lifetime=timeout)
                ptr_results[ip] = [rdata.to_text() for rdata in answers]
            except Exception:
                ptr_results[ip] = []
    
    return ptr_results


def attempt_axfr(domain: str, records: Dict, timeout: int, verbose: bool, dns_server: Optional[str] = None) -> Dict[str, Any]:
    """Attempt AXFR zone transfers on nameservers"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Testing zone transfers (AXFR)...", total=None)
        
        axfr_results = {}
        ns_list = records.get("NS", [])
        
        ns_hosts = []
        for ns_record in ns_list:
            ns_host = ns_record.get("value", "").rstrip('.')
            if ns_host:
                ns_hosts.append(ns_host)
        
        for ns in sorted(set(ns_hosts)):
            try:
                ns_ips = socket.gethostbyname_ex(ns)[2]
            except Exception:
                ns_ips = []
            
            axfr_results[ns] = {
                "ips": ns_ips,
                "axfr_allowed": False,
                "zone_records": [],
                "record_count": 0
            }
            
            for ip in ns_ips:
                try:
                    z = dns.query.xfr(ip, domain, timeout=timeout)
                    zone = dns.zone.from_xfr(z)
                    if zone:
                        axfr_results[ns]["axfr_allowed"] = True
                        zone_names = [str(name) for name in zone.nodes.keys()]
                        axfr_results[ns]["zone_records"] = zone_names[:10]
                        axfr_results[ns]["record_count"] = len(zone_names)
                        break
                except Exception:
                    pass
    
    return axfr_results


def count_spf_lookups(spf_record: str, domain: str, timeout: int, depth: int = 0, max_depth: int = 5, seen: Set[str] = None) -> Tuple[int, Set[str]]:
    """Recursively count DNS lookups in SPF record"""
    if seen is None:
        seen = set()
    
    if depth > max_depth:
        return 0, seen
    
    if spf_record in seen:
        return 0, seen
    
    seen.add(spf_record)
    
    lookup_count = 0
    
    mechanisms = re.findall(r'(?<!\S)(?:[-~+?])?(a(?!ll)\b|mx\b|ptr\b|exists\b)(?::([^\s]+))?', spf_record, re.IGNORECASE)
    lookup_count += len(mechanisms)
    
    includes = re.findall(r'include:([^\s]+)', spf_record, re.IGNORECASE)
    for include_domain in includes:
        lookup_count += 1
        
        if depth < max_depth:
            try:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = timeout
                answers = resolver.resolve(include_domain, "TXT", lifetime=timeout)
                for rdata in answers:
                    txt = join_txt_chunks(rdata.to_text())
                    if "v=spf1" in txt.lower():
                        nested_count, seen = count_spf_lookups(txt, include_domain, timeout, depth + 1, max_depth, seen)
                        lookup_count += nested_count
                        break
            except Exception:
                pass
    
    return lookup_count, seen


def email_security_analysis(domain: str, records: Dict, timeout: int, verbose: bool, dns_server: Optional[str] = None) -> Dict[str, Any]:
    """Analyze SPF, DMARC, and DKIM configurations"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Analyzing email security (SPF/DMARC/DKIM)...", total=None)
        
        email_sec = {
            "spf": {"present": False, "record": None, "total_lookups": 0, "includes": [], "issues": []},
            "dmarc": {"present": False, "record": None, "policy": None, "issues": []},
            "dkim": {"selectors_found": []}
        }
        
        txt_records = records.get("TXT", [])
        for record in txt_records:
            value = join_txt_chunks(record.get("value", ""))
            if "v=spf1" in value.lower():
                email_sec["spf"]["present"] = True
                email_sec["spf"]["record"] = value
                
                includes = re.findall(r'include:([^\s]+)', value, re.IGNORECASE)
                email_sec["spf"]["includes"] = includes
                
                total_lookups, _ = count_spf_lookups(value, domain, timeout)
                email_sec["spf"]["total_lookups"] = total_lookups
                
                if total_lookups > 10:
                    email_sec["spf"]["issues"].append(f"Too many DNS lookups ({total_lookups}/10) - may cause SPF failures")
                
                if "~all" in value:
                    pass
                elif "-all" in value:
                    pass
                elif "+all" in value:
                    email_sec["spf"]["issues"].append("Uses +all (allows any server) - insecure")
                else:
                    email_sec["spf"]["issues"].append("No explicit all mechanism")
                
                break
        
        try:
            resolver = create_resolver(timeout, dns_server)
            dmarc_domain = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_domain, "TXT", lifetime=timeout)
            for rdata in answers:
                value = join_txt_chunks(rdata.to_text())
                if "v=DMARC1" in value:
                    email_sec["dmarc"]["present"] = True
                    email_sec["dmarc"]["record"] = value
                    
                    policy_match = re.search(r'p=([a-z]+)', value, re.IGNORECASE)
                    if policy_match:
                        email_sec["dmarc"]["policy"] = policy_match.group(1).lower()
                    
                    if email_sec["dmarc"]["policy"] == "none":
                        email_sec["dmarc"]["issues"].append("Policy set to 'none' - no action taken on failures")
                    
                    break
        except Exception:
            pass
        
        common_selectors = ["default", "google", "k1", "dkim", "mail", "selector1", "selector2", 
                           "s1", "s2", "mx", "email", "smtpapi"]
        
        for selector in common_selectors:
            try:
                resolver = create_resolver(timeout, dns_server)
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = resolver.resolve(dkim_domain, "TXT", lifetime=timeout)
                for rdata in answers:
                    value = join_txt_chunks(rdata.to_text())
                    if "v=DKIM1" in value or "p=" in value:
                        email_sec["dkim"]["selectors_found"].append(selector)
                        break
            except Exception:
                pass
    
    return email_sec


def whois_lookup(domain: str, verbose: bool) -> Dict[str, Any]:
    """Perform enhanced WHOIS lookup with extended information"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Performing WHOIS lookup...", total=None)
        
        whois_data = {
            "domain_name": None,
            "registrar": None,
            "registrant_org": None,
            "registrant_country": None,
            "creation_date": None,
            "updated_date": None,
            "expiration_date": None,
            "days_until_expiry": None,
            "status": [],
            "name_servers": [],
            "admin_email": None,
            "tech_email": None,
            "privacy": False
        }
        
        try:
            w = whois_lib.whois(domain)
            
            if hasattr(w, 'domain_name') and w.domain_name:
                if isinstance(w.domain_name, list):
                    whois_data["domain_name"] = w.domain_name[0]
                else:
                    whois_data["domain_name"] = w.domain_name
            
            if hasattr(w, 'registrar') and w.registrar:
                whois_data["registrar"] = w.registrar
            
            if hasattr(w, 'org') and w.org:
                whois_data["registrant_org"] = w.org
            
            if hasattr(w, 'country') and w.country:
                whois_data["registrant_country"] = w.country
            
            if hasattr(w, 'creation_date') and w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                if creation:
                    whois_data["creation_date"] = creation.strftime('%Y-%m-%d') if hasattr(creation, 'strftime') else str(creation)
            
            if hasattr(w, 'updated_date') and w.updated_date:
                updated = w.updated_date
                if isinstance(updated, list):
                    updated = updated[0]
                if updated:
                    whois_data["updated_date"] = updated.strftime('%Y-%m-%d') if hasattr(updated, 'strftime') else str(updated)
            
            if hasattr(w, 'expiration_date') and w.expiration_date:
                expiration = w.expiration_date
                if isinstance(expiration, list):
                    expiration = expiration[0]
                if expiration:
                    whois_data["expiration_date"] = expiration.strftime('%Y-%m-%d') if hasattr(expiration, 'strftime') else str(expiration)
                    
                    if hasattr(expiration, 'date'):
                        days_left = (expiration.date() - datetime.now().date()).days
                        whois_data["days_until_expiry"] = days_left
            
            if hasattr(w, 'status') and w.status:
                if isinstance(w.status, list):
                    whois_data["status"] = w.status
                else:
                    whois_data["status"] = [w.status]
            
            if hasattr(w, 'name_servers') and w.name_servers:
                if isinstance(w.name_servers, list):
                    whois_data["name_servers"] = [ns.lower() for ns in w.name_servers if ns]
                else:
                    whois_data["name_servers"] = [w.name_servers.lower()]
            
            if hasattr(w, 'emails') and w.emails:
                emails = w.emails if isinstance(w.emails, list) else [w.emails]
                for email in emails:
                    email_lower = email.lower()
                    if 'admin' in email_lower and not whois_data["admin_email"]:
                        whois_data["admin_email"] = email
                    elif 'tech' in email_lower and not whois_data["tech_email"]:
                        whois_data["tech_email"] = email
                    elif not whois_data["admin_email"]:
                        whois_data["admin_email"] = email
            
            if hasattr(w, 'name') and w.name:
                name_str = str(w.name).lower()
                if any(privacy_term in name_str for privacy_term in ['privacy', 'redacted', 'protected', 'proxy']):
                    whois_data["privacy"] = True
            
            if whois_data.get("registrant_org"):
                org_str = str(whois_data["registrant_org"]).lower()
                if any(privacy_term in org_str for privacy_term in ['privacy', 'redacted', 'protected', 'proxy']):
                    whois_data["privacy"] = True
        
        except Exception as e:
            if verbose:
                console.print(f"[yellow]WHOIS lookup failed: {str(e)}[/yellow]")
    
    return whois_data


def nameserver_analysis(domain: str, records: Dict, timeout: int, verbose: bool, dns_server: Optional[str] = None) -> Dict[str, Any]:
    """Analyze nameserver infrastructure and DNSSEC"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Analyzing nameserver infrastructure...", total=None)
        
        ns_info = {
            "nameservers": {},
            "dnssec": {"enabled": False, "has_dnskey": False, "has_ds": False, "dnskey_count": 0},
            "issues": []
        }
        
        ns_list = records.get("NS", [])
        ns_hosts = []
        for ns_record in ns_list:
            ns_host = ns_record.get("value", "").rstrip('.')
            if ns_host:
                ns_hosts.append(ns_host)
        
        soa_serials = set()
        
        for ns in sorted(set(ns_hosts)):
            ns_data = {"ips": [], "soa_serial": None, "asn": None, "org": None, "country": None}
            
            try:
                ns_ips = socket.gethostbyname_ex(ns)[2]
                ns_data["ips"] = ns_ips
            except Exception:
                ns_data["ips"] = []
            
            if ns_data["ips"]:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [ns_data["ips"][0]]
                    resolver.lifetime = timeout
                    soa_answers = resolver.resolve(domain, "SOA", lifetime=timeout)
                    for soa in soa_answers:
                        ns_data["soa_serial"] = soa.serial
                        soa_serials.add(soa.serial)
                        break
                except Exception:
                    pass
                
                try:
                    obj = IPWhois(ns_data["ips"][0])
                    results = obj.lookup_rdap(depth=1)
                    ns_data["asn"] = results.get("asn")
                    ns_data["org"] = results.get("asn_description", "")[:30]
                    ns_data["country"] = results.get("asn_country_code")
                except Exception:
                    pass
            
            ns_info["nameservers"][ns] = ns_data
        
        if len(soa_serials) > 1:
            ns_info["issues"].append(f"Inconsistent SOA serials across nameservers: {soa_serials}")
        
        dnskey_records = records.get("DNSKEY", [])
        if dnskey_records:
            ns_info["dnssec"]["has_dnskey"] = True
            ns_info["dnssec"]["dnskey_count"] = len(dnskey_records)
        
        ds_records = records.get("DS", [])
        if ds_records:
            ns_info["dnssec"]["has_ds"] = True
        else:
            parent_zone = get_parent_zone(domain)
            if parent_zone:
                try:
                    resolver = create_resolver(timeout, dns_server)
                    ds_answers = resolver.resolve(domain, "DS", lifetime=timeout)
                    if ds_answers:
                        ns_info["dnssec"]["has_ds"] = True
                except Exception:
                    pass
        
        if ns_info["dnssec"]["has_dnskey"] and ns_info["dnssec"]["has_ds"]:
            ns_info["dnssec"]["enabled"] = True
    
    return ns_info


def propagation_check(domain: str, timeout: int, verbose: bool, dns_server: Optional[str] = None) -> Dict[str, Any]:
    """Check DNS propagation across public resolvers"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Checking DNS propagation...", total=None)

        propagation = {}

        # Use custom DNS server if specified, otherwise use public resolvers
        resolvers_to_check = {"Custom": dns_server} if dns_server else PUBLIC_RESOLVERS

        for name, resolver_ip in resolvers_to_check.items():
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.lifetime = timeout
            
            propagation[name] = {
                "method": "UDP",
                "A": [],
                "MX": [],
                "status": "failed"
            }
            
            try:
                a_answers = resolver.resolve(domain, "A", lifetime=timeout)
                propagation[name]["A"] = [rdata.to_text() for rdata in a_answers]
                propagation[name]["status"] = "success"
            except Exception:
                pass
            
            try:
                mx_answers = resolver.resolve(domain, "MX", lifetime=timeout)
                propagation[name]["MX"] = [rdata.to_text() for rdata in mx_answers]
            except Exception:
                pass
    
    return propagation


def security_audit(domain: str, records: Dict, axfr_results: Dict, email_sec: Dict, ns_info: Dict, propagation: Dict, verbose: bool) -> Dict[str, Any]:
    """Perform security checks with improved signal quality"""
    security = {
        "critical": [],
        "warnings": [],
        "info": []
    }
    
    for ns, data in axfr_results.items():
        if data.get("axfr_allowed"):
            record_count = data.get("record_count", 0)
            security["critical"].append(f"Zone transfer (AXFR) allowed on {ns} - {record_count} records exposed")
    
    if not ns_info["dnssec"]["enabled"]:
        if ns_info["dnssec"]["has_dnskey"] and not ns_info["dnssec"]["has_ds"]:
            security["warnings"].append("DNSSEC incomplete: DNSKEY present but DS missing at parent zone")
        else:
            security["warnings"].append("DNSSEC not enabled")
    
    a_by_resolver = {}
    for resolver_name, data in propagation.items():
        if data.get("status") == "success" and data.get("A"):
            a_by_resolver[resolver_name] = set(data["A"])
    
    if len(a_by_resolver) > 1:
        all_a_sets = list(a_by_resolver.values())
        if not all(s == all_a_sets[0] for s in all_a_sets):
            security["warnings"].append(f"Conflicting A records across public resolvers - possible DNS poisoning or propagation issue")
    
    if not email_sec["spf"]["present"]:
        security["warnings"].append("No SPF record found")
    elif email_sec["spf"]["issues"]:
        security["warnings"].extend(email_sec["spf"]["issues"])
    
    if not email_sec["dmarc"]["present"]:
        security["warnings"].append("No DMARC record found")
    elif email_sec["dmarc"]["issues"]:
        security["warnings"].extend(email_sec["dmarc"]["issues"])
    
    if ns_info["issues"]:
        security["warnings"].extend(ns_info["issues"])
    
    if records.get("CAA"):
        security["info"].append(f"CAA records configured ({len(records['CAA'])} records)")
    else:
        security["info"].append("No CAA records - consider adding for certificate authority control")
    
    return security


def osint_enrichment(domain: str, timeout: int, verbose: bool, dns_server: Optional[str] = None) -> Dict[str, Any]:
    """Perform OSINT enrichment with robust error handling"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Performing OSINT enrichment...", total=None)
        
        osint = {
            "cert_transparency": {"checked": False, "domains": [], "error": None}
        }
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    domains_found = set()
                    
                    for entry in data[:50]:
                        name_value = entry.get("name_value", "")
                        for cert_domain in name_value.split("\n"):
                            cert_domain = cert_domain.strip().lower()
                            if cert_domain and domain in cert_domain:
                                domains_found.add(cert_domain)
                    
                    osint["cert_transparency"]["checked"] = True
                    osint["cert_transparency"]["domains"] = sorted(list(domains_found))[:20]
                
                except json.JSONDecodeError as e:
                    osint["cert_transparency"]["error"] = f"Invalid JSON response from crt.sh: {str(e)}"
                except Exception as e:
                    osint["cert_transparency"]["error"] = f"Failed to parse crt.sh response: {str(e)}"
            else:
                osint["cert_transparency"]["error"] = f"HTTP {response.status_code} from crt.sh"
        
        except requests.exceptions.Timeout:
            osint["cert_transparency"]["error"] = "Request timeout to crt.sh"
        except requests.exceptions.RequestException as e:
            osint["cert_transparency"]["error"] = f"Network error: {str(e)}"
        except Exception as e:
            osint["cert_transparency"]["error"] = f"Unexpected error: {str(e)}"
    
    return osint


def export_reports(domain: str, all_data: Dict, verbose: bool):
    """Export JSON and TXT reports with enhanced AXFR details to Desktop"""
    desktop_path = get_desktop_path()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    json_file = desktop_path / f"{domain}_dnsint_{timestamp}.json"
    txt_file = desktop_path / f"{domain}_dnsint_{timestamp}.txt"
    
    all_data["export_timestamp"] = datetime.now().isoformat()
    all_data["export_location"] = str(desktop_path)
    
    with open(json_file, "w") as f:
        json.dump(all_data, f, indent=2, default=str)
    
    with open(txt_file, "w") as f:
        f.write("=" * 80 + "\n")
        f.write(f"DNSint v1 Report for {domain}\n")
        f.write(f"Created by wh0xac\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("DNS RECORDS\n")
        f.write("-" * 80 + "\n")
        for rtype, records in all_data["records"].items():
            f.write(f"\n{rtype}:\n")
            if records:
                for record in records:
                    f.write(f"  {record['value']} (TTL: {record.get('ttl', 'N/A')})\n")
            else:
                f.write("  (none)\n")
        
        f.write("\n\nREVERSE PTR LOOKUPS\n")
        f.write("-" * 80 + "\n")
        for ip, ptrs in all_data["ptr_lookups"].items():
            f.write(f"{ip} → {ptrs if ptrs else '(no PTR)'}\n")
        
        f.write("\n\nZONE TRANSFER (AXFR) ATTEMPTS\n")
        f.write("-" * 80 + "\n")
        for ns, data in all_data["axfr"].items():
            status = "ALLOWED (SECURITY ISSUE!)" if data["axfr_allowed"] else "Denied (secure)"
            f.write(f"{ns} ({', '.join(data['ips'])}): {status}\n")
            if data["axfr_allowed"]:
                record_count = data.get("record_count", 0)
                f.write(f"  ⚠ CRITICAL: {record_count} DNS records exposed via zone transfer!\n")
                if data.get("zone_records"):
                    f.write(f"  Sample leaked records:\n")
                    for record_name in data["zone_records"][:5]:
                        f.write(f"    - {record_name}\n")
                    if record_count > 5:
                        f.write(f"    ... and {record_count - 5} more records\n")
        
        email = all_data.get("email_security", {})
        if email:
            f.write("\n\nEMAIL SECURITY\n")
            f.write("-" * 80 + "\n")
            f.write(f"SPF: {'Found' if email.get('spf', {}).get('present') else 'Not Found'}\n")
            if email.get('spf', {}).get('present'):
                f.write(f"  Record: {email['spf']['record']}\n")
                f.write(f"  Total DNS Lookups: {email['spf']['total_lookups']} (limit: 10)\n")
                if email['spf']['includes']:
                    f.write(f"  Includes: {', '.join(email['spf']['includes'])}\n")
                if email['spf']['issues']:
                    f.write("  Issues:\n")
                    for issue in email['spf']['issues']:
                        f.write(f"    - {issue}\n")
            
            f.write(f"\nDMARC: {'Found' if email.get('dmarc', {}).get('present') else 'Not Found'}\n")
            if email.get('dmarc', {}).get('present'):
                f.write(f"  Policy: {email['dmarc']['policy']}\n")
                f.write(f"  Record: {email['dmarc']['record']}\n")
            
            f.write(f"\nDKIM Selectors: {', '.join(email.get('dkim', {}).get('selectors_found', [])) if email.get('dkim', {}).get('selectors_found') else 'None found'}\n")
        
        f.write("\n\nWHOIS INFORMATION\n")
        f.write("-" * 80 + "\n")
        whois = all_data.get("whois", {})
        f.write(f"Domain Name: {whois.get('domain_name', 'Unknown')}\n")
        f.write(f"Registrar: {whois.get('registrar', 'Unknown')}\n")
        if whois.get('registrant_org'):
            f.write(f"Registrant Organization: {whois['registrant_org']}\n")
        if whois.get('registrant_country'):
            f.write(f"Registrant Country: {whois['registrant_country']}\n")
        f.write(f"Created: {whois.get('creation_date', 'Unknown')}\n")
        f.write(f"Updated: {whois.get('updated_date', 'Unknown')}\n")
        f.write(f"Expires: {whois.get('expiration_date', 'Unknown')}\n")
        if whois.get('days_until_expiry'):
            f.write(f"Days Until Expiry: {whois['days_until_expiry']}\n")
        f.write(f"Privacy Protection: {'Yes' if whois.get('privacy') else 'No'}\n")
        if whois.get('admin_email'):
            f.write(f"Admin Email: {whois['admin_email']}\n")
        if whois.get('tech_email'):
            f.write(f"Tech Email: {whois['tech_email']}\n")
        if whois.get('name_servers'):
            f.write(f"Name Servers: {', '.join(whois['name_servers'])}\n")
        
        ns = all_data.get("nameserver_info", {})
        if ns.get("nameservers"):
            f.write("\n\nNAMESERVER ANALYSIS\n")
            f.write("-" * 80 + "\n")
            for ns_host, ns_data in ns["nameservers"].items():
                f.write(f"{ns_host}:\n")
                f.write(f"  IPs: {', '.join(ns_data['ips'])}\n")
                f.write(f"  SOA Serial: {ns_data.get('soa_serial', 'N/A')}\n")
                if ns_data.get('asn'):
                    f.write(f"  ASN: AS{ns_data['asn']} ({ns_data['org']}, {ns_data['country']})\n")
            f.write(f"\nDNSSEC:\n")
            f.write(f"  Enabled: {'Yes' if ns.get('dnssec', {}).get('enabled') else 'No'}\n")
            f.write(f"  DNSKEY records: {ns.get('dnssec', {}).get('dnskey_count', 0)}\n")
            f.write(f"  DS at parent: {'Yes' if ns.get('dnssec', {}).get('has_ds') else 'No'}\n")
        
        tech_data = all_data.get("technology", {})
        if tech_data.get("checked"):
            f.write("\n\nTECHNOLOGY STACK & SERVER ANALYSIS\n")
            f.write("-" * 80 + "\n")
            if tech_data.get("web_server"):
                f.write(f"Web Server: {tech_data['web_server']}\n")
            if tech_data.get("cms"):
                f.write(f"CMS: {tech_data['cms']}\n")
            if tech_data.get("frameworks"):
                f.write(f"Frameworks: {', '.join(tech_data['frameworks'])}\n")
            if tech_data.get("analytics"):
                f.write(f"Analytics: {', '.join(tech_data['analytics'])}\n")
            if tech_data.get("cdn"):
                f.write(f"CDN: {tech_data['cdn']}\n")
            if tech_data.get("hosting_provider"):
                f.write(f"Hosting Provider: {tech_data['hosting_provider']}\n")
            
            f.write(f"\nHTTP Security Headers:\n")
            for header, value in tech_data.get("security_headers", {}).items():
                f.write(f"  {header}: {value}\n")
        
        propagation = all_data.get("propagation", {})
        if propagation:
            f.write("\n\nDNS PROPAGATION\n")
            f.write("-" * 80 + "\n")
            for resolver, data in propagation.items():
                method = data.get("method", "UDP")
                f.write(f"{resolver} ({method}): {data['status']}\n")
                if data['status'] == 'success':
                    f.write(f"  A: {', '.join(data['A']) if data['A'] else 'none'}\n")
        
        sec = all_data.get("security", {})
        if sec:
            f.write("\n\nSECURITY AUDIT\n")
            f.write("-" * 80 + "\n")
            if sec.get("critical"):
                f.write("CRITICAL ISSUES:\n")
                for issue in sec["critical"]:
                    f.write(f"  ✗ {issue}\n")
            if sec.get("warnings"):
                f.write("\nWARNINGS:\n")
                for warning in sec["warnings"]:
                    f.write(f"  ⚠ {warning}\n")
            if sec.get("info"):
                f.write("\nINFORMATIONAL:\n")
                for info in sec["info"]:
                    f.write(f"  ℹ {info}\n")
        
        if all_data.get("osint", {}).get("cert_transparency", {}).get("checked"):
            f.write("\n\nOSINT - CERTIFICATE TRANSPARENCY\n")
            f.write("-" * 80 + "\n")
            ct_domains = all_data["osint"]["cert_transparency"].get("domains", [])
            if ct_domains:
                for ct_domain in ct_domains:
                    f.write(f"  {ct_domain}\n")
            error = all_data["osint"]["cert_transparency"].get("error")
            if error:
                f.write(f"  Error: {error}\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("SUMMARY\n")
        f.write("=" * 80 + "\n")
        record_count = sum(len(r) for r in all_data.get("records", {}).values())
        f.write(f"Total DNS Records: {record_count}\n")
        f.write(f"Critical Issues: {len(sec.get('critical', []))}\n")
        f.write(f"Warnings: {len(sec.get('warnings', []))}\n")
        if ns.get('nameservers'):
            f.write(f"Nameservers: {len(ns['nameservers'])}\n")
            f.write(f"DNSSEC: {'Enabled' if ns.get('dnssec', {}).get('enabled') else 'Disabled'}\n")
        f.write("\n")
    
    console.print(f"\n[green]✓ Reports exported to Desktop:[/green]")
    console.print(f"  [cyan]→[/cyan] {json_file}")
    console.print(f"  [cyan]→[/cyan] {txt_file}\n")


def display_summary(all_data: Dict, quiet: bool):
    """Display console summary"""
    if quiet:
        return
    
    # Check if there's any data to display first
    has_data = False
    
    record_count = sum(len(r) for r in all_data.get("records", {}).values())
    if record_count > 0:
        has_data = True
    
    ns_info = all_data.get("nameserver_info", {})
    if ns_info.get("nameservers") or ns_info.get("dnssec"):
        has_data = True
    
    email_sec = all_data.get("email_security", {})
    if email_sec.get("spf") or email_sec.get("dmarc"):
        has_data = True
    
    security = all_data.get("security", {})
    if security.get("critical") or security.get("warnings") or security:
        has_data = True
    
    # Only show summary section if there's data
    if not has_data:
        return
    
    console.print("\n")
    console.rule("[bold cyan]SCAN SUMMARY[/bold cyan]", style="cyan")
    console.print()
    
    table = Table(box=box.DOUBLE, border_style="cyan", show_header=False, padding=(0, 2))
    table.add_column("Category", style="cyan bold", width=25)
    table.add_column("Status", style="white")
    
    if record_count > 0:
        table.add_row("📊 DNS Records Found", f"[green bold]{record_count}[/green bold]")
    
    if ns_info.get("nameservers"):
        ns_count = len(ns_info["nameservers"])
        table.add_row("🌐 Nameservers", f"[cyan]{ns_count}[/cyan]")
    
    if ns_info.get("dnssec"):
        dnssec = "✓ Enabled" if ns_info["dnssec"]["enabled"] else "✗ Disabled"
        dnssec_color = "green" if ns_info["dnssec"]["enabled"] else "yellow"
        table.add_row("🔐 DNSSEC", f"[{dnssec_color}]{dnssec}[/{dnssec_color}]")
    
    if email_sec.get("spf"):
        spf = "✓ Present" if email_sec["spf"]["present"] else "✗ Missing"
        spf_color = "green" if email_sec["spf"]["present"] else "yellow"
        table.add_row("📧 SPF", f"[{spf_color}]{spf}[/{spf_color}]")
    
    if email_sec.get("dmarc"):
        dmarc = "✓ Present" if email_sec["dmarc"]["present"] else "✗ Missing"
        dmarc_color = "green" if email_sec["dmarc"]["present"] else "yellow"
        table.add_row("📧 DMARC", f"[{dmarc_color}]{dmarc}[/{dmarc_color}]")
    
    critical = len(security.get("critical", []))
    warnings = len(security.get("warnings", []))
    
    if critical > 0:
        table.add_row("🚨 Critical Issues", f"[red bold]{critical}[/red bold]")
    if warnings > 0:
        table.add_row("⚠️  Warnings", f"[yellow]{warnings}[/yellow]")
    if critical == 0 and warnings == 0 and security:
        table.add_row("✅ Security Status", "[green bold]No major issues[/green bold]")
    
    console.print(Panel(table, border_style="cyan", box=box.DOUBLE))
    
    if security.get("critical"):
        console.print("\n[bold red]⚠ CRITICAL SECURITY ISSUES DETECTED:[/bold red]")
        for issue in security["critical"]:
            console.print(f"  [red]✗ {issue}[/red]")
        console.print()


def main():
    parser = argparse.ArgumentParser(
        description="DNSint v1 - DNS Intelligence Toolkit\nPerform deep DNS reconnaissance, WHOIS analysis, and email security checks.\nCreated by wh0xac",
        epilog="""
Examples:
  python3 dnsint.py example.com -a -e
  python3 dnsint.py example.com -m -w -e -t
  python3 dnsint.py example.com -p -r --tech
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("domain", nargs='?', help="Target domain (e.g., example.com)")
    parser.add_argument("-a", "--all", action="store_true", help="Run full DNS + OSINT + Technology scan")
    parser.add_argument("-r", "--records", action="store_true", help="Query DNS record types")
    parser.add_argument("-z", "--zone", action="store_true", help="Perform reverse PTR & AXFR checks")
    parser.add_argument("-m", "--mail", action="store_true", help="Analyze SPF, DKIM, DMARC")
    parser.add_argument("-w", "--whois", action="store_true", help="Perform extended WHOIS lookup")
    parser.add_argument("-n", "--nsinfo", action="store_true", help="Analyze nameserver info & DNSSEC")
    parser.add_argument("-p", "--propagation", action="store_true", help="Check global DNS propagation")
    parser.add_argument("-s", "--security", action="store_true", help="Run DNS misconfiguration checks")
    parser.add_argument("-o", "--osint", action="store_true", help="Enrich with passive DNS & CT data")
    parser.add_argument("-t", "--tech", action="store_true", help="Detect web technologies, CMS, servers, and security headers")
    parser.add_argument("-e", "--export", action="store_true", help="Export JSON + TXT reports to Desktop")
    parser.add_argument("--timeout", type=int, default=5, help="Set DNS query timeout (default 5)")
    parser.add_argument("--dns-server", type=str, help="Custom DNS server to use (e.g., 8.8.8.8)")
    parser.add_argument("-u", "--update", action="store_true", help="Update DNSint to the latest version")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed logs")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal console output")
    
    args = parser.parse_args()

    # Handle update flag
    if args.update:
        update_tool()

    # Validate domain is provided
    if not args.domain:
        parser.error("the following arguments are required: domain")

    domain = args.domain.strip().rstrip('.')

    if not args.quiet:
        print_banner()
        console.print(f"[bold]Target:[/bold] [cyan]{domain}[/cyan]")
        console.print(f"[dim]Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
    
    run_all = args.all or not any([args.records, args.zone, args.mail, args.whois, 
                                     args.nsinfo, args.propagation, args.security, args.osint, args.tech])
    
    all_data = {
        "domain": domain,
        "scan_timestamp": datetime.now().isoformat(),
        "records": {},
        "ptr_lookups": {},
        "axfr": {},
        "email_security": {},
        "whois": {},
        "nameserver_info": {},
        "propagation": {},
        "security": {},
        "osint": {},
        "technology": {}
    }
    
    if run_all or args.records:
        all_data["records"] = get_dns_records(domain, args.timeout, args.verbose, args.dns_server)
        display_dns_records_table(all_data["records"], args.quiet)

    if run_all or args.zone:
        if not all_data["records"]:
            all_data["records"] = get_dns_records(domain, args.timeout, args.verbose, args.dns_server)
        all_data["ptr_lookups"] = reverse_ptr_lookups(all_data["records"], args.timeout, args.verbose, args.dns_server)
        display_ptr_table(all_data["ptr_lookups"], args.quiet)

        all_data["axfr"] = attempt_axfr(domain, all_data["records"], args.timeout, args.verbose, args.dns_server)
        display_axfr_results(all_data["axfr"], args.quiet)

    if run_all or args.mail:
        if not all_data["records"]:
            all_data["records"] = get_dns_records(domain, args.timeout, args.verbose, args.dns_server)
        all_data["email_security"] = email_security_analysis(domain, all_data["records"], args.timeout, args.verbose, args.dns_server)
        display_email_security(all_data["email_security"], args.quiet)

    if run_all or args.whois:
        all_data["whois"] = whois_lookup(domain, args.verbose)
        display_whois_info(all_data["whois"], args.quiet)

    if run_all or args.nsinfo:
        if not all_data["records"]:
            all_data["records"] = get_dns_records(domain, args.timeout, args.verbose, args.dns_server)
        all_data["nameserver_info"] = nameserver_analysis(domain, all_data["records"], args.timeout, args.verbose, args.dns_server)
        display_nameserver_analysis(all_data["nameserver_info"], args.quiet)

    if run_all or args.propagation:
        all_data["propagation"] = propagation_check(domain, args.timeout, args.verbose, args.dns_server)
        display_propagation(all_data["propagation"], args.quiet)

    if run_all or args.tech:
        all_data["technology"] = detect_technologies(domain, args.timeout, args.verbose)
        display_technology_info(all_data["technology"], args.quiet)

    if run_all or args.security:
        if not all_data["records"]:
            all_data["records"] = get_dns_records(domain, args.timeout, args.verbose, args.dns_server)
        if not all_data["axfr"]:
            all_data["axfr"] = attempt_axfr(domain, all_data["records"], args.timeout, args.verbose, args.dns_server)
        if not all_data["email_security"]:
            all_data["email_security"] = email_security_analysis(domain, all_data["records"], args.timeout, args.verbose, args.dns_server)
        if not all_data["nameserver_info"]:
            all_data["nameserver_info"] = nameserver_analysis(domain, all_data["records"], args.timeout, args.verbose, args.dns_server)
        if not all_data["propagation"]:
            all_data["propagation"] = propagation_check(domain, args.timeout, args.verbose, args.dns_server)

        all_data["security"] = security_audit(domain, all_data["records"], all_data["axfr"],
                                              all_data["email_security"], all_data["nameserver_info"],
                                              all_data["propagation"], args.verbose)
        display_security_audit(all_data["security"], args.quiet)

    if run_all or args.osint:
        all_data["osint"] = osint_enrichment(domain, args.timeout, args.verbose, args.dns_server)
        display_osint_results(all_data["osint"], args.quiet)
    
    display_summary(all_data, args.quiet)
    
    if args.export:
        export_reports(domain, all_data, args.verbose)
    
    if not args.quiet:
        console.print(f"[green]✓ Scan completed for[/green] [cyan bold]{domain}[/cyan bold]")
        console.print(f"[dim]Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")


if __name__ == "__main__":
    main()
