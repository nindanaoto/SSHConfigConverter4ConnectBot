#!/usr/bin/env python3
"""
SSH Config Converter for ConnectBot

Converts between OpenSSH ssh_config format and ConnectBot's JSON export format.

Note: Some OpenSSH features are not supported by ConnectBot and will be ignored:
- ProxyCommand (only ProxyJump is supported)
- ControlMaster/ControlPath (connection multiplexing)
- StrictHostKeyChecking
- UserKnownHostsFile
- ServerAliveInterval/ServerAliveCountMax
- ConnectTimeout
- And other advanced options
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PortForward:
    """Represents a port forwarding rule."""
    nickname: str
    forward_type: str  # "local" or "remote"
    source_port: int
    dest_addr: str
    dest_port: int


@dataclass
class SSHHost:
    """Represents an SSH host configuration."""
    nickname: str
    hostname: str = ""
    username: str = ""
    port: int = 22
    compression: bool = False
    use_keys: bool = True
    identity_file: Optional[str] = None
    proxy_jump: Optional[str] = None
    post_login: Optional[str] = None
    port_forwards: list = field(default_factory=list)

    # Additional fields for ConnectBot
    protocol: str = "ssh"
    use_auth_agent: str = "no"
    want_session: bool = True
    stay_connected: bool = False
    quick_disconnect: bool = False
    scrollback_lines: int = 140
    use_ctrl_alt_as_meta_key: bool = False


class SSHConfigParser:
    """Parser for OpenSSH ssh_config format."""

    # SSH config directives that map to ConnectBot fields
    SUPPORTED_DIRECTIVES = {
        'hostname': 'hostname',
        'user': 'username',
        'port': 'port',
        'compression': 'compression',
        'identityfile': 'identity_file',
        'proxyjump': 'proxy_jump',
        'localforward': 'local_forward',
        'remoteforward': 'remote_forward',
    }

    # Directives that are ignored (not supported by ConnectBot)
    IGNORED_DIRECTIVES = {
        'proxycommand', 'controlmaster', 'controlpath', 'controlpersist',
        'stricthostkeychecking', 'userknownhostsfile', 'serveraliveinterval',
        'serveralivecountmax', 'connecttimeout', 'batchmode', 'forwardagent',
        'forwardx11', 'forwardx11trusted', 'hashknownhosts', 'addkeystoagent',
        'identitiesonly', 'pubkeyauthentication', 'preferredauthentications',
        'kexalgorithms', 'hostkeyalgorithms', 'ciphers', 'macs', 'loglevel',
        'sendenv', 'setenv', 'include', 'match', 'canonicaldomains',
        'canonicalizefallbacklocal', 'canonicalizehostname', 'canonicalizemaxdots',
        'canonicalizepermittedcnames', 'dynamicforward', 'gssapiauthentication',
        'gssapidelegatecredentials', 'tcpkeepalive', 'visualhostkey',
    }

    def __init__(self):
        self.hosts: list[SSHHost] = []
        self.ignored_options: dict[str, list[str]] = {}

    def parse(self, content: str) -> list[SSHHost]:
        """Parse ssh_config content and return list of SSHHost objects."""
        self.hosts = []
        self.ignored_options = {}
        current_host: Optional[SSHHost] = None

        for line_num, line in enumerate(content.splitlines(), 1):
            # Remove comments and strip whitespace
            line = re.sub(r'#.*$', '', line).strip()
            if not line:
                continue

            # Parse directive and value
            match = re.match(r'^(\S+)\s+(.+)$', line)
            if not match:
                continue

            directive = match.group(1).lower()
            value = match.group(2).strip()

            # Remove surrounding quotes if present
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]

            if directive == 'host':
                # Start a new host block
                # Skip wildcard patterns like "*" as they're default settings
                if value != '*' and not self._is_pattern(value):
                    current_host = SSHHost(nickname=value)
                    self.hosts.append(current_host)
                else:
                    current_host = None
            elif current_host is not None:
                self._apply_directive(current_host, directive, value)

        return self.hosts

    def _is_pattern(self, value: str) -> bool:
        """Check if the host value contains wildcards."""
        return '*' in value or '?' in value or '!' in value

    def _apply_directive(self, host: SSHHost, directive: str, value: str) -> None:
        """Apply a directive to the host configuration."""
        directive_lower = directive.lower()

        if directive_lower == 'hostname':
            host.hostname = value
        elif directive_lower == 'user':
            host.username = value
        elif directive_lower == 'port':
            try:
                host.port = int(value)
            except ValueError:
                pass
        elif directive_lower == 'compression':
            host.compression = value.lower() in ('yes', 'true', '1')
        elif directive_lower == 'identityfile':
            host.identity_file = value
            host.use_keys = True
        elif directive_lower == 'proxyjump':
            host.proxy_jump = value
        elif directive_lower == 'localforward':
            pf = self._parse_port_forward(value, 'local', host.nickname)
            if pf:
                host.port_forwards.append(pf)
        elif directive_lower == 'remoteforward':
            pf = self._parse_port_forward(value, 'remote', host.nickname)
            if pf:
                host.port_forwards.append(pf)
        elif directive_lower in self.IGNORED_DIRECTIVES:
            # Track ignored options for reporting
            if host.nickname not in self.ignored_options:
                self.ignored_options[host.nickname] = []
            self.ignored_options[host.nickname].append(f"{directive}={value}")

    def _parse_port_forward(self, value: str, forward_type: str, host_nickname: str) -> Optional[PortForward]:
        """Parse port forward specification.

        Formats supported:
        - port host:hostport
        - bind_address:port host:hostport
        """
        parts = value.split()
        if len(parts) < 2:
            return None

        # Parse source (bind_address:port or just port)
        source = parts[0]
        if ':' in source:
            source_port_str = source.split(':')[-1]
        else:
            source_port_str = source

        # Parse destination (host:port)
        dest = parts[1]
        if ':' in dest:
            dest_parts = dest.rsplit(':', 1)
            dest_addr = dest_parts[0]
            dest_port_str = dest_parts[1]
        else:
            return None

        try:
            source_port = int(source_port_str)
            dest_port = int(dest_port_str)
        except ValueError:
            return None

        pf_count = sum(1 for pf in self.hosts[-1].port_forwards if True) + 1 if self.hosts else 1
        return PortForward(
            nickname=f"{host_nickname}-{forward_type}-{pf_count}",
            forward_type=forward_type,
            source_port=source_port,
            dest_addr=dest_addr,
            dest_port=dest_port
        )

    def get_ignored_options(self) -> dict[str, list[str]]:
        """Return dictionary of ignored options per host."""
        return self.ignored_options


class SSHConfigWriter:
    """Writer for OpenSSH ssh_config format."""

    def write(self, hosts: list[SSHHost]) -> str:
        """Write list of SSHHost objects to ssh_config format."""
        lines = []
        lines.append("# SSH Config generated by SSHConfigConverter4ConnectBot")
        lines.append("")

        for host in hosts:
            lines.append(f"Host {host.nickname}")

            if host.hostname:
                lines.append(f"    HostName {host.hostname}")
            if host.username:
                lines.append(f"    User {host.username}")
            if host.port != 22:
                lines.append(f"    Port {host.port}")
            if host.compression:
                lines.append("    Compression yes")
            if host.identity_file:
                lines.append(f"    IdentityFile {host.identity_file}")
            if host.proxy_jump:
                lines.append(f"    ProxyJump {host.proxy_jump}")

            for pf in host.port_forwards:
                if pf.forward_type == 'local':
                    lines.append(f"    LocalForward {pf.source_port} {pf.dest_addr}:{pf.dest_port}")
                elif pf.forward_type == 'remote':
                    lines.append(f"    RemoteForward {pf.source_port} {pf.dest_addr}:{pf.dest_port}")

            lines.append("")

        return '\n'.join(lines)


class ConnectBotJsonParser:
    """Parser for ConnectBot's JSON export format."""

    def parse(self, content: str) -> tuple[list[SSHHost], list[dict]]:
        """Parse ConnectBot JSON and return list of SSHHost objects and profiles."""
        data = json.loads(content)
        hosts = []
        profiles = data.get('profiles', [])

        # Build host ID to host mapping for jump host resolution
        host_id_map: dict[int, SSHHost] = {}
        raw_hosts = data.get('hosts', [])

        # First pass: create all hosts
        for raw_host in raw_hosts:
            if raw_host.get('protocol', 'ssh') != 'ssh':
                continue  # Skip non-SSH hosts (telnet, local)

            host = SSHHost(
                nickname=raw_host.get('nickname', ''),
                hostname=raw_host.get('hostname', ''),
                username=raw_host.get('username', ''),
                port=raw_host.get('port', 22),
                compression=bool(raw_host.get('compression', 0)),
                use_keys=bool(raw_host.get('useKeys', 1)),
                use_auth_agent=raw_host.get('useAuthAgent', 'no'),
                want_session=bool(raw_host.get('wantSession', 1)),
                stay_connected=bool(raw_host.get('stayConnected', 0)),
                quick_disconnect=bool(raw_host.get('quickDisconnect', 0)),
                scrollback_lines=raw_host.get('scrollbackLines', 140),
                use_ctrl_alt_as_meta_key=bool(raw_host.get('useCtrlAltAsMetaKey', 0)),
                post_login=raw_host.get('postLogin'),
            )

            host_id = raw_host.get('id', 0)
            host_id_map[host_id] = host

            # Store jump host ID for second pass
            host._jump_host_id = raw_host.get('jumpHostId')
            host._host_id = host_id

            hosts.append(host)

        # Second pass: resolve jump host references
        for host in hosts:
            if hasattr(host, '_jump_host_id') and host._jump_host_id:
                jump_host = host_id_map.get(host._jump_host_id)
                if jump_host:
                    host.proxy_jump = jump_host.nickname

        # Parse port forwards
        port_forwards = data.get('port_forwards', [])
        for pf_data in port_forwards:
            host_id = pf_data.get('hostId')
            if host_id in host_id_map:
                host = host_id_map[host_id]
                pf = PortForward(
                    nickname=pf_data.get('nickname', ''),
                    forward_type=pf_data.get('type', 'local'),
                    source_port=pf_data.get('sourcePort', 0),
                    dest_addr=pf_data.get('destAddr', 'localhost'),
                    dest_port=pf_data.get('destPort', 0)
                )
                host.port_forwards.append(pf)

        return hosts, profiles


class ConnectBotJsonWriter:
    """Writer for ConnectBot's JSON export format."""

    SCHEMA_VERSION = 7

    DEFAULT_PROFILE = {
        "id": 1,
        "name": "Default",
        "colorSchemeId": -1,
        "fontSize": 10,
        "delKey": "del",
        "encoding": "UTF-8",
        "emulation": "xterm-256color"
    }

    def __init__(self):
        self.host_nickname_to_id: dict[str, int] = {}

    def write(self, hosts: list[SSHHost], profiles: Optional[list[dict]] = None) -> str:
        """Write list of SSHHost objects to ConnectBot JSON format."""
        if profiles is None:
            profiles = [self.DEFAULT_PROFILE]

        # First pass: assign IDs and build nickname map
        self.host_nickname_to_id = {}
        for i, host in enumerate(hosts, 1):
            self.host_nickname_to_id[host.nickname] = i

        # Build hosts array
        hosts_json = []
        for i, host in enumerate(hosts, 1):
            jump_host_id = None
            if host.proxy_jump:
                jump_host_id = self.host_nickname_to_id.get(host.proxy_jump)

            host_json = {
                "id": i,
                "nickname": host.nickname,
                "protocol": host.protocol,
                "username": host.username,
                "hostname": host.hostname if host.hostname else host.nickname,
                "port": host.port,
                "useKeys": int(host.use_keys),
                "useAuthAgent": host.use_auth_agent,
                "postLogin": host.post_login,
                "pubkeyId": -1,  # No key reference from ssh_config
                "wantSession": int(host.want_session),
                "compression": int(host.compression),
                "stayConnected": int(host.stay_connected),
                "quickDisconnect": int(host.quick_disconnect),
                "scrollbackLines": host.scrollback_lines,
                "useCtrlAltAsMetaKey": int(host.use_ctrl_alt_as_meta_key),
                "jumpHostId": jump_host_id,
                "profileId": 1
            }
            hosts_json.append(host_json)

        # Build port forwards array
        port_forwards_json = []
        pf_id = 1
        for i, host in enumerate(hosts, 1):
            for pf in host.port_forwards:
                pf_json = {
                    "id": pf_id,
                    "hostId": i,
                    "nickname": pf.nickname,
                    "type": pf.forward_type,
                    "sourcePort": pf.source_port,
                    "destAddr": pf.dest_addr,
                    "destPort": pf.dest_port
                }
                port_forwards_json.append(pf_json)
                pf_id += 1

        result = {
            "version": self.SCHEMA_VERSION,
            "profiles": profiles,
            "hosts": hosts_json,
            "port_forwards": port_forwards_json
        }

        return json.dumps(result, indent=2)


def convert_ssh_config_to_connectbot(ssh_config_content: str, verbose: bool = False) -> str:
    """Convert SSH config to ConnectBot JSON format."""
    parser = SSHConfigParser()
    hosts = parser.parse(ssh_config_content)

    if verbose:
        ignored = parser.get_ignored_options()
        if ignored:
            print("Warning: The following options were ignored (not supported by ConnectBot):", file=sys.stderr)
            for hostname, options in ignored.items():
                print(f"  {hostname}:", file=sys.stderr)
                for opt in options:
                    print(f"    - {opt}", file=sys.stderr)

    writer = ConnectBotJsonWriter()
    return writer.write(hosts)


def convert_connectbot_to_ssh_config(connectbot_json_content: str) -> str:
    """Convert ConnectBot JSON to SSH config format."""
    parser = ConnectBotJsonParser()
    hosts, _ = parser.parse(connectbot_json_content)

    writer = SSHConfigWriter()
    return writer.write(hosts)


def main():
    parser = argparse.ArgumentParser(
        description='Convert between SSH config and ConnectBot JSON formats',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert SSH config to ConnectBot JSON
  %(prog)s --to-connectbot ~/.ssh/config -o connectbot_hosts.json

  # Convert ConnectBot JSON to SSH config
  %(prog)s --to-ssh-config connectbot_export.json -o config

  # Read from stdin, write to stdout
  cat ~/.ssh/config | %(prog)s --to-connectbot

Note: Some OpenSSH features are not supported by ConnectBot:
  - ProxyCommand (use ProxyJump instead)
  - ControlMaster/ControlPath
  - ServerAliveInterval/ServerAliveCountMax
  - And other advanced options
        """
    )

    # Conversion direction
    direction = parser.add_mutually_exclusive_group(required=True)
    direction.add_argument(
        '--to-connectbot', '-c',
        action='store_true',
        help='Convert SSH config to ConnectBot JSON'
    )
    direction.add_argument(
        '--to-ssh-config', '-s',
        action='store_true',
        help='Convert ConnectBot JSON to SSH config'
    )

    # Input/Output
    parser.add_argument(
        'input',
        nargs='?',
        help='Input file (default: stdin)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file (default: stdout)'
    )

    # Options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show warnings about ignored options'
    )

    args = parser.parse_args()

    # Read input
    if args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        content = input_path.read_text()
    else:
        content = sys.stdin.read()

    # Convert
    try:
        if args.to_connectbot:
            result = convert_ssh_config_to_connectbot(content, verbose=args.verbose)
        else:
            result = convert_connectbot_to_ssh_config(content)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Write output
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(result)
        print(f"Output written to: {args.output}", file=sys.stderr)
    else:
        print(result)


if __name__ == '__main__':
    main()
