#!/usr/bin/env python3
"""Unit tests for SSH Config Converter for ConnectBot."""

import json
import unittest
from ssh_config_converter import (
    SSHConfigParser,
    SSHConfigWriter,
    ConnectBotJsonParser,
    ConnectBotJsonWriter,
    SSHHost,
    PortForward,
    convert_ssh_config_to_connectbot,
    convert_connectbot_to_ssh_config,
)


class TestSSHConfigParser(unittest.TestCase):
    """Tests for SSHConfigParser class."""

    def setUp(self):
        self.parser = SSHConfigParser()

    def test_parse_simple_host(self):
        """Test parsing a simple host configuration."""
        config = """
Host myserver
    HostName example.com
    User admin
    Port 2222
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].nickname, "myserver")
        self.assertEqual(hosts[0].hostname, "example.com")
        self.assertEqual(hosts[0].username, "admin")
        self.assertEqual(hosts[0].port, 2222)

    def test_parse_multiple_hosts(self):
        """Test parsing multiple host configurations."""
        config = """
Host server1
    HostName server1.example.com
    User user1

Host server2
    HostName server2.example.com
    User user2
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0].nickname, "server1")
        self.assertEqual(hosts[1].nickname, "server2")

    def test_parse_compression(self):
        """Test parsing compression setting."""
        config = """
Host compressed
    HostName example.com
    Compression yes

Host uncompressed
    HostName example2.com
    Compression no
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 2)
        self.assertTrue(hosts[0].compression)
        self.assertFalse(hosts[1].compression)

    def test_parse_proxy_jump(self):
        """Test parsing ProxyJump directive."""
        config = """
Host internal
    HostName internal.example.com
    ProxyJump bastion

Host bastion
    HostName bastion.example.com
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0].proxy_jump, "bastion")
        self.assertIsNone(hosts[1].proxy_jump)

    def test_parse_local_forward(self):
        """Test parsing LocalForward directive."""
        config = """
Host tunnel
    HostName example.com
    LocalForward 3306 localhost:3306
    LocalForward 6379 redis.local:6379
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(len(hosts[0].port_forwards), 2)

        pf1 = hosts[0].port_forwards[0]
        self.assertEqual(pf1.forward_type, "local")
        self.assertEqual(pf1.source_port, 3306)
        self.assertEqual(pf1.dest_addr, "localhost")
        self.assertEqual(pf1.dest_port, 3306)

        pf2 = hosts[0].port_forwards[1]
        self.assertEqual(pf2.source_port, 6379)
        self.assertEqual(pf2.dest_addr, "redis.local")
        self.assertEqual(pf2.dest_port, 6379)

    def test_parse_remote_forward(self):
        """Test parsing RemoteForward directive."""
        config = """
Host tunnel
    HostName example.com
    RemoteForward 8080 localhost:80
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(len(hosts[0].port_forwards), 1)

        pf = hosts[0].port_forwards[0]
        self.assertEqual(pf.forward_type, "remote")
        self.assertEqual(pf.source_port, 8080)
        self.assertEqual(pf.dest_addr, "localhost")
        self.assertEqual(pf.dest_port, 80)

    def test_parse_identity_file(self):
        """Test parsing IdentityFile directive."""
        config = """
Host github
    HostName github.com
    IdentityFile ~/.ssh/id_ed25519
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].identity_file, "~/.ssh/id_ed25519")
        self.assertTrue(hosts[0].use_keys)

    def test_skip_wildcard_host(self):
        """Test that wildcard hosts are skipped."""
        config = """
Host *
    ServerAliveInterval 60

Host myserver
    HostName example.com
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].nickname, "myserver")

    def test_skip_pattern_host(self):
        """Test that pattern hosts are skipped."""
        config = """
Host *.example.com
    User admin

Host specific
    HostName specific.example.com
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].nickname, "specific")

    def test_ignore_comments(self):
        """Test that comments are ignored."""
        config = """
# This is a comment
Host myserver
    HostName example.com # inline comment
    User admin
"""
        hosts = self.parser.parse(config)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].hostname, "example.com")

    def test_track_ignored_options(self):
        """Test that ignored options are tracked."""
        config = """
Host myserver
    HostName example.com
    ServerAliveInterval 60
    ControlMaster auto
"""
        hosts = self.parser.parse(config)
        ignored = self.parser.get_ignored_options()

        self.assertEqual(len(hosts), 1)
        self.assertIn("myserver", ignored)
        self.assertEqual(len(ignored["myserver"]), 2)

    def test_parse_quoted_values(self):
        """Test parsing quoted values."""
        config = """
Host myserver
    HostName "example.com"
    User 'admin'
"""
        hosts = self.parser.parse(config)

        self.assertEqual(hosts[0].hostname, "example.com")
        self.assertEqual(hosts[0].username, "admin")

    def test_parse_default_port(self):
        """Test that default port is 22."""
        config = """
Host myserver
    HostName example.com
"""
        hosts = self.parser.parse(config)

        self.assertEqual(hosts[0].port, 22)

    def test_parse_empty_config(self):
        """Test parsing empty configuration."""
        hosts = self.parser.parse("")
        self.assertEqual(len(hosts), 0)

    def test_parse_config_with_only_comments(self):
        """Test parsing configuration with only comments."""
        config = """
# Comment 1
# Comment 2
"""
        hosts = self.parser.parse(config)
        self.assertEqual(len(hosts), 0)

    def test_case_insensitive_directives(self):
        """Test that directives are case-insensitive."""
        config = """
Host myserver
    HOSTNAME example.com
    USER admin
    PORT 22
    COMPRESSION yes
"""
        hosts = self.parser.parse(config)

        self.assertEqual(hosts[0].hostname, "example.com")
        self.assertEqual(hosts[0].username, "admin")
        self.assertTrue(hosts[0].compression)


class TestSSHConfigWriter(unittest.TestCase):
    """Tests for SSHConfigWriter class."""

    def setUp(self):
        self.writer = SSHConfigWriter()

    def test_write_simple_host(self):
        """Test writing a simple host configuration."""
        hosts = [
            SSHHost(
                nickname="myserver",
                hostname="example.com",
                username="admin",
                port=22
            )
        ]

        result = self.writer.write(hosts)

        self.assertIn("Host myserver", result)
        self.assertIn("HostName example.com", result)
        self.assertIn("User admin", result)
        self.assertNotIn("Port", result)  # Default port should be omitted

    def test_write_non_default_port(self):
        """Test writing host with non-default port."""
        hosts = [
            SSHHost(nickname="myserver", hostname="example.com", port=2222)
        ]

        result = self.writer.write(hosts)

        self.assertIn("Port 2222", result)

    def test_write_compression(self):
        """Test writing host with compression enabled."""
        hosts = [
            SSHHost(nickname="myserver", hostname="example.com", compression=True)
        ]

        result = self.writer.write(hosts)

        self.assertIn("Compression yes", result)

    def test_write_proxy_jump(self):
        """Test writing host with ProxyJump."""
        hosts = [
            SSHHost(nickname="internal", hostname="internal.com", proxy_jump="bastion")
        ]

        result = self.writer.write(hosts)

        self.assertIn("ProxyJump bastion", result)

    def test_write_port_forwards(self):
        """Test writing host with port forwards."""
        hosts = [
            SSHHost(
                nickname="tunnel",
                hostname="example.com",
                port_forwards=[
                    PortForward("pf1", "local", 3306, "localhost", 3306),
                    PortForward("pf2", "remote", 8080, "localhost", 80),
                ]
            )
        ]

        result = self.writer.write(hosts)

        self.assertIn("LocalForward 3306 localhost:3306", result)
        self.assertIn("RemoteForward 8080 localhost:80", result)

    def test_write_identity_file(self):
        """Test writing host with identity file."""
        hosts = [
            SSHHost(
                nickname="github",
                hostname="github.com",
                identity_file="~/.ssh/id_ed25519"
            )
        ]

        result = self.writer.write(hosts)

        self.assertIn("IdentityFile ~/.ssh/id_ed25519", result)

    def test_write_empty_list(self):
        """Test writing empty host list."""
        result = self.writer.write([])

        self.assertIn("# SSH Config generated by", result)


class TestConnectBotJsonParser(unittest.TestCase):
    """Tests for ConnectBotJsonParser class."""

    def setUp(self):
        self.parser = ConnectBotJsonParser()

    def test_parse_simple_host(self):
        """Test parsing a simple ConnectBot JSON host."""
        json_data = {
            "version": 6,
            "profiles": [],
            "hosts": [
                {
                    "id": 1,
                    "nickname": "myserver",
                    "protocol": "ssh",
                    "username": "admin",
                    "hostname": "example.com",
                    "port": 22,
                    "useKeys": True,
                    "compression": False
                }
            ],
            "port_forwards": []
        }

        hosts, profiles = self.parser.parse(json.dumps(json_data))

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].nickname, "myserver")
        self.assertEqual(hosts[0].hostname, "example.com")
        self.assertEqual(hosts[0].username, "admin")
        self.assertEqual(hosts[0].port, 22)

    def test_parse_jump_host(self):
        """Test parsing hosts with jump host reference."""
        json_data = {
            "version": 6,
            "profiles": [],
            "hosts": [
                {
                    "id": 1,
                    "nickname": "internal",
                    "protocol": "ssh",
                    "hostname": "internal.com",
                    "username": "user",
                    "port": 22,
                    "jumpHostId": 2
                },
                {
                    "id": 2,
                    "nickname": "bastion",
                    "protocol": "ssh",
                    "hostname": "bastion.com",
                    "username": "jump",
                    "port": 22,
                    "jumpHostId": None
                }
            ],
            "port_forwards": []
        }

        hosts, _ = self.parser.parse(json.dumps(json_data))

        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0].proxy_jump, "bastion")
        self.assertIsNone(hosts[1].proxy_jump)

    def test_parse_port_forwards(self):
        """Test parsing hosts with port forwards."""
        json_data = {
            "version": 6,
            "profiles": [],
            "hosts": [
                {
                    "id": 1,
                    "nickname": "tunnel",
                    "protocol": "ssh",
                    "hostname": "example.com",
                    "username": "user",
                    "port": 22
                }
            ],
            "port_forwards": [
                {
                    "id": 1,
                    "hostId": 1,
                    "nickname": "MySQL",
                    "type": "local",
                    "sourcePort": 3306,
                    "destAddr": "localhost",
                    "destPort": 3306
                },
                {
                    "id": 2,
                    "hostId": 1,
                    "nickname": "Web",
                    "type": "remote",
                    "sourcePort": 8080,
                    "destAddr": "localhost",
                    "destPort": 80
                }
            ]
        }

        hosts, _ = self.parser.parse(json.dumps(json_data))

        self.assertEqual(len(hosts[0].port_forwards), 2)
        self.assertEqual(hosts[0].port_forwards[0].forward_type, "local")
        self.assertEqual(hosts[0].port_forwards[1].forward_type, "remote")

    def test_skip_non_ssh_hosts(self):
        """Test that non-SSH hosts (telnet, local) are skipped."""
        json_data = {
            "version": 6,
            "profiles": [],
            "hosts": [
                {
                    "id": 1,
                    "nickname": "ssh-host",
                    "protocol": "ssh",
                    "hostname": "example.com",
                    "username": "user",
                    "port": 22
                },
                {
                    "id": 2,
                    "nickname": "telnet-host",
                    "protocol": "telnet",
                    "hostname": "telnet.example.com",
                    "username": "user",
                    "port": 23
                },
                {
                    "id": 3,
                    "nickname": "local-shell",
                    "protocol": "local",
                    "hostname": "",
                    "username": "",
                    "port": 0
                }
            ],
            "port_forwards": []
        }

        hosts, _ = self.parser.parse(json.dumps(json_data))

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].nickname, "ssh-host")

    def test_parse_compression_as_bool(self):
        """Test parsing compression setting with JSON boolean."""
        json_data = {
            "version": 6,
            "profiles": [],
            "hosts": [
                {
                    "id": 1,
                    "nickname": "compressed",
                    "protocol": "ssh",
                    "hostname": "example.com",
                    "username": "user",
                    "port": 22,
                    "compression": True
                }
            ],
            "port_forwards": []
        }

        hosts, _ = self.parser.parse(json.dumps(json_data))

        self.assertTrue(hosts[0].compression)

    def test_parse_compression_as_integer(self):
        """Test parsing compression setting with integer (as ConnectBot exports)."""
        json_data = {
            "version": 6,
            "profiles": [],
            "hosts": [
                {
                    "id": 1,
                    "nickname": "compressed",
                    "protocol": "ssh",
                    "hostname": "example.com",
                    "username": "user",
                    "port": 22,
                    "compression": 1
                }
            ],
            "port_forwards": []
        }

        hosts, _ = self.parser.parse(json.dumps(json_data))

        self.assertTrue(hosts[0].compression)

    def test_parse_booleans_as_integers(self):
        """Test parsing all boolean fields as integers (ConnectBot export format)."""
        json_data = {
            "version": 6,
            "profiles": [],
            "hosts": [
                {
                    "id": 1,
                    "nickname": "intbools",
                    "protocol": "ssh",
                    "hostname": "example.com",
                    "username": "user",
                    "port": 22,
                    "useKeys": 1,
                    "wantSession": 1,
                    "compression": 0,
                    "stayConnected": 0,
                    "quickDisconnect": 0,
                    "useCtrlAltAsMetaKey": 0
                }
            ],
            "port_forwards": []
        }

        hosts, _ = self.parser.parse(json.dumps(json_data))

        self.assertTrue(hosts[0].use_keys)
        self.assertTrue(hosts[0].want_session)
        self.assertFalse(hosts[0].compression)
        self.assertFalse(hosts[0].stay_connected)
        self.assertFalse(hosts[0].quick_disconnect)
        self.assertFalse(hosts[0].use_ctrl_alt_as_meta_key)

    def test_parse_empty_hosts(self):
        """Test parsing JSON with no hosts."""
        json_data = {
            "version": 6,
            "profiles": [],
            "hosts": [],
            "port_forwards": []
        }

        hosts, _ = self.parser.parse(json.dumps(json_data))

        self.assertEqual(len(hosts), 0)


class TestConnectBotJsonWriter(unittest.TestCase):
    """Tests for ConnectBotJsonWriter class."""

    def setUp(self):
        self.writer = ConnectBotJsonWriter()

    def test_write_simple_host(self):
        """Test writing a simple host to ConnectBot JSON."""
        hosts = [
            SSHHost(
                nickname="myserver",
                hostname="example.com",
                username="admin",
                port=22
            )
        ]

        result = json.loads(self.writer.write(hosts))

        self.assertEqual(result["version"], 6)
        self.assertEqual(len(result["hosts"]), 1)
        self.assertEqual(result["hosts"][0]["nickname"], "myserver")
        self.assertEqual(result["hosts"][0]["hostname"], "example.com")
        self.assertEqual(result["hosts"][0]["username"], "admin")
        self.assertEqual(result["hosts"][0]["port"], 22)

    def test_write_with_jump_host(self):
        """Test writing hosts with jump host reference."""
        hosts = [
            SSHHost(nickname="internal", hostname="internal.com", proxy_jump="bastion"),
            SSHHost(nickname="bastion", hostname="bastion.com"),
        ]

        result = json.loads(self.writer.write(hosts))

        # internal should have jumpHostId pointing to bastion (id=2)
        self.assertEqual(result["hosts"][0]["jumpHostId"], 2)
        self.assertIsNone(result["hosts"][1]["jumpHostId"])

    def test_write_port_forwards(self):
        """Test writing hosts with port forwards."""
        hosts = [
            SSHHost(
                nickname="tunnel",
                hostname="example.com",
                port_forwards=[
                    PortForward("MySQL", "local", 3306, "localhost", 3306),
                    PortForward("Web", "remote", 8080, "localhost", 80),
                ]
            )
        ]

        result = json.loads(self.writer.write(hosts))

        self.assertEqual(len(result["port_forwards"]), 2)
        self.assertEqual(result["port_forwards"][0]["type"], "local")
        self.assertEqual(result["port_forwards"][0]["sourcePort"], 3306)
        self.assertEqual(result["port_forwards"][1]["type"], "remote")
        self.assertEqual(result["port_forwards"][1]["sourcePort"], 8080)

    def test_write_compression(self):
        """Test writing host with compression."""
        hosts = [
            SSHHost(nickname="compressed", hostname="example.com", compression=True)
        ]

        result = json.loads(self.writer.write(hosts))

        self.assertEqual(result["hosts"][0]["compression"], 1)

    def test_write_booleans_as_integers(self):
        """Test that all boolean fields are written as integers (0/1) not true/false."""
        hosts = [
            SSHHost(
                nickname="myserver",
                hostname="example.com",
                use_keys=True,
                want_session=True,
                compression=False,
                stay_connected=False,
                quick_disconnect=False,
                use_ctrl_alt_as_meta_key=False,
            )
        ]

        result = json.loads(self.writer.write(hosts))
        host = result["hosts"][0]

        self.assertIsInstance(host["useKeys"], int)
        self.assertNotIsInstance(host["useKeys"], bool)
        self.assertEqual(host["useKeys"], 1)

        self.assertIsInstance(host["wantSession"], int)
        self.assertEqual(host["wantSession"], 1)

        self.assertIsInstance(host["compression"], int)
        self.assertEqual(host["compression"], 0)

        self.assertIsInstance(host["stayConnected"], int)
        self.assertEqual(host["stayConnected"], 0)

        self.assertIsInstance(host["quickDisconnect"], int)
        self.assertEqual(host["quickDisconnect"], 0)

        self.assertIsInstance(host["useCtrlAltAsMetaKey"], int)
        self.assertEqual(host["useCtrlAltAsMetaKey"], 0)

    def test_write_includes_default_profile(self):
        """Test that output includes default profile."""
        hosts = [SSHHost(nickname="myserver", hostname="example.com")]

        result = json.loads(self.writer.write(hosts))

        self.assertEqual(len(result["profiles"]), 1)
        self.assertEqual(result["profiles"][0]["name"], "Default")

    def test_write_empty_list(self):
        """Test writing empty host list."""
        result = json.loads(self.writer.write([]))

        self.assertEqual(len(result["hosts"]), 0)
        self.assertEqual(len(result["port_forwards"]), 0)

    def test_host_ids_are_sequential(self):
        """Test that host IDs are assigned sequentially."""
        hosts = [
            SSHHost(nickname="server1", hostname="s1.com"),
            SSHHost(nickname="server2", hostname="s2.com"),
            SSHHost(nickname="server3", hostname="s3.com"),
        ]

        result = json.loads(self.writer.write(hosts))

        self.assertEqual(result["hosts"][0]["id"], 1)
        self.assertEqual(result["hosts"][1]["id"], 2)
        self.assertEqual(result["hosts"][2]["id"], 3)


class TestConversionFunctions(unittest.TestCase):
    """Tests for high-level conversion functions."""

    def test_ssh_config_to_connectbot(self):
        """Test full SSH config to ConnectBot conversion."""
        ssh_config = """
Host webserver
    HostName web.example.com
    User deploy
    Port 22
    Compression yes
"""
        result = json.loads(convert_ssh_config_to_connectbot(ssh_config))

        self.assertEqual(len(result["hosts"]), 1)
        self.assertEqual(result["hosts"][0]["nickname"], "webserver")
        self.assertEqual(result["hosts"][0]["hostname"], "web.example.com")
        self.assertEqual(result["hosts"][0]["compression"], 1)

    def test_connectbot_to_ssh_config(self):
        """Test full ConnectBot to SSH config conversion."""
        connectbot_json = json.dumps({
            "version": 6,
            "profiles": [],
            "hosts": [
                {
                    "id": 1,
                    "nickname": "webserver",
                    "protocol": "ssh",
                    "username": "deploy",
                    "hostname": "web.example.com",
                    "port": 2222,
                    "compression": True
                }
            ],
            "port_forwards": []
        })

        result = convert_connectbot_to_ssh_config(connectbot_json)

        self.assertIn("Host webserver", result)
        self.assertIn("HostName web.example.com", result)
        self.assertIn("User deploy", result)
        self.assertIn("Port 2222", result)
        self.assertIn("Compression yes", result)

    def test_round_trip_ssh_to_connectbot_to_ssh(self):
        """Test round-trip conversion: SSH -> ConnectBot -> SSH."""
        original_ssh = """
Host myserver
    HostName example.com
    User admin
    Port 2222
    Compression yes
"""
        # Convert to ConnectBot JSON
        connectbot_json = convert_ssh_config_to_connectbot(original_ssh)

        # Convert back to SSH config
        result_ssh = convert_connectbot_to_ssh_config(connectbot_json)

        # Verify key fields are preserved
        self.assertIn("Host myserver", result_ssh)
        self.assertIn("HostName example.com", result_ssh)
        self.assertIn("User admin", result_ssh)
        self.assertIn("Port 2222", result_ssh)
        self.assertIn("Compression yes", result_ssh)

    def test_round_trip_with_port_forwards(self):
        """Test round-trip conversion preserves port forwards."""
        original_ssh = """
Host tunnel
    HostName tunnel.example.com
    User tunneluser
    LocalForward 3306 localhost:3306
    RemoteForward 8080 localhost:80
"""
        connectbot_json = convert_ssh_config_to_connectbot(original_ssh)
        result_ssh = convert_connectbot_to_ssh_config(connectbot_json)

        self.assertIn("LocalForward 3306 localhost:3306", result_ssh)
        self.assertIn("RemoteForward 8080 localhost:80", result_ssh)

    def test_round_trip_with_jump_host(self):
        """Test round-trip conversion preserves jump host."""
        original_ssh = """
Host bastion
    HostName bastion.example.com
    User jumpuser

Host internal
    HostName internal.example.com
    User internaluser
    ProxyJump bastion
"""
        connectbot_json = convert_ssh_config_to_connectbot(original_ssh)
        result_ssh = convert_connectbot_to_ssh_config(connectbot_json)

        self.assertIn("ProxyJump bastion", result_ssh)


class TestEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        with self.assertRaises(json.JSONDecodeError):
            convert_connectbot_to_ssh_config("not valid json")

    def test_host_without_hostname(self):
        """Test handling of host without explicit hostname."""
        ssh_config = """
Host myserver
    User admin
"""
        result = json.loads(convert_ssh_config_to_connectbot(ssh_config))

        # When hostname is missing, it should use the nickname
        self.assertEqual(result["hosts"][0]["hostname"], "myserver")

    def test_invalid_port_number(self):
        """Test handling of invalid port number."""
        ssh_config = """
Host myserver
    HostName example.com
    Port notanumber
"""
        # Should not raise, just ignore invalid port
        result = json.loads(convert_ssh_config_to_connectbot(ssh_config))
        self.assertEqual(result["hosts"][0]["port"], 22)  # Default

    def test_malformed_port_forward(self):
        """Test handling of malformed port forward."""
        ssh_config = """
Host tunnel
    HostName example.com
    LocalForward invalid
"""
        # Should not raise, just ignore malformed forward
        result = json.loads(convert_ssh_config_to_connectbot(ssh_config))
        self.assertEqual(len(result["port_forwards"]), 0)

    def test_jump_host_not_found(self):
        """Test handling of jump host reference to non-existent host."""
        ssh_config = """
Host internal
    HostName internal.com
    ProxyJump nonexistent
"""
        result = json.loads(convert_ssh_config_to_connectbot(ssh_config))

        # Jump host ID should be None since reference doesn't exist
        self.assertIsNone(result["hosts"][0]["jumpHostId"])

    def test_empty_ssh_config(self):
        """Test conversion of empty SSH config."""
        result = json.loads(convert_ssh_config_to_connectbot(""))

        self.assertEqual(len(result["hosts"]), 0)

    def test_unicode_in_hostname(self):
        """Test handling of unicode in hostname."""
        ssh_config = """
Host myserver
    HostName ユニコード.example.com
    User admin
"""
        result = json.loads(convert_ssh_config_to_connectbot(ssh_config))
        self.assertEqual(result["hosts"][0]["hostname"], "ユニコード.example.com")

    def test_port_forward_with_bind_address(self):
        """Test parsing port forward with bind address."""
        ssh_config = """
Host tunnel
    HostName example.com
    LocalForward 127.0.0.1:3306 dbserver:3306
"""
        result = json.loads(convert_ssh_config_to_connectbot(ssh_config))

        self.assertEqual(len(result["port_forwards"]), 1)
        self.assertEqual(result["port_forwards"][0]["sourcePort"], 3306)
        self.assertEqual(result["port_forwards"][0]["destAddr"], "dbserver")
        self.assertEqual(result["port_forwards"][0]["destPort"], 3306)

    def test_connectbot_missing_optional_fields(self):
        """Test parsing ConnectBot JSON with missing optional fields."""
        json_data = {
            "version": 6,
            "profiles": [],
            "hosts": [
                {
                    "id": 1,
                    "nickname": "minimal",
                    "protocol": "ssh",
                    "hostname": "example.com",
                    "username": "",
                    "port": 22
                    # Missing: compression, useKeys, jumpHostId, etc.
                }
            ],
            "port_forwards": []
        }

        hosts, _ = ConnectBotJsonParser().parse(json.dumps(json_data))

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].nickname, "minimal")
        self.assertFalse(hosts[0].compression)  # Default


if __name__ == '__main__':
    unittest.main()
