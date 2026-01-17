# SSH Config Converter for ConnectBot

A Python script to convert between OpenSSH `~/.ssh/config` format and ConnectBot's JSON export format.

## Usage

```bash
# Convert SSH config to ConnectBot JSON
./ssh_config_converter.py --to-connectbot ~/.ssh/config -o connectbot_hosts.json

# Convert ConnectBot JSON to SSH config
./ssh_config_converter.py --to-ssh-config connectbot_export.json -o config

# Read from stdin, write to stdout
cat ~/.ssh/config | ./ssh_config_converter.py --to-connectbot

# Show warnings about ignored options
./ssh_config_converter.py --to-connectbot -v ~/.ssh/config
```

## Supported SSH Config Options

| SSH Config | ConnectBot Field | Notes |
|------------|------------------|-------|
| `Host` | `nickname` | Host alias/name |
| `HostName` | `hostname` | Actual server address |
| `User` | `username` | SSH username |
| `Port` | `port` | SSH port (default: 22) |
| `Compression` | `compression` | Enable compression |
| `ProxyJump` | `jumpHostId` | Jump/bastion host |
| `LocalForward` | `port_forwards` | Local port forwarding |
| `RemoteForward` | `port_forwards` | Remote port forwarding |
| `IdentityFile` | (noted only) | ConnectBot uses its own key store |

## Ignored SSH Config Options

The following options are not supported by ConnectBot and will be ignored:

- `ProxyCommand` (use `ProxyJump` instead)
- `ControlMaster`, `ControlPath`, `ControlPersist`
- `ServerAliveInterval`, `ServerAliveCountMax`
- `StrictHostKeyChecking`
- `UserKnownHostsFile`
- `ConnectTimeout`
- `ForwardAgent`, `ForwardX11`
- `DynamicForward`
- And other advanced options

Use `-v` or `--verbose` flag to see which options were ignored.

## Examples

See the `examples/` directory for sample files:
- `sample_ssh_config` - Example SSH config file
- `sample_connectbot.json` - Example ConnectBot JSON export

## Requirements

- Python 3.9+
- No external dependencies (uses only standard library)

## License

MIT License - See LICENSE file
