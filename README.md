# srun - 深澜认证登录工具，超轻量、多平台，支持多拨、自动探测IP、指定网卡

**This is a rewrite of [zu1k/srun](https://github.com/zu1k/srun) with additional features and improvements.**

[![GitHub stars](https://img.shields.io/github/stars/lihaotong0712/srun)](https://github.com/lihaotong0712/srun/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/lihaotong0712/srun)](https://github.com/lihaotong0712/srun/network)
[![GitHub issues](https://img.shields.io/github/issues/lihaotong0712/srun)](https://github.com/lihaotong0712/srun/issues)
[![Release](https://img.shields.io/github/release/lihaotong0712/srun)](https://github.com/lihaotong0712/srun/releases)
[![Build](https://github.com/lihaotong0712/srun/actions/workflows/build.yml/badge.svg)](https://github.com/lihaotong0712/srun/actions/workflows/build.yml)
[![GitHub license](https://img.shields.io/github/license/lihaotong0712/srun)](https://github.com/lihaotong0712/srun/blob/master/LICENSE)

Srun authentication system login tools. [compatible versions](https://github.com/zu1k/srun/discussions/8)

## Features

- Support both command line and config file
- Multiple IP acquisition methods
  - User Specified
  - Auto detect
  - Query by NIC name
- Support specify Auth Server address and IP
- Support strict bind
- Support multiple users login, suitable for multi-dial
- Support multi CPU architecture
- Support multi system

## Usage

[Pre-built binaries](https://github.com/lihaotong0712/srun/releases)

### CMD mode

Quickstart: (auto detect IP)

```bash
./srun login -s AUTH_SERVER -u USERNAME -p PASSWORD
```

Detailed usage:

```bash
./srun login -s AUTH_SERVER -u USERNAME -p PASSWORD [--ip IP / --iface IFACE] [--acid ACID] [--strict-bind true] \
    [--server-ip SERVER_IP] # provide server IP if DNS resolution fails \
    [--verify-cert skip | system | /path/to/cert.pem] \
    [-f / --force] # force login even already online \
    [--enc "srun_bx1"] [--n 200] [--type 1] [--double-stack false] # Default Srun configs, adjust based on captured packets \
    [--os "Linux"] [--os-name "Linux"] # specify OS info provided to srun \
    [--retry-times N] [--retry-delay MILLISECONDS]
```

`AUTH_SERVER` should contain protocols.

Example for BUAA (BUAA-WiFi):

```bash
./srun-tls login -s https://gw.buaa.edu.cn/ -u your_username -p your_password --acid 62 [--iface wlan0 --strict-bind true] [--server-ip 10.200.21.4]
```

#### Which IP to be authorized?

You can specify IP by `--ip` or `--iface`. If both are not provided, srun will try to auto detect the IP by querying all non-loopback interfaces.

You can use `./srun interfaces` to list all available interfaces and their IPs.

Currently only IPv4 is supported.

### Using a Config

Usually, it is sufficient to specify the information directly using command line parameters.

In order to meet the needs of multi-dial users, srun support reading multiple user information from a config file.

```bash
./srun login -c config.json
```

You can use `./srun gen-config [--file config.json]` to generate a sample config file.

Sample config file:

```json
{
  "server": "http://10.0.0.1",
  "server_ip": "10.0.0.1",
  "verify_cert": "skip",
  "users": [
    {
      "username": "your_username1",
      "password": "your_password1",
      "ip": "10.1.2.3"
    },
    {
      "username": "your_username2@cmcc",
      "password": "your_password2",
      "iface": "macvlan1"
    }
  ],
  "strict_bind": false,
  "enc": "srun_bx1",
  "n": 200,
  "type": 1,
  "acid": 1,
  "double_stack": false,
  "os": "Linux",
  "os_name": "Linux",
  "retry_count": 10,
  "retry_delay": 500
}
```

Since we use `serde_json` to parse the config file, srun doesn't support `json comments`, and detailed fields are optional. If a field is missing, the default value will be used.

As you can see, we support `ip` or `iface`.

If your IP will not change, you can use `ip` to specify directly.

But for multi-dial or Wifi, IP may be automatically assigned by DHCP and may change, at this time we suggest to use `iface` to specify the corresponding NIC name, we will automatically query the IP under that NIC as the IP to be authorized.

On windows, the NIC name may be like `{93123211-9629-4E04-82F0-EA2E4F221468}`, use `./srun interfaces` to see.

### Operator selection

Some colleges support network operator selection, which implemented by append the operator code to the username.

Operator code:

- 中国电信: [`chinanet`, `ctcc`]
- 中国移动: [`cmcc`]
- 中国联通: [`unicom`, `cucc`]
- 校园网: [`xn`]

For example, if you choose `cmcc`, just append `@cmcc` to your username, like `202112345@cmcc`.

This code needs to be confirmed by capturing packets.

### TLS support

Curretly, srun provides two binaries: `srun-<target-platform>-default` (with no optional features) and `srun-<target-platform>-tls`.

If your authentication system uses `https`, please use `srun-<target-platform>-tls`.

### Help message

```bash
./srun --help
Usage: ./srun [OPTIONS] <COMMAND>

Commands:
  login
  logout
  gen-config
  interfaces
  help        Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>              Config file path
  -s, --server <SERVER>              Srun Auth Server, default is "http://10.0.0.1/"
      --server-ip <SERVER_IP>        Srun Auth Server IP, default is None (resolve from dns)
  -f, --force                        Force login or logout even if already in desired state, default is false
      --verify-cert <VERIFY_CERT>    Certificate verification mode: skip, system (default), or path to custom CA cert
  -u, --username <USERNAME>          Username
  -p, --password <PASSWORD>          Password
      --ip <IP>                      IP address
      --iface <IFACE>                Network interface
      --strict-bind <STRICT_BIND>    Enable strict bind, default is false [possible values: true, false]
      --enc <ENC>                    Srun Param - Srun enc parameter, default is "srun_bx1"
      --n <N>                        Srun Param - Srun n parameter, default is 200
      --type <TYPE>                  Srun Param - Srun type parameter, default is 1
      --acid <ACID>                  Srun Param - "Srun ac_id parameter, default is 1
      --double-stack <DOUBLE_STACK>  Srun Param - Enable double stack, default is false [possible values: true, false]
      --os <OS>                      Srun Param - Operating system, default is "Linux"
      --os-name <OS_NAME>            Srun Param - Operating system name, default is "Linux"
      --retry-count <RETRY_COUNT>    Retry count, default is 10
      --retry-delay <RETRY_DELAY>    Retry interval in milliseconds, default is 500
  -h, --help                         Print help
  -V, --version                      Print version
```

### Linux Systemd Service Example

Create a service file `/etc/systemd/system/srun.service`: (example for srun installed in `/opt/srun/srun`)

```ini
[Unit]
Description=Srun
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/srun
ExecStart=/opt/srun/srun login -c /opt/srun/config.json

[Install]
WantedBy=multi-user.target
```

Then create a timer file `/etc/systemd/system/srun.timer`:

```ini
[Timer]
OnBootSec=15
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
```

Enable and start the timer:

```bash
sudo systemctl enable --now srun.timer
```

Inspect the status:

```bash
sudo systemctl status srun.service
sudo systemctl status srun.timer
```

Inspect the logs:

```bash
sudo journalctl -xeu srun.service
```

## Build from source

Make sure you have installed Rust toolchain. Then run:

```bash
cargo build --release --features tls
```

or:

```bash
cargo install cross --git https://github.com/cross-rs/cross
cross build --release --features tls
```

For building with `cross`, make sure you have installed `Docker` first, and you can enable `create-container-cache` in `Cross.toml`.

## License

**srun** © [lihaotong0712](https://github.com/lihaotong0712), Released under the [GPL-3.0](./LICENSE) License.
