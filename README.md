# xray-check

`xray-check` reads an Xray/V2Ray subscription, extracts its server addresses, and looks up their approximate IP, location, ISP, and ASN using [ip-api.com](https://ip-api.com/).

It does **not** connect to or test proxy servers. It only inspects subscription data and looks up the addresses it finds.

## Features

- Reads supported proxy share links and Xray-style JSON outbounds.
- Shows the protocol, node name, address, port, country, city, ISP, and ASN.
- Accepts common subscription User-Agent presets or a custom User-Agent.
- Can try every built-in User-Agent preset and choose the response with the most recognized configs.
- Available as a Python command-line app or as a standalone release executable.

## Requirements

- Python 3.10 or later (for source installation)

## Install

### Standalone executable

Download the latest executable for your platform from the project's GitHub Releases:

- macOS: `xray-check`
- Windows: `xray-check.exe`

The executable bundles Python and project dependencies; no separate Python installation or `pip install` is needed. On macOS, if needed, make the downloaded file executable:

```sh
chmod +x ./xray-check
```

Run the downloaded executable directly:

```sh
./xray-check
```

In PowerShell, run `.\xray-check.exe`. macOS may warn that the app is from an unidentified developer because the executable is not code-signed. The macOS build uses the architecture of the GitHub-hosted runner.

### Install from source

Python 3.10 or later is required. From the project directory, install the package and its dependencies:

```sh
python -m pip install .
```

## Usage

Run the command without arguments to enter a subscription URL interactively, or pass one with `--url`:

```sh
xray-check
xray-check --url 'https://example.com/my-subscription'
```

### Options

| Option | Description |
| --- | --- |
| `--url URL` | Subscription URL. If omitted, the command prompts for it. |
| `--ua VALUE` | User-Agent preset or literal string. Default: `Happ/5.0.0`. |
| `--lang {en,ru}` | Language for ip-api.com location fields. Default: `en`. |
| `--try-all` | Try all built-in User-Agent presets and use the response with the most recognized configs. |
| `-h`, `--help` | Show help. |

Examples:

```sh
# Use the Clash preset
xray-check --url 'https://example.com/my-subscription' --ua clash

# Use a custom User-Agent and Russian lookup results
xray-check --url 'https://example.com/my-subscription' \
  --ua 'MyClient/1.0' --lang ru

# Try all built-in User-Agent presets
xray-check --url 'https://example.com/my-subscription' --try-all
```

Built-in presets: `clash`, `v2rayng`, `neko`, `hiddify`, `sagernet`, `streisand`, `happ`, `incy`, `shadowrocket`, `quantumult`, `surfboard`, and `singbox`. Values that are not preset names are sent as literal User-Agent strings.

## Supported config formats

### Share links

The parser recognizes `vmess://`, `vless://`, `trojan://`, `ss://`, `ssr://`, `hysteria2://`, and `hy2://` links.

### JSON outbounds

JSON parsing supports Xray-style outbounds, including VMess, VLESS, Trojan, Shadowsocks, SOCKS, HTTP, Hysteria, TUIC, and WireGuard, when an address can be extracted from the outbound's settings.

For example, the configuration-level `remarks` value is used as the displayed name when an outbound does not have its own `name`:

```json
{
  "remarks": "🇷🇺Россия",
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "example.org",
            "port": 443
          }
        ]
      }
    }
  ],
  "routing": {
    "domainMatcher": "hybrid",
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "outboundTag": "direct",
        "protocol": ["bittorrent"],
        "type": "field"
      }
    ]
  }
}
```

The displayed name is selected in this order: outbound `name`, configuration-level `remarks`, then `meta.serverDescription`. The outbound `tag` is not used as the name.

Configs are deduplicated by protocol, address, and port. Address lookups run in batches, with a pause between batches to accommodate ip-api.com's rate limits; large subscriptions may take a while.

## Privacy and lookup behavior

- The subscription is fetched from your machine using the selected User-Agent. `--try-all` fetches it once for each built-in preset.
- Each extracted server address is sent to ip-api.com. The current lookup uses ip-api.com's HTTP endpoint, so lookup requests are not encrypted in transit.
- Subscription URLs can contain private access tokens. Use the interactive prompt instead of `--url` if you do not want the URL stored in shell history or exposed in process arguments.
- Location and ISP results are informational. They do not indicate whether a proxy is reachable or working.
