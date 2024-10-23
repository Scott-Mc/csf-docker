# CSF Docker Integration Script

This script integrates Docker container traffic control with ConfigServer Security & Firewall (CSF).
It allows you to enforce CSF's firewall rules on Docker containers by default. However, for specific cases, such as when you need to allow an NGINX proxy container to retrieve the real client IP, you can bypass CSF rules for those ports using DNAT.

CSF provides some docker filtering by default in /etc/csf/csf.conf so try that first. You only need a secondary post script if you need to DNAT to get the end clients IP address, such as for web proxies.

## Installation

1. Copy the script to /etc/csf/csfpost.sh
   ```sh
   wget -O /etc/csf/csfpost.sh https://raw.githubusercontent.com/Scott-Mc/refs/heads/main/csfpost.sh
   ```
2. Ensure the script is executable:
   ```sh
   chmod +x /etc/csf/csfpost.sh
   ```
3. Restart CSF

   ```sh
   csf -r
   ```

4. To ensure Docker does not manage iptables directly, edit the systemd unit file for Docker:

   - Open the Docker unit file for editing:

   ```sh
     sudo systemctl edit docker
   ```

   Add `--iptables=false` to the startup line `ExecStart` line so it looks something like like:

   ```sh
     [Service]
     ExecStart=
     ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock --iptables=false
   ```

   - Save and exit, then reload and restart Docker:

   ```sh
     sudo systemctl daemon-reload
     sudo systemctl restart docker
   ```

## Usage

By default, this script will enforce CSF rules on all Docker containers. However, certain containers, like NGINX proxies, may need to bypass CSF rules to capture the real client's IP address. This is achieved using DNAT.

The script offers two configurable variables to control DNAT behavior:

### Configurable Variables

1. **ALLOWED_DNAT_PORTS**: List of container ports to allow DNAT (which bypasses CSF). Common values would be `80` and `443` for NGINX containers.

   - Example to allow `80` and `443` ports for DNAT:
     ```sh
     ALLOWED_DNAT_PORTS="80 443"
     ```
   - Set to `all` to allow DNAT for all ports exposed by containers (this is not recommended unless necessary):
     ```sh
     ALLOWED_DNAT_PORTS="all"
     ```
   - If left empty (default), DNAT is not applied and CSF handles the port allows (TCP_IN) / whitelists.

2. **ALLOWED_DNAT_SOURCE**: Restrict the source IP for DNAT.
   - Example: To allow DNAT only for internal VPN traffic (e.g., `10.1.0.0/24`):
     ```sh
     ALLOWED_DNAT_SOURCE="10.1.0.0/24"
     ```
   - The default is `0.0.0.0/0`, which allows DNAT from any source address and is what you would use in most use cases.

## Example Scenarios

- **Default Behavior**: By default, CSF will control all ports, and no DNAT rules are applied. This is the recommended and most secure configuration.
- **NGINX Proxy Use Case**: If you are running an NGINX proxy in Docker and need to capture the real client IP, you will likely need to enable DNAT for ports `80` and `443`:

  ```sh
  ALLOWED_DNAT_PORTS="80 443"
  ALLOWED_DNAT_SOURCE="0.0.0.0/0" # Allow DNAT from all sources
  ```

## License

This script is licensed under the MIT License. See the LICENSE file for more details.

## Author and Credits

- **Maintainer**: Scott Mcintyre (<me@scott.cm>)
- **Based on**: The original script from [https://github.com/juli3nk/csf-post-docker](https://github.com/juli3nk/csf-post-docker)

## Contributing

Feel free to open issues or submit pull requests to contribute to this project. Any improvements or suggestions are welcome.
