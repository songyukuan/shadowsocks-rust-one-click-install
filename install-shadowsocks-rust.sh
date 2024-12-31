#!/bin/bash

# Created by 灰太狼 (QQ: 5278212)
# 2024/12/24 (Ver: 1.0.0)
# curl -SL https://api.miguan.vip/download/shadowsocks/release/setup_shadowsocks-rust.sh -o setup_shadowsocks-rust.sh && sudo chmod +x ./setup_shadowsocks-rust.sh && sudo bash ./setup_shadowsocks-rust.sh
# --password yourpassword
# --port 12345
# --cipher chacha20-ietf-poly1305
# -y


PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
LANG=en_US.UTF-8
set -e
set -o pipefail

while [[ $# -gt 0 ]]; do
    case $1 in
    -p | --password)
        ss_pswd="$2"
        shift 1
        ;;
    -P | --port)
        ss_port="$2"
        shift 1
        ;;
    -c | --cipher)
        ss_ciph="$2"
        shift 1
        ;;
    -y)
        choice_continue="y"
        ;;
    esac
    shift 1
done

SS_PORT=$(shuf -i 18000-18999 -n 1)
SS_PSWD="5278212@qq.com"
SS_CIPH="aes-256-cfb"
SS_HOST=""

OS_ID=""
OS_VERSION_ID=""
CURDIR=$(pwd)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'
WHITE='\033[1;32m'
BLUE='\033[0;34m'

CIPHERS=(
    aes-256-gcm
    aes-192-gcm
    aes-128-gcm
    aes-256-ctr
    aes-192-ctr
    aes-128-ctr
    aes-256-cfb
    aes-192-cfb
    aes-128-cfb
    camellia-128-cfb
    camellia-192-cfb
    camellia-256-cfb
    xchacha20-ietf-poly1305
    chacha20-ietf-poly1305
    chacha20-ietf
    chacha20
    salsa20
    rc4-md5
)

print_info() {
    local message=$1
    local color=${2:-$GREEN}
    local timestamp=$(date +"%T")
    echo -e "${GREEN}[ $timestamp ]${RESET} ${color}$message${RESET}" >&2
}

get_os_type() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION_ID="$VERSION_ID"
        print_info "Your system is ${OS_ID} ${OS_VERSION_ID}"
        case "$OS_ID" in
        "ubuntu" | "centos" | "debian" | "armbian")
            return 0
            ;;
        *)
            print_info "Unsupported system: ${OS_ID}" ${RED}
            return 1
            ;;
        esac
    else
        print_info "Unknown system." ${RED}
        return 1
    fi
}

out_put() {
    local message=$1

    print_info "---------------------------" ${BLUE}
    print_info "${message}" ${WHITE}
    print_info "---------------------------" ${BLUE}
}

install_dependencies() {
    # Function to install dependencies for CentOS/RedHat and Debian/Ubuntu
    print_info "Installing dependencies ..."

    if [ "${OS_ID}" == "centos" ]; then
        yum update -y
        yum upgrade -y
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            print_info "Installing EPEL repository ..."
            yum install -y -q epel-release
        fi
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            print_info "EPEL repository installation failed, please check it" ${RED}
            return 1
        fi
        if ! command -v yum-config-manager >/dev/null; then
            print_info "Installing yum-utils ..."
            yum install -y -q yum-utils
        fi
        if [ "$(yum-config-manager epel | grep -w enabled | awk '{print $3}')" != "True" ]; then
            yum-config-manager --enable epel
            print_info "EPEL repository enabled"
        fi
        print_info "Installing required packages on CentOS..."
        packages="wget curl unzip openssl openssl-devel gettext gcc autoconf libtool automake make asciidoc xmlto libev-devel pcre pcre-devel git c-ares-devel jq python3 firewalld bzip2 xz"
        yum install -y ${packages}
    elif [ "${OS_ID}" == "ubuntu" ] || [ "${OS_ID}" == "debian" || "${OS_ID}" == "armbian" ]; then
        packages="wget curl libcurl4-openssl-dev gcc make zip unzip tar openssl libssl-dev libxml2 libxml2-dev zlib1g zlib1g-dev libjpeg-dev libpng-dev lsof libpcre3 libpcre3-dev cron net-tools swig build-essential libffi-dev libbz2-dev libncurses-dev libsqlite3-dev libreadline-dev tk-dev libgdbm-dev libdb-dev libdb++-dev libpcap-dev xz-utils git qrencode ruby lsb-release gettext python python-dev python-setuptools 2to3 python2 libev-dev libc-ares-dev jq firewalld bzip2"
        print_info "Updating and installing packages on Debian/Ubuntu..."
        sudo apt-get update -y
        sudo apt-get upgrade -y
        sudo apt-get install -y ${packages}
    else
        print_info "Unsupported OS: ${OS_ID}. Please check the OS_ID value." ${RED}
        return 1
    fi

    print_info "Dependencies installation complete"
}

download_release() {
    local package_user=$1
    local package_name=$2
    local package_tag=$3
    local package_ass=$4
    if [ -z "${package_user}" ] || [ -z "${package_name}" ] || [ -z "${package_tag}" ] || [ -z "${package_ass}" ]; then
        print_info "Error: Missing required parameters." ${RED}
        return 1
    fi
    local file_name="${package_name}.${package_ass}"
    local download_url="https://github.com/${package_user}/releases/download/${package_tag}/${file_name}"
    print_info "Downloading from: ${download_url}"
    print_info "File name: ${file_name}, downloading ... "
    curl -sfL -o "${file_name}" "${download_url}"
    if [ $? -eq 0 ]; then
        print_info "Download successful: ${file_name}"
        echo "${file_name}"
    else
        print_info "Download failed." ${RED}
        return 1
    fi
}

install_package() {
    local file_path="$1"
    local install_command="$2"
    local extract_dir=""
    local file_name=$(basename "${file_path}")
    cd "${CURDIR}"
    if [[ "${file_name}" =~ \.tar\.bz2$ ]]; then
        extract_dir="${file_name%.tar.bz2}"
    elif [[ "${file_name}" =~ \.tar\.gz$ ]]; then
        extract_dir="${file_name%.tar.gz}"
    elif [[ "${file_name}" =~ \.tar\.xz$ ]]; then
        extract_dir="${file_name%.tar.xz}"
    elif [[ "${file_name}" =~ \.zip$ ]]; then
        extract_dir="${file_name%.zip}"
    else
        extract_dir="${file_name%.*}"
    fi
    if [ ! -f "${file_path}" ]; then
        print_info "Error: File not found: ${file_path}" ${RED}
        return 1
    fi
    if [ -d "${extract_dir}" ]; then
        print_info "Removing existing directory: ${extract_dir}"
        rm -rf "${extract_dir}"
    fi
    print_info "Extracting ${file_path}..."
    mkdir -p "${extract_dir}"
    print_info "file_path: ${file_path}, extract dir: ${extract_dir}"
    if [[ "${file_name}" == *.tar.bz2 ]]; then
        tar -xjf "${file_path}" -C "${extract_dir}" --strip-components=1 && [ -z "$(ls -A "${extract_dir}")" ] && tar -xjf "${file_path}" -C "${extract_dir}"
    elif [[ "${file_name}" == *.tar.gz ]]; then
        tar -xzf "${file_path}" -C "${extract_dir}" --strip-components=1 && [ -z "$(ls -A "${extract_dir}")" ] && tar -xzf "${file_path}" -C "${extract_dir}"
    elif [[ "${file_name}" == *.tar.xz ]]; then
        tar -xJf "${file_path}" -C "${extract_dir}" --strip-components=1 && [ -z "$(ls -A "${extract_dir}")" ] && tar -xJf "${file_path}" -C "${extract_dir}"
    elif [[ "${file_name}" == *.zip ]]; then
        unzip -q "${file_path}" -d "${extract_dir}"
    else
        print_info "Error: Unsupported archive format: ${file_name}" ${RED}
        return 1
    fi
    print_info "Changing to directory: ${extract_dir}"
    cd "${extract_dir}" || {
        print_info "Error: Failed to change directory to ${extract_dir}"
        return 1
    }
    print_info "Running custom install command: ${install_command}"
    eval "${install_command}"
    if [ $? -ne 0 ]; then
        print_info "Error: Installation command failed." ${RED}
        cd "${CURDIR}"
        return 1
    fi
    print_info "Installation completed successfully."
    cd "${CURDIR}" || {
        print_info "Error: Failed to return to the original directory"
        return 1
    }
    print_info "Cleaning up..."
    rm -rf "${file_path}" "${extract_dir}"
    print_info "Cleanup completed."
    return 0
}

install_libsodium() {
    if [ -f "/usr/lib/libsodium.a" ]; then
        print_info "Libsodium is already installed." # 提示已安装
        return 0
    fi
    local package_user="jedisct1/libsodium"
    local package_name="libsodium-1.0.20"
    local package_tag="1.0.20-RELEASE"
    local package_ass="tar.gz"
    local install_command="sudo ./configure --prefix=/usr && sudo make && sudo make install"
    local file_path=$(download_release "${package_user}" "${package_name}" "${package_tag}" "${package_ass}")
    if [ $? -eq 0 ]; then
        install_package "${file_path}" "${install_command}"
        ldconfig
    else
        print_info "Failed to download the ${package_name}" ${RED}
        return 1
    fi
}

install_mbedtls() {
    if [ -f "/usr/lib/libmbedtls.a" ]; then
        print_info "MbedTLS is already installed."
        return 0
    fi
    local package_user="Mbed-TLS/mbedtls"
    local package_name="mbedtls-3.6.2"
    local package_tag="mbedtls-3.6.2"
    local package_ass="tar.bz2"
    local install_command="sudo make SHARED=1 CFLAGS='-fPIC -std=c99' && sudo make DESTDIR=/usr install"
    local file_path=$(download_release "${package_user}" "${package_name}" "${package_tag}" "${package_ass}")
    if [ $? -eq 0 ]; then
        install_package "${file_path}" "${install_command}"
        ldconfig
    else
        print_info "Failed to download the ${package_name}" ${RED}
        return 1
    fi
}

install_v2ray_plugin() {
    if [ -f "/usr/local/shadowsocks-rust/v2ray-plugin" ]; then
        print_info "V2ray-plugin is already installed." # 提示已安装
        return 0
    fi
    local package_user="shadowsocks/v2ray-plugin"
    local package_name="v2ray-plugin-linux-amd64-v1.3.2"
    local package_tag="v1.3.2"
    local package_ass="tar.gz"
    local install_command="sudo make SHARED=1 CFLAGS='-fPIC -std=c99' && sudo make DESTDIR=/usr install"
    local file_path=$(download_release "${package_user}" "${package_name}" "${package_tag}" "${package_ass}")
    if [ $? -eq 0 ]; then
        install_package "${file_path}" "${install_command}"
        ldconfig
    else
        print_info "Failed to download the ${package_name}" ${RED}
        return 1
    fi
}
version_gt() {
    test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
}
check_kernel_version() {
    local kernel_version=$(uname -r | cut -d- -f1)
    if version_gt ${kernel_version} 3.7.0; then
        return 0
    else
        return 1
    fi
}
get_ipv4() {
    local IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
    [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
    [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipinfo.io/ip)
    [ ! -z ${IP} ] && echo ${IP} || echo
}
get_ipv6() {
    local IPV6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [ ! -z ${IPV6} ] && echo ${IPV6} || echo
}
check_ip_address() {
    ipv4=$(get_ipv4)
    ipv6=$(get_ipv6)
    if [ -n "${ipv4}" ]; then
        print_info "IPv4 Address: ${ipv4}"
    else
        print_info "IPv4 Address not found." ${YELLOW}
    fi

    if [ -n "${ipv6}" ]; then
        print_info "IPv6 Address: ${ipv6}"
    else
        print_info "IPv6 Address not found." ${YELLOW}
    fi
}

set_sysctl_param() {
    local param=$1
    local value=$2
    local sysctl_file="/etc/sysctl.conf"
    local full_param="net.ipv4.${param}"
    if grep -q "^${full_param}" "${sysctl_file}"; then
        sudo sed -i "s|^${full_param}.*|${full_param} = ${value}|" "${sysctl_file}"
        print_info "Updated '${full_param}' to ${value} in ${sysctl_file}"
    else
        echo "${full_param} = ${value}" | sudo tee -a "${sysctl_file}" >/dev/null
        print_info "Added '${full_param} = ${value}' to ${sysctl_file}"
    fi
    sudo sysctl -p
}

config_shadowsocks_rust() {
    sudo cat >/etc/systemd/system/shadowsocks-rust.service <<-EOF
[Unit]
Description=Shadowsocks-rust
Documentation=https://github.com/shadowsocks/shadowsocks-rust
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/shadowsocks-rust/ssserver -c /usr/local/shadowsocks-rust/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
LimitNOFILE=32768
RestartSec=3
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
    sudo chmod 0777 /etc/systemd/system/shadowsocks-rust.service
    sudo systemctl daemon-reload
    sudo systemctl enable shadowsocks-rust
    sudo systemctl start shadowsocks-rust
    if [ -z "${ipv6}" ]; then
        local server_value="\"0.0.0.0\""
    else
        local server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi
    set_sysctl_param "tcp_fastopen" 3
    if check_kernel_version && [ $? -eq 0 ]; then
        fast_open="true"
    else
        fast_open="false"
    fi
    mkdir -p "/usr/local/shadowsocks-rust/${SS_HOST}"
    curl -sfL -o "/usr/local/shadowsocks-rust/${SS_HOST}/fullchain.pem" "http://${SS_HOST}/cert/fullchain.pem"
    curl -sfL -o "/usr/local/shadowsocks-rust/${SS_HOST}/privkey.pem" "http://${SS_HOST}/cert/privkey.pem"
    cat >/usr/local/shadowsocks-rust/config.json <<-EOF
{
    "server":${server_value},
    "server_port":${ss_port},
    "password":"${ss_pswd}",
    "timeout":300,
    "user":"nobody",
    "method":"${ss_ciph}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"/usr/local/shadowsocks-rust/v2ray-plugin",
    "plugin_opts":"server;tls;host=${SS_HOST};cert=/usr/local/shadowsocks-rust/${SS_HOST}/fullchain.pem;key=/usr/local/shadowsocks-rust/${SS_HOST}/privkey.pem",
    "pid-file":"/tmp/shadowsocks.pid",
    "log-file":"/var/log/shadowsocks/shadowsocks.log"
}
EOF
}

install_shadowsocks_rust() {
    if [ -f "/usr/local/shadowsocks-rust/ssserver" ]; then
        print_info "Shadowsocks-rust is already installed." # 提示已安装
        return 0
    fi
    if [ ! -d /usr/local/shadowsocks-rust ]; then
        mkdir -p /usr/local/shadowsocks-rust
    fi
    local package_user="shadowsocks/shadowsocks-rust"
    local package_name="shadowsocks-v1.21.2.x86_64-unknown-linux-musl"
    local package_tag="v1.21.2"
    local package_ass="tar.xz"
    local install_command="sudo chmod +x * && sudo cp -af * /usr/local/shadowsocks-rust"
    local file_path=$(download_release "${package_user}" "${package_name}" "${package_tag}" "${package_ass}")
    if [ $? -eq 0 ]; then
        install_package "${file_path}" "${install_command}"
        install_v2ray_plugin
        config_shadowsocks_rust
    else
        print_info "Failed to download the ${package_name}" ${RED}
        return 1
    fi
}

install_v2ray_plugin() {
    if [ -f "/usr/local/shadowsocks-rust/v2ray-plugin" ]; then
        print_info "V2ray-plugin is already installed." # 提示已安装
        return 0
    fi
    local package_user="shadowsocks/v2ray-plugin"
    local package_name="v2ray-plugin-linux-amd64-v1.3.2"
    local package_tag="v1.3.2"
    local package_ass="tar.gz"
    local install_command="sudo mv ./v2ray-plugin_linux_amd64 /usr/local/shadowsocks-rust/v2ray-plugin && sudo chmod +x /usr/local/shadowsocks-rust/v2ray-plugin"
    local file_path=$(download_release "${package_user}" "${package_name}" "${package_tag}" "${package_ass}")
    if [ $? -eq 0 ]; then
        install_package "${file_path}" "${install_command}"
        ldconfig
    else
        print_info "Failed to download the ${package_name}" ${RED}
        return 1
    fi
}

config_firewalld() {
    sudo systemctl enable firewalld
    sudo systemctl start firewalld
    sshPort=$(cat /etc/ssh/sshd_config | grep 'Port ' | awk '{print $2}')
    firewall-cmd --permanent --zone=public --add-port=${sshPort}/tcp >/dev/null 2>&1
    firewall-cmd --permanent --zone=public --add-port=${ss_port}/tcp >/dev/null 2>&1
    firewall-cmd --reload
}
disable_selinux() {
    if [ -s /etc/selinux/config ]; then
        local selinux_config=$(cat /etc/selinux/config)
        if echo "${selinux_config}" | grep -q '^SELINUX=enforcing$'; then
            sed -i 's/^SELINUX=enforcing$/SELINUX=disabled/' /etc/selinux/config
            setenforce 0
            if [ $? -ne 0 ]; then
                print_info "Failed to set SELinux to permissive mode."
            fi
        fi
    fi
}

# =====================================================================================

if [ $(whoami) != "root" ]; then
    print_info "This script must be run as root or with sudo privileges." ${RED}
    exit 1
fi
if ! sudo -v; then
    print_info "This script requires sudo privileges. Please run as a user with sudo access." ${RED}
    exit 1
fi
clear
echo -e "${GREEN}#########################################################"
echo -e "#                                                       #"
echo -e "#            Shadowsocks-rust onekey setup              #"
echo -e "#           Created By: YiKaSo (QQ: 5278212)            #"
echo -e "#                     Ver: 1.2.0                        #"
echo -e "#                                                       #"
echo -e "#          Alipay donation: ace0168@yeah.net            #"
echo -e "#                Thank you for using                    #"
echo -e "#                                                       #"
echo -e "#########################################################${RESET}"
if [ -z "${ss_pswd}" ]; then
    print_info "Please enter password for shadowsocks: " ${WHITE}
    read -p "(Default password: ${SS_PSWD}):" ss_pswd
    [ -z "${ss_pswd}" ] && ss_pswd="${SS_PSWD}"
fi
if [ -z "${ss_port}" ]; then
    while true; do
        print_info "Please enter a port for shadowsocks [1-65535]" ${WHITE}
        read -p "(Default port: ${SS_PORT}): " ss_port
        [ -z "${ss_port}" ] && ss_port=${SS_PORT}
        expr ${ss_port} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${ss_port} -ge 1 ] && [ ${ss_port} -le 65535 ] && [ ${ss_port:0:1} != 0 ]; then
                break
            fi
        fi
        print_info "Please enter a correct number [1-65535]" ${YELLOW}
    done
fi
if [ -z "${ss_ciph}" ]; then
    while true; do
        print_info "Please select stream cipher for shadowsocks: " ${WHITE}
        for ((i = 1; i <= ${#CIPHERS[@]}; i++)); do
            hint="${CIPHERS[$i - 1]}"
            print_info "${green}${i}${plain}) ${hint}" ${WHITE}
        done
        read -p "Which cipher you'd select(Default: ${CIPHERS[6]}):" pick
        [ -z "${pick}" ] && pick=7
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            print_info "Please enter a number."
            continue
        fi
        if [[ "${pick}" -lt 1 || "${pick}" -gt ${#CIPHERS[@]} ]]; then
            print_info "Please enter a number between 1 and ${#CIPHERS[@]}."
            continue
        fi
        ss_ciph=${CIPHERS[${pick} - 1]}
        break
    done
fi
print_info "---------------------------" ${BLUE}
print_info "Shadowsocks port     : ${ss_port}" ${WHITE}
print_info "Shadowsocks password : ${ss_pswd}" ${WHITE}
print_info "Shadowsocks cipher   : ${ss_ciph}" ${WHITE}
print_info "---------------------------" ${BLUE}
while [[ "${choice_continue}" != "y" && "${choice_continue}" != "Y" && "${choice_continue}" != "n" && "${choice_continue}" != "N" ]]; do
    read -p "You can input 'y' to start, input 'n' or Ctrl+C to cancel (y/n): " choice_1
done

if [[ "${choice_continue}" == "n" || "${choice_continue}" == "N" ]]; then
    print_info "Program terminated." ${RED}
    exit 0
fi
get_os_type
disable_selinux
out_put "[STEP] Install dependencies ..."
install_dependencies
check_ip_address
out_put "[STEP] Install libsodium ..."
install_libsodium
out_put "[STEP] Install mbedtls ..."
install_mbedtls
out_put "[STEP] Install shadowsocks ..."
install_shadowsocks_rust
out_put "[STEP] Set firewalld ..."
config_firewalld
print_info "---------------------------" ${BLUE}
print_info "Your server IP       : ${ipv4}" ${WHITE}
print_info "Shadowsocks port     : ${ss_port}" ${WHITE}
print_info "Shadowsocks password : ${ss_pswd}" ${WHITE}
print_info "Shadowsocks cipher   : ${ss_ciph}" ${WHITE}
print_info "---------------------------" ${BLUE}
