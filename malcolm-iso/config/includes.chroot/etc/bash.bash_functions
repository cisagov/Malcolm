########################################################################
# text processing
########################################################################
function cols () {
    first="awk '{print "
    last="}'"
    cmd="${first}"
    commatime=""
    for var in "$@"
    do
      if [ -z $commatime ]
      then
        commatime="no"
        cmd=${cmd}\$${var}
      else
        cmd=${cmd}\,\$${var}
      fi
    done
    cmd="${cmd}${last}"
    eval $cmd
}

function headtail () {
  awk -v offset="$1" '{ if (NR <= offset) print; else { a[NR] = $0; delete a[NR-offset] } } END { { print "--------------------------------" } for (i=NR-offset+1; i<=NR; i++) print a[i] }' ;
}

function wait_file() {
  local file="$1"; shift
  local wait_seconds="${1:-10}"; shift # 10 seconds as default timeout

  until test $((wait_seconds--)) -eq 0 -o -f "$file" ; do sleep 1; done

  ((++wait_seconds))
}

function taildiff () {
  LEFT_FILE=$1
  RIGHT_FILE=$2
  RIGHT_LINES=$(wc -l "$RIGHT_FILE" | cut -d ' ' -f1)
  diff -bwBy --suppress-common-lines <(head -n $RIGHT_LINES "$LEFT_FILE") <(head -n $RIGHT_LINES "$RIGHT_FILE")
}

function dirdiff () {
  if [ -d "$1" ] && [ -d "$2" ]; then
    dir1="$1"
    dir2="$2"
    IFS=$'\n'
    for file in $(grep -Ilsr -m 1 '.' "$dir1"); do
      diff -q "$file" "${file/${dir1}/${dir2}}"
    done
  else
    echo "Must specify two directories">&2
  fi
}

function fs() {
  if du -b /dev/null > /dev/null 2>&1; then
    local arg=-sbh;
  else
    local arg=-sh;
  fi
  if [[ -n "$@" ]]; then
    du $arg -- "$@";
  else
    du $arg .[^.]* ./*;
  fi;
}

function lin () {
  sed -n $1p
}

function fsize () {
  echo "$1" | awk 'function human(x) {
     s=" B   KiB MiB GiB TiB EiB PiB YiB ZiB"
     while (x>=1024 && length(s)>1)
           {x/=1024; s=substr(s,5)}
     s=substr(s,1,4)
     xf=(s==" B  ")?"%5d   ":"%0.2f"
     return sprintf( xf"%s", x, s)
  }
  {gsub(/^[0-9]+/, human($1)); print}'
}

function multigrep() { local IFS='|'; grep -rinE "$*" . ; }

function ord() { printf "%d\n" "'$1"; }

function chr() { printf \\$(($1/64*100+$1%64/8*10+$1%8))\\n; }

########################################################################
# math
########################################################################
function calc () { python -c "from math import *; n = $1; print n; print '$'+hex(trunc(n))[2:]; print '&'+oct(trunc(n))[1:]; print '%'+bin(trunc(n))[2:];"; }

function add () {
  awk '{s+=$1} END {print s}'
}

########################################################################
# date/time
########################################################################
function dateu()
{
  if [ "$1" ]; then
    echo $(date -u -d @$1);
  else
    echo "No UNIX time specified">&2
  fi
}

function udate()
{
  if [ "$1" ]; then
    date -u +%s -d "$1"
  else
    date -u +%s
  fi
}

function sec2dhms() {
  if [ "$1" ]; then
    SECS="$1"
    printf '%02d:%02d:%02d\n' $(($SECS/3600)) $(($SECS%3600/60)) $(($SECS%60))
  else
    echo "00:00:00"
  fi
}

########################################################################
# directory navigation/file manipulation
########################################################################
function cd() { if [[ "$1" =~ ^\.\.+$ ]];then local a dir;a=${#1};while [ $a -ne 1 ];do dir=${dir}"../";((a--));done;builtin cd $dir;else builtin cd "$@";fi ;}

function fcd() { [ -f $1  ] && { cd $(dirname $1);  } || { cd $1 ; } }

function up { cd $(eval printf '../'%.0s {1..$1}) && pwd; }

function realgo() { fcd $(realpath $(which $1)) && pwd ; }

function realwhich() { realpath $(which $1) ; }

function renmod() {
  FILENAME="$@";
  TIMESTAMP=$(date -d @$(stat -c%Y "$FILENAME") +"%Y%m%d%H%M%S")
  mv -iv "$FILENAME" "$FILENAME.$TIMESTAMP"
}

function upto() {
  local EXPRESSION="$1"
  if [ -z "$EXPRESSION" ]; then
    echo "A folder expression must be provided." >&2
    return 1
  fi
  if [ "$EXPRESSION" = "/" ]; then
    cd "/"
    return 0
  fi
  local CURRENT_FOLDER="$(pwd)"
  local MATCHED_DIR=""
  local MATCHING=true

  while [ "$MATCHING" = true ]; do
    if [[ "$CURRENT_FOLDER" =~ "$EXPRESSION" ]]; then
      MATCHED_DIR="$CURRENT_FOLDER"
      CURRENT_FOLDER=$(dirname "$CURRENT_FOLDER")
    else
      MATCHING=false
    fi
  done
  if [ -n "$MATCHED_DIR" ]; then
    cd "$MATCHED_DIR"
    return 0
  else
    echo "No Match." >&2
    return 1
  fi
}

# complete upto
_upto () {
  # necessary locals for _init_completion
  local cur prev words cword
  _init_completion || return

  COMPREPLY+=( $( compgen -W "$( echo ${PWD//\// } )" -- $cur ) )
}
complete -F _upto upto

function encrypt_file() {
  if [[ -n "$1" ]] && [[ -f "$1" ]]; then
    openssl enc -aes-256-cbc -md sha512 -pbkdf2 -iter 1024 -salt -in "$1" -out "$1.enc" && \
      [[ -f "$1.enc" ]] && \
      ls -l "$1.enc" && \
      rm -vi "$1"
  else
    echo "No file specified, or invalid/nonexistant file" >&2
  fi
}

function decrypt_file() {
  if [[ -n "$1" ]] && [[ -f "$1" ]]; then
    OUT_FILE="$(echo "$1" | sed "s/\.enc$//")"
    if [ "$1" = "$OUT_FILE" ]; then
      OUT_FILE="$1.dec"
    fi
    openssl enc -aes-256-cbc -md sha512 -pbkdf2 -iter 1024 -salt -d -in "$1" -out "$OUT_FILE" && \
      [[ -f "$OUT_FILE" ]] && \
      ls -l "$OUT_FILE" && \
      rm -vi "$1"
  else
    echo "No file specified, or invalid/nonexistant file" >&2
  fi
}

########################################################################
# history
########################################################################
function h() { if [ -z "$1" ]; then history; else history | grep -i "$@"; fi; }

########################################################################
# searching
########################################################################
function fname() { find . -iname "*$@*"; }

########################################################################
# examine running processes
########################################################################
function auxer() {
  ps aux | grep -i "$(echo "$1" | sed "s/^\(.\)\(.*$\)/\[\1\]\2/")"
}

function psgrep() {
  ps axuf | grep -v grep | grep "$@" -i --color=auto;
}

function killtree() {
  if [ "$1" ]
  then
    kill $(pstree -p $1 | sed 's/(/\n(/g' | grep '(' | sed 's/(\(.*\)).*/\1/' | tr "\n" " ")
  else
    echo "No PID specified">&2
  fi
}

function howmuchmem () {
  PROCNAME="$@";
  RAMKILOBYTES=($(ps axo rss,comm|grep $PROCNAME| awk '{ TOTAL += $1 } END { print TOTAL }'));
  RAMBYTES=$(echo "$RAMKILOBYTES*1024" | bc);
  RAM=$(fsize $RAMBYTES);
  echo "$RAM";
}

function mempercent () {
  PROCNAME="$@";
  ps -eo pmem,comm | grep "$PROCNAME" | awk '{sum+=$1} END {print sum " % of RAM"}'
}

function htopid () {
  PROCPID="$1"
  htop -p $(pstree -p $PROCPID | perl -ne 'push @t, /\((\d+)\)/g; END { print join ",", @t }')
}

function pidstart () {
  for PROC_PID in "$@"; do
    PROC_START_DATE_STR="$(ps -q $PROC_PID -o lstart=)"
    PROC_START_DATE_UNIX="$(date +%s -d "$PROC_START_DATE_STR")"
    NOW_DATE_UNIX="$(date +%s)"
    PROC_START_SECONDS_AGO=$((NOW_DATE_UNIX-PROC_START_DATE_UNIX))
    PROC_START_AGO="$(sec2dhms $PROC_START_SECONDS_AGO)"
    echo "$PROC_START_DATE_STR ($PROC_START_AGO ago)"
  done
}

########################################################################
# network
########################################################################
function lport () {
  if [ "$1" ]
  then
    netstat -anp 2>/dev/null|grep "$1"|grep LISTEN|awk '{print $4}'|grep -P -o "\d+"|grep -v "^0$"
  else
    echo "No process specified">&2
  fi
}

function arps()
{
  /usr/sbin/arp -a | grep -v '^?' | cols 4 1 | sed "s/ /|/" | sed "s/$/|/"
}

function portping()
{
  python <<<"import socket; socket.setdefaulttimeout(1); socket.socket().connect(('$1', $2))" 2> /dev/null && echo OPEN || echo CLOSED;
}

########################################################################
# APT package management
########################################################################
function aptsearch() { apt-cache search "$1"; }

function aptsize() {
  dpkg-query --show --showformat='${Package;-50}\t${Installed-Size} ${Status}\n' | sort -k 2 -n | grep -v deinstall
}

########################################################################
# system
########################################################################
function ddisousb() {
  if [ "$1" ] && [[ -r "$1" ]] ; then
    if [ "$2" ] && [[ -r "$2" ]] ; then
      DEV_DESC="$2 $(lsblk "$2" | sed -n 2p | awk '{ print $4 }') $(udevadm info --query=all -n "$2" | grep -P "(ID_VENDOR|ID_MODEL|ID_FS_LABEL|ID_BUS)=" | cols 2 | sed "s/.*=//" | tr '\n' ' ')"
      DEV_DESC="$(sed -e 's/[[:space:]]*$//' <<<${DEV_DESC})"
      read -p "This will overwrite $DEV_DESC, are you sure? " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "dd if=\"$1\" of=\"$2\" bs=4M status=progress oflag=sync"
        dd if="$1" of="$2" bs=4M status=progress oflag=sync
      fi
    else
      echo "No destination device specified">&2
    fi
  else
    echo "No iso file specified">&2
  fi
}

function find_linux_root_device() {
  local PDEVICE=`stat -c %04D /`
  for file in $(find /dev -type b 2>/dev/null) ; do
    local CURRENT_DEVICE=$(stat -c "%02t%02T" $file)
    if [ $CURRENT_DEVICE = $PDEVICE ]; then
      ROOTDEVICE="$file"
      break;
    fi
  done
  echo "$ROOTDEVICE"
}

function rotationals() {
  for f in /sys/block/sd?/queue/rotational; do printf "$f is "; cat $f; done
}

function schedulers() {
  for f in /sys/block/sd?/queue/scheduler; do printf "$f is "; cat $f; done
}

function watch_file_size() {
  perl -e '
  $file = shift; die "no file [$file]" unless ((-f $file) || (-d $file));
  $isDir = (-d $file);
  $sleep = shift; $sleep = 1 unless $sleep =~ /^[0-9]+$/;
  $format = "%0.2f %0.2f\n";
  while(1){
    if ($isDir) {
      $size = `du -0scb $file`;
      $size =~ s/\s+.*//;
    } else {
      $size = ((stat($file))[7]);
    }
    $change = $size - $lastsize;
    printf $format, $size/1024/1024, $change/1024/1024/$sleep;
    sleep $sleep;
    $lastsize = $size;
  }' "$1" "$2"
}

function dux() {
  du -x --max-depth=1|sort -rn|awk -F / -v c=$COLUMNS 'NR==1{t=$1} NR>1{r=int($1/t*c+.5); b="\033[1;31m"; for (i=0; i<r; i++) b=b"#"; printf " %5.2f%% %s\033[0m %s\n", $1/t*100, b, $2}'|tac
}

function dirtydev() {
  while true; do cat /sys/block/$1/stat|cols 9; grep -P "(Dirty)\b" /proc/meminfo; sleep 1; done
}

function cpuuse() {
  if [ "$1" ]; then
    SLEEPSEC="$1"
  else
    SLEEPSEC=1
  fi
   { cat /proc/stat; sleep "$SLEEPSEC"; cat /proc/stat; } | \
      awk '/^cpu / {usr=$2-usr; sys=$4-sys; idle=$5-idle; iow=$6-iow} \
      END {total=usr+sys+idle+iow; printf "%.2f\n", (total-idle)*100/total}'
}

########################################################################
# misc. shell/tmux/etc
########################################################################
function tmux() {
  TMUX="$(which tmux)"

  # old habits die hard, make "screen -l" and "screen -r" work the way I want them to for tmux

  if [ "$#" -eq 1 ] && ([ "$1" = "-list" ] || [ "$1" = "-l" ]); then
    shift
    "$TMUX" ls

  elif ([ "$#" -eq 1 ] || [ "$#" -ge 2 ]) && [ "$1" = "-r" ]; then
    shift
    if [ "$#" -eq 0 ]; then
      "$TMUX" ls >/dev/null 2>&1 && "$TMUX" attach || echo "No tmux sessions found"
    else
      SID="$1"; shift
      "$TMUX" attach -t "$SID" "$@"
    fi

  else
    "$TMUX" "$@"
  fi
}

function screen() {
  tmux "$@"
}

########################################################################
# helper functions for docker
########################################################################
# run a new container and remove it when done
function drun() {
  docker run -t -i -P --rm \
    "$@"
}

# docker compose
alias dc="docker-compose"

# Get latest container ID
alias dl="docker ps -l -q"

# Get container process
alias dps="docker ps"

# Get process included stop container
alias dpa="docker ps -a"

# Get images
alias di="docker images | tail -n +2"
alias dis="docker images | tail -n +2 | cols 1 2 | sed \"s/ /:/\""

# Get container IP
alias dip="docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'"

# a slimmed-down stats
alias dstats="docker stats --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}'"

# Execute in existing interactive container, e.g., $dex base /bin/bash
alias dex="docker exec -i -t"

# backup *all* docker images!
function docker_backup() {
  for IMAGE in `dis`; do export FN=$(echo "$IMAGE" | sed -e 's/[^A-Za-z0-9._-]/_/g') ; docker save "$IMAGE" | pv | pigz > "$FN.tgz"  ; done
}

# pull updates for docker images
function dockup() {
  di | cols 1 2 | tr ' ' ':' | xargs -r -l docker pull
}

function dxl() {
  CONTAINER=$(docker ps -l -q)
  docker exec -i -t $CONTAINER "$@"
}

# list virtual networks
alias dnl="docker network ls"

# inspect virtual networks
alias dnins="docker network inspect $@"

# Stop all containers
function dstop() { docker stop $(docker ps -a -q); }

# list docker registry catalog
function dregls () {
  curl -k -X GET "https://"$1"/v2/_catalog"
}

########################################################################
# malcolm-specific
########################################################################
function malcolmmonitor () {
  if [[ -d "$HOME"/Malcolm ]]; then
    mkdir -p "$HOME"/Malcolm/.tmp
    export TMPDIR="$HOME"/Malcolm/.tmp
    MAX_WIDTH=$(tput cols)
    MAX_HEIGHT=$(tput lines)
    /usr/bin/tmux new-session \; \
      split-window -h \; \
      select-pane -t 1 \; \
      split-window -v \; \
      select-pane -t 2 \; \
      split-window -h \; \
      select-pane -t 2 \; \
      split-window -v \; \
      select-pane -t 5 \; \
      split-window -v \; \
      split-window -v \; \
      select-pane -t 1 \; \
      send-keys '~/Malcolm/scripts/logs' C-m \; \
      select-pane -t 2 \; \
      send-keys 'dstats' C-m \; \
      select-pane -t 3 \; \
      send-keys 'while true; do clear; df -h ~/Malcolm/; sleep 60; done' C-m \; \
      select-pane -t 4 \; \
      send-keys 'top' C-m \; \
      split-window -v \; \
      select-pane -t 5 \; \
      send-keys 'while true; do clear; free -m | head -n 2; sleep 60; done' C-m \; \
      select-pane -t 6 \; \
      send-keys "while true; do clear; pushd ~/Malcolm >/dev/null 2>&1; docker-compose exec -u $(id -u) api curl -sSL 'http://localhost:5000/mapi/agg/event.dataset?from=1970' | python3 -m json.tool | grep -P '\b(doc_count|key)\b' | tr -d '\", ' | cut -d: -f2 | paste - - -d'\t\t' | head -n $(( (MAX_HEIGHT / 2) - 1 )) ; popd >/dev/null 2>&1; sleep 60; done" C-m \; \
      select-pane -t 7 \; \
      send-keys "while true; do clear; pushd ~/Malcolm >/dev/null 2>&1; docker-compose exec -u $(id -u) api curl -sSL 'http://localhost:5000/mapi/agg?from=1970' | python3 -m json.tool | grep -P '\b(doc_count|key)\b' | tr -d '\", ' | cut -d: -f2 | paste - - -d'\t\t' ; popd >/dev/null 2>&1; sleep 60; done" C-m \; \
      split-window -v \; \
      select-pane -t 8 \; \
      send-keys "while true; do clear; find ~/Malcolm/zeek-logs/extract_files -type f | sed 's@.*/\(.*\)/.*@\1@' | sort | uniq -c | sort -nr; sleep 60; done" C-m \; \
      select-pane -t 9 \; \
      send-keys "while true; do clear; find ~/Malcolm/zeek-logs/extract_files -type f | sed 's@.*/@@' | sed 's/.*\.//' | sort | uniq -c | sort -nr | head -n $(( (MAX_HEIGHT / 3) - 1 )) ; sleep 60; done" C-m \; \
      select-pane -t 9 \; \
      resize-pane -R $(( ($MAX_WIDTH / 2) - 30 )) \; \
      select-pane -t 3 \; \
      resize-pane -D $(( ($MAX_HEIGHT / 4) - 4 )) \; \
      select-pane -t 5 \; \
      resize-pane -D $(( ($MAX_HEIGHT / 4) - 4 )) \; \
      select-pane -t 7 \; \
      resize-pane -U $(( ($MAX_HEIGHT / 8) - 4 )) \; \
      select-pane -t 8 \; \
      resize-pane -U $(( ($MAX_HEIGHT / 8) - 1 )) \; \
      select-pane -t 4 \;
  fi
}
