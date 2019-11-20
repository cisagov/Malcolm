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

function lport () {
  if [ "$1" ]
  then
    netstat -anp 2>/dev/null|grep "$1"|grep LISTEN|awk '{print $4}'|grep -P -o "\d+"|grep -v "^0$"
  else
    echo "No process specified">&2
  fi
}

########################################################################
# APT package management
########################################################################
function aptsearch() { apt-cache search "$1"; }

function aptsize() {
  dpkg-query --show --showformat='${Package;-50}\t${Installed-Size} ${Status}\n' | sort -k 2 -n | grep -v deinstall
}

########################################################################
# date/time
########################################################################
function dateu()
{
  if [ "$1" ]
  then
    echo $(date -u -d @$1);
  else
    echo "No UNIX time specified">&2
  fi
}

function udate()
{
  if [ "$1" ]
  then
    date -u +%s -d "$1"
  else
    date -u +%s
  fi
}

function sec2dhms() {
  declare -i SS="$1" D=$(( SS / 86400 )) H=$(( SS % 86400 / 3600 )) M=$(( SS % 3600 / 60 )) S=$(( SS % 60 )) [ "$D" -gt 0 ] && echo -n "${D}:" [ "$H" -gt 0 ] && printf "%02g:" "$H" printf "%02g:%02g\n" "$M" "$S"
}

########################################################################
# system
########################################################################
function ddisousb() {
  if [ "$1" ] && [[ -r "$1" ]] ; then
    if [ "$2" ] && [[ -r "$2" ]] ; then
      echo "dd if=\"$1\" of=\"$2\" bs=4M status=progress oflag=sync"
      dd if="$1" of="$2" bs=4M status=progress oflag=sync
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
