# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# new directories default to 700, new files to 600
umask 077
export UMASK=077

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# don't put duplicate lines in the history and ignore same sucessive entries.
export HISTCONTROL=ignoreboth:erasedups
export HISTIGNORE="&:ls:ll:cd:history:h:[bf]g:exit:pwd:clear"
export HISTFILESIZE=1000000000
export HISTSIZE=1000000
export HISTTIMEFORMAT="[%Y-%m-%d %H:%M:%S] "

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(lesspipe)"

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
  PROMPT_COMMAND='echo -ne "\033]0;${USER}@${HOSTNAME}: ${PWD/$HOME/~}\007"'
  ;;
*)
  ;;
esac

# enable programmable completion features
if [ -f /etc/bash_completion ]; then
  . /etc/bash_completion
fi

###############################################################################
# PATH
###############################################################################
PATH=/opt/zeek/bin:opt/arkime/bin:/opt/fluent-bit/bin:/usr/sbin:$PATH

if [ -d ~/bin ]; then
  PATH=~/bin:$PATH
fi

if [ -d ~/.local/bin ]; then
  PATH=~/.local/bin:$PATH
fi

export PATH

###############################################################################
# ALIASES AND FUNCTIONS
###############################################################################
if [ -f /etc/bash.bash_aliases ]; then
  . /etc/bash.bash_aliases
fi

if [ -f /etc/bash.bash_functions ]; then
  . /etc/bash.bash_functions
fi

if [ -f ~/.bash_aliases ]; then
  . ~/.bash_aliases
fi

if [ -f ~/.bash_functions ]; then
  . ~/.bash_functions
fi

###############################################################################
# BASH OPTIONS
###############################################################################
shopt -s extglob
shopt -s dotglob
shopt -s cdspell
shopt -s histverify
shopt -s histappend
shopt -u progcomp
PROMPT_COMMAND="history -a;$PROMPT_COMMAND"

###############################################################################
# BASH PROMPT
###############################################################################
PS1="\[\033[00;32m\]\u\[\033[00;34m\]@\h\[\033[1;30m\]:\[\033[00;35m\]\W\[\033[00m\]\[\033[01;37m\]\$ \[\033[00;37m\]"
