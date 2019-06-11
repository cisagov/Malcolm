# some more ls aliases

#safety
alias mv='mv -i'
alias rm='rm -I -v'
alias cp='cp -i'
alias chmod='chmod --preserve-root'
alias chown='chown --preserve-root'

#convenience
alias ls="ls --block-size=\"'1\" --color=auto --group-directories-first"
alias la='ls -A'
alias l='ls -oah'
alias ll='ls -l --si --color=auto --group-directories-first'
alias lt='ls -ltr'
alias lld='ls -lUd */'
alias lsize='ls -lSrh'
alias df='df -Th'
alias ln='ln -s'
alias ..='cd ..'
alias cd..='cd ..'
alias cd-='cd -'
alias cdp='cd -P'
alias dump='hexdump -C'
alias findbroken='find . -type l ! -exec test -r {} \; -print'
alias utime='date +%s'
alias dutop='du -csh ./* 2>/dev/null | sort -rh'
alias mountcol='mount | column -t'
alias dmesg='dmesg -wHx'
