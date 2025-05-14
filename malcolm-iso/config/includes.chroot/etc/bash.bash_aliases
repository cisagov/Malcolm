# some more ls aliases

#safety
alias mv='mv -i'
alias rm='rm -I -v'
alias cp='cp -i'
alias chmod='chmod --preserve-root'
alias chown='chown --preserve-root'

#convenience
alias eza="eza --binary --color auto --group-directories-first --hyperlink --icons auto --mounts --no-permissions --octal-permissions --time-style long-iso"
alias e="eza --all --long"
alias ea="eza --all"
alias el="eza --long"
alias eld="eza --all --long --only-dirs --sort name"
alias esize="eza --long --sort size"
alias et="eza --long --sort modified"
alias etree="eza --tree"
alias la=ea
alias l=e
alias ll=el
alias lt=et
alias lsize=esize
alias lld=eld
alias ls="ls --block-size=\"'1\" --color=auto --group-directories-first"
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
alias x='xargs -r -l'
alias rg="rg --no-ignore --hidden --smart-case"
alias rgfile="cut -d: -f1 | sort -u"
alias fd="fdfind --no-ignore --hidden --ignore-case"
alias ct='\cat'
alias cat='batcat --paging=never --style=plain,header --tabs 0'