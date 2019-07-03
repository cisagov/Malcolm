#!/bin/sh

##################################################################################
# prompt whether to autologin or not
# prompt whether or not to lock xscreensaver for the sensor GUI session

# this is a debconf-compatible script
. /usr/share/debconf/confmodule

# template for user prompt
cat > /tmp/hedgehog.template <<'!EOF!'
Template: hedgehog/autologin
Type: boolean
Default: true
Description:
 Should the sensor user open a GUI session automatically?

Template: hedgehog/autologin_title
Type: text
Description: Autologin?

Template: hedgehog/xscreensaver_lock
Type: boolean
Default: false
Description:
 Should the GUI session be locked due to inactivity?

Template: hedgehog/xscreensaver_title
Type: text
Description: Lock idle session?
!EOF!

# load template
db_x_loadtemplatefile /tmp/hedgehog.template hedgehog


# set title
db_settitle hedgehog/autologin_title

# prompt
db_input critical hedgehog/autologin
db_go

# get answer to $RET
db_get hedgehog/autologin

# store answer in /etc/lightdm/lightdm.conf for autologin
if [ -n $RET ] && [ -f /etc/lightdm/lightdm.conf ]; then
  if [ "$RET" = true ]; then
    sed -i 's/^#\(autologin-user=\)/\1/' /etc/lightdm/lightdm.conf
    sed -i 's/^#\(autologin-user-timeout=\)/\1/' /etc/lightdm/lightdm.conf
  else
  	sed -i 's/^\(autologin-user=\)/#\1/' /etc/lightdm/lightdm.conf
  	sed -i 's/^\(autologin-user-timeout=\)/#\1/' /etc/lightdm/lightdm.conf
  fi
fi

echo "hedgehog/autologin=$RET" > /tmp/hedgehog.answer

# set title
db_settitle hedgehog/xscreensaver_title

# prompt
db_input critical hedgehog/xscreensaver_lock
db_go

# get answer to $RET
db_get hedgehog/xscreensaver_lock

# store answer in .Xresources/.xscreensaver for xscreensaver.lock:
if [ -n $RET ]; then
  [ -f /etc/skel/.Xresources ] && sed -i "s/^\(xscreensaver.lock:\).*$/\1 $RET/" /etc/skel/.Xresources
  URET="$(echo "$RET" | sed -r 's/\<./\U&/')"
  [ -f /etc/skel/.xscreensaver ] && sed -i "s/^\(lock:\).*$/\1		$URET/" /etc/skel/.xscreensaver
fi

echo "hedgehog/xscreensaver_lock=$RET" >> /tmp/hedgehog.answer
