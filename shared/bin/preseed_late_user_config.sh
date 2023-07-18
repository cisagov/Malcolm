#!/bin/sh

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

##################################################################################
# prompt whether to autologin or not
# prompt whether or not to lock screen for the GUI session on inactivity
# prompt whether to use U.S. DoD login banner (https://www.stigviewer.com/stig/general_purpose_operating_system_srg/2015-06-26/finding/V-56585)
# prompt for disabling IPV6 or not

# this is a debconf-compatible script
. /usr/share/debconf/confmodule

# template for user prompt
cat > /tmp/malcolm.template <<'!EOF!'
Template: malcolm/autologin
Type: boolean
Default: true
Description:
 Automatically login to the GUI session?

Template: malcolm/autologin_title
Type: text
Description: Autologin?

Template: malcolm/xscreensaver_lock
Type: boolean
Default: false
Description:
 Should the GUI session be locked due to inactivity?

Template: malcolm/xscreensaver_title
Type: text
Description: Lock idle session?

Template: malcolm/dod_banner
Type: boolean
Default: false
Description:
 Display the Standard Mandatory DoD Notice and Consent Banner?

Template: malcolm/dod_banner_title
Type: text
Description: Use U.S. DoD login banner?

Template: malcolm/disable_ipv6
Type: boolean
Default: true
Description:
 Disable IPv6?

Template: malcolm/disable_ipv6_title
Type: text
Description: IPv6

Template: malcolm/ssh_password_auth
Type: boolean
Default: false
Description:
 Allow SSH password authentication?

Template: malcolm/ssh_password_auth_title
Type: text
Description: SSH Password Authentication
!EOF!

# load template
db_x_loadtemplatefile /tmp/malcolm.template malcolm

# set title
db_settitle malcolm/disable_ipv6_title

# prompt
db_input critical malcolm/disable_ipv6
db_go

# get answer to $RET
db_get malcolm/disable_ipv6

# store answer in /etc/sysctl.conf and /etc/default/grub
if [ "$RET" = false ]; then
  DISABLE_IPV6_VAL=0
else
  DISABLE_IPV6_VAL=1
fi

sed -i "s/\(disable_ipv6=\)[[:digit:]]\+/\1$DISABLE_IPV6_VAL/g" /etc/sysctl.conf 2>/dev/null || true
sed -i "s/\(ipv6\.disable=\)[[:digit:]]\+/\1$DISABLE_IPV6_VAL/g" /etc/default/grub 2>/dev/null || true

echo "malcolm/disable_ipv6=$RET" > /tmp/malcolm.answer

# set title
db_settitle malcolm/autologin_title

# prompt
db_input critical malcolm/autologin
db_go

# get answer to $RET
db_get malcolm/autologin

# store answer in /etc/lightdm/lightdm.conf for autologin
if [ -n $RET ] && [ -f /etc/lightdm/lightdm.conf ]; then
  MAIN_USER="$(id -nu 1000)"
  if [ -n $MAIN_USER ] && [ "$RET" = true ]; then
    sed -i "s/^#\(autologin-user=\).*/\1$MAIN_USER/" /etc/lightdm/lightdm.conf
    sed -i 's/^#\(autologin-user-timeout=\)/\1/' /etc/lightdm/lightdm.conf
  else
  	sed -i 's/^\(autologin-user=\)/#\1/' /etc/lightdm/lightdm.conf
  	sed -i 's/^\(autologin-user-timeout=\)/#\1/' /etc/lightdm/lightdm.conf
  fi
fi

echo "malcolm/autologin=$RET" >> /tmp/malcolm.answer

# set title
db_settitle malcolm/xscreensaver_title

# prompt
db_input critical malcolm/xscreensaver_lock
db_go

# get answer to $RET
db_get malcolm/xscreensaver_lock

# store places defaults can exist for screensaver lock
if [ -n $RET ]; then
  if [ "$RET" = false ]; then
    SCREEN_LOCK=false
    SCREEN_LOCK_INT=0
  else
    SCREEN_LOCK=true
    SCREEN_LOCK_INT=1
  fi

  sed -i "s/\(.*lock-screen-suspend-hibernate.*value=\"\).*\(\".*\)$/\1$SCREEN_LOCK\2/g" \
    /etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml 2>/dev/null || true
  sed -i "s/\(.*LockScreen.*value=\"\).*\(\".*\)$/\1$SCREEN_LOCK\2/g" \
    /etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml 2>/dev/null || true
  sed -i "s/\(lock-after-screensaver=\).*/\1uint32 $SCREEN_LOCK_INT/" \
    /etc/skel/.config/light-locker-dconf-defaults.conf 2>/dev/null || true
  sed -i "s/\(lock-on-suspend=\).*/\1$SCREEN_LOCK/" \
    /etc/skel/.config/light-locker-dconf-defaults.conf 2>/dev/null || true

  # at this point users have already been created, so we need to re-apply our changes there
  for HOMEDIR in $(getent passwd | cut -d: -f6); do
    [ -f /etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml ] && \
      [ -d "$HOMEDIR"/.config/xfce4/xfconf/xfce-perchannel-xml/ ] && \
      cp -f /etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml \
            "$HOMEDIR"/.config/xfce4/xfconf/xfce-perchannel-xml/

    [ -f /etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml ] && \
      [ -d "$HOMEDIR"/.config/xfce4/xfconf/xfce-perchannel-xml/ ] && \
      cp -f /etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml \
            "$HOMEDIR"/.config/xfce4/xfconf/xfce-perchannel-xml/

    [ -f /etc/skel/.config/light-locker-dconf-defaults.conf ] && \
      [ -d "$HOMEDIR"/.config/ ] && \
      cp -f /etc/skel/.config/light-locker-dconf-defaults.conf \
            "$HOMEDIR"/.config/
  done

fi

echo "malcolm/xscreensaver_lock=$RET" >> /tmp/malcolm.answer

# set title
db_settitle malcolm/dod_banner_title

# prompt
db_input critical malcolm/dod_banner
db_go

# get answer to $RET
db_get malcolm/dod_banner

if [ "$RET" = true ]; then
  # login banner
  OLD_ISSUE="$(grep ^Debian /etc/issue | sed -r "s@[[:space:]]\\\.*@@g")"
  cat << 'EOF' > /etc/issue
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

EOF
  /bin/echo -E "$OLD_ISSUE \n \l" >> /etc/issue
  echo >> /etc/issue

else
  rm -f /usr/local/bin/dod-login-banner.sh
fi

echo "malcolm/dod_banner=$RET" >> /tmp/malcolm.answer

# set title
db_settitle malcolm/ssh_password_auth_title

# prompt
db_input critical malcolm/ssh_password_auth
db_go

# get answer to $RET
db_get malcolm/ssh_password_auth

if [ "$RET" = true ]; then
  SSH_PASSWORD_AUTH="yes"
else
  SSH_PASSWORD_AUTH="no"
fi

sed -i "s/^[[:space:]]*#*[[:space:]]*PasswordAuthentication[[:space:]][[:space:]]*[[:alpha:]][[:alpha:]]*[[:space:]]*$/PasswordAuthentication $SSH_PASSWORD_AUTH/g" /etc/ssh/sshd_config 2>/dev/null || true

echo "malcolm/ssh_password_auth=$RET" >> /tmp/malcolm.answer