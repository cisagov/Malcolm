#!/bin/sh

##################################################################################
# prompt whether to autologin or not
# prompt whether or not to lock xscreensaver for the sensor GUI session
# prompt whether to use U.S. DoD login banner (https://www.stigviewer.com/stig/general_purpose_operating_system_srg/2015-06-26/finding/V-56585)

# this is a debconf-compatible script
. /usr/share/debconf/confmodule

# template for user prompt
cat > /tmp/malcolm.template <<'!EOF!'
Template: malcolm/autologin
Type: boolean
Default: true
Description:
 Should the sensor user open a GUI session automatically?

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
!EOF!

# load template
db_x_loadtemplatefile /tmp/malcolm.template malcolm

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

echo "malcolm/autologin=$RET" > /tmp/malcolm.answer

# set title
db_settitle malcolm/xscreensaver_title

# prompt
db_input critical malcolm/xscreensaver_lock
db_go

# get answer to $RET
db_get malcolm/xscreensaver_lock

# store places defaults can exist for xscreensaver lock
if [ -n $RET ]; then
  URET="$(echo "$RET" | sed -r 's/\<./\U&/')"
  sed -i "s/^\(xscreensaver.lock:\).*$/\1 $RET/g" /etc/skel/.Xresources 2>/dev/null || true
  sed -i "s/^\(lock:\).*$/\1		$URET/g" /etc/skel/.xscreensaver 2>/dev/null  || true
  sed -i "s/^\(\*lock:\).*$/\1			$URET/g" /etc/X11/app-defaults/XScreenSaver* 2>/dev/null || true
  # at this point users have already been created, so we need to re-apply our changes there
  for HOMEDIR in $(getent passwd | cut -d: -f6); do
    [ -f /etc/skel/.Xresources ] && [ -f "$HOMEDIR"/.Xresources ] && cp -f /etc/skel/.Xresources "$HOMEDIR"/.Xresources
    [ -f /etc/skel/.xscreensaver ] && [ -f "$HOMEDIR"/.xscreensaver ] && cp -f /etc/skel/.xscreensaver "$HOMEDIR"/.xscreensaver
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
  if [ -f /usr/local/bin/dod-login-banner.sh ]; then
    [ -f /etc/xdg/lxsession/LXDE/autostart ] && echo "@/usr/local/bin/dod-login-banner.sh" >> /etc/xdg/lxsession/LXDE/autostart
    for HOMEDIR in $(getent passwd | cut -d: -f6); do
      [ -f "$HOMEDIR"/.config/lxsession/LXDE/autostart ] && echo "@/usr/local/bin/dod-login-banner.sh" >> "$HOMEDIR"/.config/lxsession/LXDE/autostart
    done
  fi

else
  rm -f /usr/local/bin/dod-login-banner.sh
fi

echo "malcolm/dod_banner=$RET" >> /tmp/malcolm.answer
