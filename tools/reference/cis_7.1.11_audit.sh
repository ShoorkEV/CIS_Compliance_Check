#!/usr/bin/env bash
# CIS Ubuntu 26.04 L1 – 7.1.11 Ensure world writable files and directories are secured (Audit)
{
   a_file=(); a_dir=()
   l_smask='01000'
   l_exclude="nfs|proc|cifs|smb|vfat|iso9660|efivarfs|selinuxfs|ncpfs"
   l_exclude2="\/run|\/tmp|\/var\/tmp"
   a_path=(-path "*/containers/storage/*" -o -path "*/containerd/*" -o -path "*/kubelet/*" \
           -o -path "/sys/*" -o -path "/snap/*" -o -path "/boot/efi/*")

   while IFS= read -r l_mount; do
      while IFS= read -r -d $'\0' l_file; do
         if [ -e "$l_file" ]; then
            [ -f "$l_file" ] && a_file+=("$l_file")
            if [ -d "$l_file" ]; then
               l_mode="$(stat -Lc '%#a' "$l_file")"
               [ ! $(( l_mode & l_smask )) -gt 0 ] && a_dir+=("$l_file")
            fi
         fi
      done < <(find "$l_mount" -mount -xdev \( "${a_path[@]}" \) \
                 -prune -o \( -type f -o -type d \) -perm -0002 -print0 2>/dev/null)
   done < <(findmnt -Dkerno fstype,target | \
            awk '($1 !~ /^\s*('"$l_exclude"')/ && $2 !~ /^('"$l_exclude2"')(\/|$)/){print $2}')

   if [ "${#a_file[@]}" -le 0 ]; then
      printf '%s\n' "" " - No world writable files exist on the local filesystem."
   else
      printf '%s\n' "" " - There are \"${#a_file[@]}\" World writable files on the system." \
         " - The following is a list of World writable files:" \
         "${a_file[@]}" " - end of list"
   fi

   if [ "${#a_dir[@]}" -le 0 ]; then
      printf '%s\n' "" " - Sticky bit is set on world writable directories on the local filesystem."
   else
      printf '%s\n' "" " - There are \"${#a_dir[@]}\" World writable directories without the sticky bit on the system." \
         " - The following is a list of World writable directories without the sticky bit:" \
         "${a_dir[@]}" " - end of list"
   fi
}
