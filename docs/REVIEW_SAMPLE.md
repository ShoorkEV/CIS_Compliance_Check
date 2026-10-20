# Sample of catalog rows for the owner review (milestone M1)

The plan asks the owner to review a sample of 30 catalog rows against the benchmark PDF. This sample covers every check type. For each row compare the parameters with the PDF's Audit section (use `python3 tools/rem.py recs.json bench.txt Audit <id>`).

| ID | Check | Parameters | Applies if | Slow |
| --- | --- | --- | --- | --- |
| 1.2.1.12 Ensure AllowInsecureRepositories is configured | apt_config | `key=Acquire::AllowInsecureRepositories;value=0;accept=0,false,no` |  |  |
| 1.2.1.14 Ensure AllowDowngradeToInsecureRepositories is configured | apt_config | `key=Acquire::AllowDowngradeToInsecureRepositories;value=0;accept=0,false,no` |  |  |
| 1.5.11 Ensure systemd-coredump ProcessSizeMax is configured | conf_kv | `src=catcfg:systemd/coredump.conf;section=Coredump;key=ProcessSizeMax;op=eq;value=0;absent=default` | HAS_COREDUMP=1 |  |
| 5.3.3.2.1 Ensure password number of changed characters is configured | conf_kv | `src=files:/etc/security/pwquality.conf.d/*.conf,/etc/security/pwquality.conf;pam_file=common-password;pam_mod=pam_pwquality.so;pam_type=password;key=difok;op=ge;value=@PWQ_DIFOK:2;absent=fail` |  |  |
| 5.3.3.2.7 Ensure password quality checking is enforced | conf_kv | `src=files:/etc/security/pwquality.conf.d/*.conf,/etc/security/pwquality.conf;pam_file=common-password;pam_mod=pam_pwquality.so;pam_type=password;key=enforcing;op=ne;value=0;absent=pass` |  |  |
| 1.2.1.3 Ensure access to gpg key files are configured | custom | `-` |  |  |
| 4.1.3 Ensure ufw incoming default is configured | custom | `-` |  |  |
| 5.4.2.8 Ensure accounts without a valid login shell are locked | custom | `-` |  |  |
| 1.2.1.4 Ensure access to /etc/apt/trusted.gpg.d directory is configured | file_perm | `path=/etc/apt/trusted.gpg.d;mode=755;owner=root;group=root;missing=fail` |  |  |
| 1.6.10 Ensure access to sshd warning banner is configured | file_perm | `dyn=sshd_banner;mode=644;owner=root;group=root;missing=pass` |  |  |
| 5.1.2 Ensure access to /etc/ssh/sshd_config.d/ directory is configured | file_perm | `path=/etc/ssh/sshd_config.d;mode=700;owner=root;group=root;missing=fail` |  |  |
| 1.2.1.6 Ensure access to files in the /etc/apt/auth.conf.d/ directory is configured | file_perm_glob | `dir=/etc/apt/auth.conf.d;pattern=*;mode=640;owner=root;group=root;missing=pass` |  |  |
| 5.1.3 Ensure access to SSH private host key files is configured | file_perm_glob | `source=sshd_hostkey;mode=600;owner=root;group=root` |  |  |
| 1.7.1 Ensure GDM login banner is configured | gdm | `key=gdm_1` | HAS_GDM=1 |  |
| 1.7.4 Ensure GDM automount is configured | gdm | `key=gdm_4` | HAS_GDM=1 |  |
| 1.1.1.1 Ensure cramfs kernel module is not available | kmod_unavailable | `name=cramfs;dir=fs/cramfs` |  |  |
| 1.1.1.10 Ensure usb-storage kernel module is not available | kmod_unavailable | `name=usb_storage;dir=drivers/usb/storage` |  |  |
| 1.1.1.11 Ensure unused filesystems kernel modules are not available | manual | `hint=Review the filesystem kernel modules available, loaded and mounted on this host and confirm every unused one is blacklisted and set to /bin/false or /bin/true; disabling a module in use can be fatal` |  |  |
| 5.3.3.2.3 Ensure password complexity is configured | manual | `hint=Confirm minclass and the dcredit/ucredit/lcredit/ocredit settings (none greater than 0) follow site policy and are not overridden on the pam_pwquality line` |  |  |
| 1.1.2.1.2 Ensure nodev option set on /tmp partition | mount_opt | `path=/tmp;opt=nodev` |  |  |
| 1.1.2.3.2 Ensure nodev option set on /home partition | mount_opt | `path=/home;opt=nodev` |  |  |
| 1.1.2.5.4 Ensure noexec option set on /var/tmp partition | mount_opt | `path=/var/tmp;opt=noexec` |  |  |
| 1.1.2.1.1 Ensure /tmp is tmpfs or a separate partition | mount_tmpfs_or_separate | `path=/tmp;unit=tmp.mount` |  |  |
| 1.1.2.2.1 Ensure /dev/shm is tmpfs or a separate partition | mount_tmpfs_or_separate | `path=/dev/shm` |  |  |
| 5.3.2.1 Ensure pam_unix module is enabled | pam_module | `mode=present_all;module=pam_unix.so;files=common-account,common-auth,common-password,common-session,common-session-noninteractive` |  |  |
| 5.3.3.3.2 Ensure password history is enforced for the root user | pam_module | `mode=conf_or_arg;module=pam_pwhistory.so;conf=/etc/security/pwhistory.conf;key=enforce_for_root;op=flag` |  |  |
| 1.5.6 Ensure prelink is not installed | pkg_absent | `pkgs=prelink` |  |  |
| 2.2.3 Ensure talk client is not installed | pkg_absent | `pkgs=talk` |  |  |
| 1.3.1.1 Ensure apparmor packages are installed | pkg_installed | `pkgs=apparmor,apparmor-utils` |  |  |
| 5.3.1.2 Ensure latest version of libpam-modules is installed | pkg_installed | `pkgs=libpam-modules;latest=1` |  |  |
