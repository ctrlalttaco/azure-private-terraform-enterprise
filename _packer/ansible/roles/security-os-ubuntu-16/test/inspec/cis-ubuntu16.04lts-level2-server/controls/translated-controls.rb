control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.1_Ensure_mounting_of_cramfs_filesystems_is_disabled" do
  title "Ensure mounting of cramfs filesystems is disabled"
  desc  "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the server. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v cramfs").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^cramfs\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.2_Ensure_mounting_of_freevxfs_filesystems_is_disabled" do
  title "Ensure mounting of freevxfs filesystems is disabled"
  desc  "The freevxfs filesystem type is a free version of the Veritas type filesystem. This is the primary filesystem type for HP-UX operating systems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v freevxfs").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^freevxfs\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.3_Ensure_mounting_of_jffs2_filesystems_is_disabled" do
  title "Ensure mounting of jffs2 filesystems is disabled"
  desc  "The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured filesystem used in flash memory devices.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v jffs2").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^jffs2\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.4_Ensure_mounting_of_hfs_filesystems_is_disabled" do
  title "Ensure mounting of hfs filesystems is disabled"
  desc  "The hfs filesystem type is a hierarchical filesystem that allows you to mount Mac OS filesystems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v hfs").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^hfs\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.5_Ensure_mounting_of_hfsplus_filesystems_is_disabled" do
  title "Ensure mounting of hfsplus filesystems is disabled"
  desc  "The hfsplus filesystem type is a hierarchical filesystem designed to replace hfs that allows you to mount Mac OS filesystems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v hfsplus").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^hfsplus\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.6_Ensure_mounting_of_squashfs_filesystems_is_disabled" do
  title "Ensure mounting of squashfs filesystems is disabled"
  desc  "The squashfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems (similar to cramfs). A squashfs image can be used without having to first decompress the image.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v squashfs").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^squashfs\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.7_Ensure_mounting_of_udf_filesystems_is_disabled" do
  title "Ensure mounting of udf filesystems is disabled"
  desc  "The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer optical disc formats.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v udf").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^udf\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.8_Ensure_mounting_of_FAT_filesystems_is_disabled" do
  title "Ensure mounting of FAT filesystems is disabled"
  desc  "The FAT filesystem format is primarily used on older windows systems and portable USB drives or flash modules. It comes in three types FAT12, FAT16, and FAT32 all of which are supported by the vfat kernel module.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v vfat").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^vfat\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.2_Ensure_separate_partition_exists_for_tmp" do
  title "Ensure separate partition exists for /tmp"
  desc  "The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n\nRationale: Since the /tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /tmp its own file system allows an administrator to set the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.3_Ensure_nodev_option_set_on_tmp_partition" do
  title "Ensure nodev option set on /tmp partition"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /tmp."
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.4_Ensure_nosuid_option_set_on_tmp_partition" do
  title "Ensure nosuid option set on /tmp partition"
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /tmp."
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "nosuid" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.5_Ensure_separate_partition_exists_for_var" do
  title "Ensure separate partition exists for /var"
  desc  "The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.\n\nRationale: Since the /var directory may contain world-writable files and directories, there is a risk of resource exhaustion if it is not bound to a separate partition."
  impact 1.0
  describe mount("/var") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.6_Ensure_separate_partition_exists_for_vartmp" do
  title "Ensure separate partition exists for /var/tmp"
  desc  "The /var/tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n\nRationale: Since the /var/tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /var/tmp its own file system allows an administrator to set the noexec option on the mount, making /var/tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.7_Ensure_nodev_option_set_on_vartmp_partition" do
  title "Ensure nodev option set on /var/tmp partition"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /var/tmp."
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
  describe mount("/var/tmp") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.8_Ensure_nosuid_option_set_on_vartmp_partition" do
  title "Ensure nosuid option set on /var/tmp partition"
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /var/tmp."
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
  describe mount("/var/tmp") do
    its("options") { should include "nosuid" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.9_Ensure_noexec_option_set_on_vartmp_partition" do
  title "Ensure noexec option set on /var/tmp partition"
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /var/tmp."
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
  describe mount("/var/tmp") do
    its("options") { should include "noexec" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.10_Ensure_separate_partition_exists_for_varlog" do
  title "Ensure separate partition exists for /var/log"
  desc  "The /var/log directory is used by system services to store log data .\n\nRationale: There are two important reasons to ensure that system logs are stored on a separate partition: protection against resource exhaustion (since logs can grow quite large) and protection of audit data."
  impact 1.0
  describe mount("/var/log") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.11_Ensure_separate_partition_exists_for_varlogaudit" do
  title "Ensure separate partition exists for /var/log/audit"
  desc  "The auditing daemon, auditd, stores log data in the /var/log/audit directory.\n\nRationale: There are two important reasons to ensure that data gathered by auditd is stored on a separate partition: protection against resource exhaustion (since the audit.log file can grow quite large) and protection of audit data. The audit daemon calculates how much free space is left and performs actions based on the results. If other processes (such as syslog) consume space in the same partition as auditd, it may not perform as desired."
  impact 1.0
  describe mount("/var/log/audit") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.12_Ensure_separate_partition_exists_for_home" do
  title "Ensure separate partition exists for /home"
  desc  "The /home directory is used to support disk storage needs of local users.\n\nRationale: If the system is intended to support local users, create a separate partition for the /home directory to protect against resource exhaustion and restrict the type of files that can be stored under /home."
  impact 1.0
  describe mount("/home") do
    it { should be_mounted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.13_Ensure_nodev_option_set_on_home_partition" do
  title "Ensure nodev option set on /home partition"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the user partitions are not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices."
  impact 1.0
  describe mount("/home") do
    it { should be_mounted }
  end
  describe mount("/home") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.14_Ensure_nodev_option_set_on_devshm_partitiov" do
  title "Ensure nodev option set on /dev/shm partitiov"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /run/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /dev/shm partitions."
  impact 1.0
  describe mount("/dev/shm") do
    it { should be_mounted }
  end
  describe mount("/dev/shm") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.15_Ensure_nosuid_option_set_on_devshm_partitionrun" do
  title "Ensure nosuid option set on /dev/shm partitionrun"
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them."
  impact 1.0
  describe mount("/dev/shm") do
    it { should be_mounted }
  end
  describe mount("/dev/shm") do
    its("options") { should include "nosuid" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.16_Ensure_noexec_option_set_on_devshm_partition" do
  title "Ensure noexec option set on /dev/shm partition"
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system."
  impact 1.0
  describe mount("/dev/shm") do
    it { should be_mounted }
  end
  describe mount("/dev/shm") do
    its("options") { should include "noexec" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.17_Ensure_nodev_option_set_on_removable_media_partitions" do
  title "Ensure nodev option set on removable media partitions"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Removable media containing character and block special devices could be used to circumvent security controls by allowing non-root users to access sensitive device files such as /dev/kmem or the raw disk partitions."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.18_Ensure_nosuid_option_set_on_removable_media_partitions" do
  title "Ensure nosuid option set on removable media partitions"
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.19_Ensure_noexec_option_set_on_removable_media_partitions" do
  title "Ensure noexec option set on removable media partitions"
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Setting this option on a file system prevents users from executing programs from the removable media. This deters users from being able to introduce potentially malicious software on the system."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.20_Ensure_sticky_bit_is_set_on_all_world-writable_directories" do
  title "Ensure sticky bit is set on all world-writable directories"
  desc  "Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.\n\nRationale: This feature prevents the ability to delete or rename files in world writable directories (such as /tmp) that are owned by another user."
  impact 1.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.21_Disable_Automounting" do
  title "Disable Automounting"
  desc  "autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.\n\nRationale: With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in system even if they lacked permissions to mount it themselves."
  impact 1.0
  a = command("systemctl is-enabled autofs.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.1_Ensure_package_manager_repositories_are_configured" do
  title "Ensure package manager repositories are configured"
  desc  "Systems need to have package manager repositories configured to ensure they receive the latest patches and updates.\n\nRationale: If a system's package repositories are misconfigured important patches may not be identified or a rogue repository could introduce compromised software."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.2_Ensure_GPG_keys_are_configured" do
  title "Ensure GPG keys are configured"
  desc  "Most packages managers implement GPG key signing to verify package integrity during installation.\n\nRationale: It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.3.1_Ensure_AIDE_is_installed" do
  title "Ensure AIDE is installed"
  desc  "AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes which can then be used to compare against the current state of the filesystem to detect modifications to the system.\n\nRationale: By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries."
  impact 1.0
  describe package("aide") do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.3.2_Ensure_filesystem_integrity_is_regularly_checked" do
  title "Ensure filesystem integrity is regularly checked"
  desc  "Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.\n\nRationale: Periodic file checking allows the system administrator to determine on a regular basis if critical files have been changed in an unauthorized fashion."
  impact 1.0
  describe.one do
    describe file("/var/spool/cron/crontabs/root") do
      its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
    end
    describe file("/etc/crontab") do
      its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
    end
    command("find /etc/cron.d -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
    command("find /etc/cron.hourly -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
    command("find /etc/cron.daily -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
    command("find /etc/cron.weekly -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
    command("find /etc/cron.monthly -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.4.1_Ensure_permissions_on_bootloader_config_are_configured" do
  title "Ensure permissions on bootloader config are configured"
  desc  "The grub configuration file contains information on boot settings and passwords for unlocking boot options. The grub configuration is usually grub.cfg stored in /boot/grub.\n\nRationale: Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them."
  impact 1.0
  describe file("/boot/grub/grub.cfg") do
    it { should exist }
  end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_executable.by "group" }
  end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_readable.by "group" }
  end
  describe file("/boot/grub/grub.cfg") do
    its("gid") { should cmp 0 }
  end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_writable.by "group" }
  end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_executable.by "other" }
  end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_readable.by "other" }
  end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_writable.by "other" }
  end
  describe file("/boot/grub/grub.cfg") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.4.2_Ensure_bootloader_password_is_set" do
  title "Ensure bootloader password is set"
  desc  "Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters\n\nRationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time)."
  impact 1.0
  describe.one do
    describe file("/boot/grub/grub.cfg") do
      its("content") { should match(/^\s*set\s+superusers\s*=\s*"[^"]*"\s*(\s+#.*)?$/) }
    end
    describe file("/boot/grub/grub.cfg") do
      its("content") { should match(/^\s*password_pbkdf2\s+\S+\s+\S+\s*(\s+#.*)?$/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.4.3_Ensure_authentication_required_for_single_user_mode" do
  title "Ensure authentication required for single user mode"
  desc  "Single user mode is used for recovery when the system detects an issue during boot or by manual selection from the bootloader.\n\nRationale: Requiring authentication in single user mode prevents an unauthorized user from rebooting the system into single user to gain root privileges without credentials."
  impact 1.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.4.4_Ensure_interactive_boot_is_not_enabled" do
  title "Ensure interactive boot is not enabled"
  desc  "Interactive boot allows console users to interactively select which services start on boot. Not all distributions support this capability.\n                 The PROMPT_FOR_CONFIRM option provides console users the ability to interactively boot the system and select which services to start on boot .\n\nRationale: Turn off the PROMPT\n                   _FOR_CONFIRM option on the console to prevent console users from potentially overriding established security settings."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.1_Ensure_core_dumps_are_restricted" do
  title "Ensure core dumps are restricted"
  desc  "A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.\n\nRationale: Setting a hard limit on core dumps prevents users from overriding the soft variable. If core dumps are required, consider setting limits for user groups (see limits.conf(5)). In addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core."
  impact 1.0
  describe.one do
    describe file("/etc/security/limits.conf") do
      its("content") { should match(/^\s*\*\s+hard\s+core\s+0\s*(\s+#.*)?$/) }
    end
    command("find /etc/security/limits.d -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\s*\*\s+hard\s+core\s+0\s*(\s+#.*)?$/) }
      end
    end
  end
  describe kernel_parameter("fs.suid_dumpable") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("fs.suid_dumpable") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.2_Ensure_XDNX_support_is_enabled" do
  title "Ensure XD/NX support is enabled"
  desc  "Recent processors in the x86 family support the ability to prevent code execution on a per memory page basis. Generically and on AMD processors, this ability is called No Execute (NX), while on Intel processors it is called Execute Disable (XD). This ability can help prevent exploitation of buffer overflow vulnerabilities and should be activated whenever possible. Extra steps must be taken to ensure that this protection is enabled, particularly on 32-bit x86 systems. Other processors, such as Itanium and POWER, have included such support since inception and the standard kernel for those platforms supports the feature.\n\nRationale: Enabling any feature that can protect against buffer overflow attacks enhances the security of the system."
  impact 0.0
  a = command("dmesg | grep \"NX [(]Execute Disable[)] protection: active\"").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/.+/) }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.3_Ensure_address_space_layout_randomization_ASLR_is_enabled" do
  title "Ensure address space layout randomization (ASLR) is enabled"
  desc  "Address space layout randomization (ASLR) is an exploit mitigation technique which randomly arranges the address space of key data areas of a process.\n\nRationale: Randomly placing virtual memory regions will make it difficult to write memory page exploits as the memory placement will be consistently shifting."
  impact 1.0
  describe kernel_parameter("kernel.randomize_va_space") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("kernel.randomize_va_space") do
    its("value") { should eq 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.5.4_Ensure_prelink_is_disabled" do
  title "Ensure prelink is disabled"
  desc  "prelink is a program that modifies ELF shared libraries and ELF dynamically linked binaries in such a way that the time needed for the dynamic linker to perform relocations at startup significantly decreases.\n\nRationale: The prelinking feature can interfere with the operation of AIDE, because it changes binaries. Prelinking can also increase the vulnerability of the system if a malicious user is able to compromise a common library such as libc."
  impact 1.0
  describe package("prelink") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.1.1_Ensure_SELinux_is_not_disabled_in_bootloader_configuration" do
  title "Ensure SELinux is not disabled in bootloader configuration"
  desc  "Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.\n\nRationale: SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden."
  impact 1.0
  describe.one do
    describe file("/boot/grub/grub.cfg") do
      its("content") { should_not match(/^\s*linux\S*(\s+\S+)+\s+selinux=0/) }
    end
    describe file("/boot/grub/grub.cfg") do
      its("content") { should_not match(/^\s*linux\S*(\s+\S+)+\s+enforcing=0/) }
    end
    describe package("selinux") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.1.2_Ensure_the_SELinux_state_is_enforcing" do
  title "Ensure the SELinux state is enforcing"
  desc  "Set SELinux to enable when the system is booted.\n\nRationale: SELinux must be enabled at boot time in to ensure that the controls it provides are in effect at all times."
  impact 1.0
  describe.one do
    describe file("/etc/selinux/config") do
      its("content") { should match(/^\s*SELINUX\s*=\s*enforcing\s*(\s+#.*)?$/) }
    end
    a = command("sestatus").stdout.scan(/.+/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/^SELinux status:\s+enabled$/) }
      end
    end
    a = command("sestatus").stdout.scan(/.+/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/^Current mode:\s+enforcing$/) }
      end
    end
    a = command("sestatus").stdout.scan(/.+/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/^Mode from config file:\s+enforcing$/) }
      end
    end
    describe package("selinux") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.1.3_Ensure_SELinux_policy_is_configured" do
  title "Ensure SELinux policy is configured"
  desc  "Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.\n\nRationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that at least the default recommendations are met."
  impact 1.0
  describe.one do
    describe file("/etc/selinux/config") do
      its("content") { should match(/^\s*SELINUXTYPE\s*=\s*(ubuntu|default|mls)\s*(\s+#.*)?$/) }
    end
    a = command("sestatus").stdout.scan(/.+/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/^Policy from config file:\s+(ubuntu|default|mls)$/) }
      end
    end
    describe package("selinux") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.1.4_Ensure_no_unconfined_daemons_exist" do
  title "Ensure no unconfined daemons exist"
  desc  "Daemons that are not defined in SELinux policy will inherit the security context of their parent process.\n\nRationale: Since daemons are launched and descend from the init process, they will inherit the security context label initrc_t. This could cause the unintended consequence of giving the process more permission than it requires."
  impact 1.0
  describe.one do
    processes(/.*/).where { pid > 0 }.entries.each do |entry|
      describe entry.label.to_s.split(":")[2] do
        it { should_not cmp "initrc_t" }
      end
    end
    describe package("selinux") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.2.1_Ensure_AppArmor_is_not_disabled_in_bootloader_configuration" do
  title "Ensure AppArmor is not disabled in bootloader configuration"
  desc  "Configure AppArmor to be enabled at boot time and verify that it has not been overwritten by the bootloader boot parameters.\n\nRationale: AppArmor must be enabled at boot time in your bootloader configuration to ensure that the controls it provides are not overridden."
  impact 1.0
  describe.one do
    describe file("/boot/grub/grub.cfg") do
      its("content") { should_not match(/^\s*linux\S*(\s+\S+)+\s+apparmor=0/) }
    end
    describe package("apparmor") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.2.2_Ensure_all_AppArmor_Profiles_are_enforcing" do
  title "Ensure all AppArmor Profiles are enforcing"
  desc  "AppArmor profiles define what resources applications are able to access.\n\nRationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated."
  impact 1.0
  describe.one do
    describe command("apparmor_status --profiled") do
      its("stdout") { should cmp > 0 }
    end
    describe command("apparmor_status --complaining") do
      its("stdout") { should cmp == 0 }
    end
    describe command("apparmor_status").stdout.scan(/^(\d+).*unconfined/).flatten do
      it { should cmp == 0 }
    end
    describe package("apparmor") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.6.3_Ensure_SELinux_or_AppArmor_are_installed" do
  title "Ensure SELinux or AppArmor are installed"
  desc  "SELinux and AppArmor provide Mandatory Access Controls.\n\nRationale: Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available."
  impact 0.0
  describe.one do
    describe package("selinux") do
      it { should be_installed }
    end
    describe package("apparmor") do
      it { should be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.1_Ensure_message_of_the_day_is_configured_properly" do
  title "Ensure message of the day is configured properly"
  desc  "The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.\n                    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \n                      \\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \"uname -a\" command once they have logged in."
  impact 1.0
  describe file("/etc/motd") do
    its("content") { should_not match(/(\\v|\\r|\\m|\\s)/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.2_Ensure_local_login_warning_banner_is_configured_properly" do
  title "Ensure local login warning banner is configured properly"
  desc  "The contents of the  /etc/issue file are displayed to users prior to login for local terminals.\n                  \n                  \n                     \n                        \n                     \n                  \n                   Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If  mingetty(8)  supports the following options, they display operating system information:\n                      \n                  \n                   \n                   \\m\n                       - machine architecture\n                      \\r\n                       - operating system release\n                      \\s\n                       - operating system name\n                      \\v\n                       - operating system version\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place.  Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in."
  impact 0.0
  describe file("/etc/issue") do
    its("content") { should_not match(/(\\v|\\r|\\m|\\s)/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.3_Ensure_remote_login_warning_banner_is_configured_properly" do
  title "Ensure remote login warning banner is configured properly"
  desc  "The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.\n                   Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If  mingetty(8)  supports the following options, they display operating system information:\n                      \n                     \n                      \\m\n                       - machine architecture\n                      \\r\n                       - operating system release\n                      \\s\n                       - operating system name\n                      \\v\n                       - operating system version\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in."
  impact 0.0
  describe file("/etc/issue.net") do
    its("content") { should_not match(/(\\v|\\r|\\m|\\s)/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.4_Ensure_permissions_on_etcmotd_are_configured" do
  title "Ensure permissions on /etc/motd are configured"
  desc  "The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.\n\nRationale: If the /etc/motd file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 0.0
  describe file("/etc/motd") do
    it { should exist }
  end
  describe file("/etc/motd") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/motd") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/motd") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/motd") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/motd") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/motd") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/motd") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/motd") do
    its("sgid") { should equal false }
  end
  describe file("/etc/motd") do
    its("sticky") { should equal false }
  end
  describe file("/etc/motd") do
    its("suid") { should equal false }
  end
  describe file("/etc/motd") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/motd") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/motd") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/motd") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.5_Ensure_permissions_on_etcissue_are_configured" do
  title "Ensure permissions on /etc/issue are configured"
  desc  "The contents of the /etc/issue file are displayed to users prior to login for local terminals.\n\nRationale: If the /etc/issue file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 1.0
  describe file("/etc/issue") do
    it { should exist }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/issue") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/issue") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/issue") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/issue") do
    its("sgid") { should equal false }
  end
  describe file("/etc/issue") do
    its("sticky") { should equal false }
  end
  describe file("/etc/issue") do
    its("suid") { should equal false }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/issue") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/issue") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.6_Ensure_permissions_on_etcissue.net_are_configured" do
  title "Ensure permissions on /etc/issue.net are configured"
  desc  "The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.\n\nRationale: If the /etc/issue.net file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 0.0
  describe file("/etc/issue.net") do
    it { should exist }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/issue.net") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/issue.net") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/issue.net") do
    its("sgid") { should equal false }
  end
  describe file("/etc/issue.net") do
    its("sticky") { should equal false }
  end
  describe file("/etc/issue.net") do
    its("suid") { should equal false }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/issue.net") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/issue.net") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.7.2_Ensure_GDM_login_banner_is_configured" do
  title "Ensure GDM login banner is configured"
  desc  "GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place."
  impact 1.0
  describe.one do
    describe file("/etc/dconf/profile/gdm") do
      its("content") { should match(/^user-db:user$/) }
    end
    describe file("/etc/dconf/profile/gdm") do
      its("content") { should match(/^system-db:gdm$/) }
    end
    describe file("/etc/dconf/profile/gdm") do
      its("content") { should match(/^file-db:\/usr\/share\/gdm\/greeter-dconf-defaults$/) }
    end
    describe file("/etc/dconf/db/gdm.d/01-banner-message") do
      its("content") { should match(/^banner-message-enable=true$/) }
    end
    describe file("/etc/dconf/db/gdm.d/01-banner-message") do
      its("content") { should match(/^banner-message-text='.+'$/) }
    end
    describe package("gdm") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.8_Ensure_updates_patches_and_additional_security_software_are_installed" do
  title "Ensure updates, patches, and additional security software are installed"
  desc  "Periodically patches are released for included software either due to security flaws or to include additional functionality.\n\nRationale: Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.1_Ensure_chargen_services_are_not_enabled" do
  title "Ensure chargen services are not enabled"
  desc  "chargen is a network service that responds with 0 to 512 ASCII characters for each connection it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("chargen").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^chargen\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^chargen\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.2_Ensure_daytime_services_are_not_enabled" do
  title "Ensure daytime services are not enabled"
  desc  "daytime is a network service that responds with the server's current date and time. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("daytime").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^daytime\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^daytime\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.3_Ensure_discard_services_are_not_enabled" do
  title "Ensure discard services are not enabled"
  desc  "discard is a network service that simply discards all data it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("discard").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^discard\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^discard\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.4_Ensure_echo_services_are_not_enabled" do
  title "Ensure echo services are not enabled"
  desc  "echo is a network service that responds to clients with the data sent to it by the client. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("echo").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^echo\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^echo\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.5_Ensure_time_services_are_not_enabled" do
  title "Ensure time services are not enabled"
  desc  "time is a network service that responds with the server's current date and time as a 32 bit integer. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("time").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^time\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^time\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.6_Ensure_rsh_server_is_not_enabled" do
  title "Ensure rsh server is not enabled"
  desc  "The Berkeley rsh-server (rsh, rlogin, rexec) package contains legacy services that exchange credentials in clear-text.\n\nRationale: These legacy services contain numerous security exposures and have been replaced with the more secure SSH package."
  impact 1.0
  describe xinetd_conf.services("shell").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^shell\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^shell\s+/) }
    end
  end
  describe xinetd_conf.services("login").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^login\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^login\s+/) }
    end
  end
  describe xinetd_conf.services("exec").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^exec\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^exec\s+/) }
    end
  end
  describe xinetd_conf.services("rsh").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^rsh\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^rsh\s+/) }
    end
  end
  describe xinetd_conf.services("rlogin").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^rlogin\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^rlogin\s+/) }
    end
  end
  describe xinetd_conf.services("resec").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^resec\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^resec\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.7_Ensure_talk_server_is_not_enabled" do
  title "Ensure talk server is not enabled"
  desc  "The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client (allows initiate of talk sessions) is installed by default.\n\nRationale: The software presents a security risk as it uses unencrypted protocols for communication."
  impact 1.0
  describe xinetd_conf.services("talk").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^talk\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^talk\s+/) }
    end
  end
  describe xinetd_conf.services("ntalk").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^ntalk\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^ntalk\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.8_Ensure_telnet_server_is_not_enabled" do
  title "Ensure telnet server is not enabled"
  desc  "The telnet-server package contains the telnet daemon, which accepts connections from users from other systems via the telnet protocol.\n\nRationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow a user with access to sniff network traffic the ability to steal credentials. The ssh package provides an encrypted session and stronger security."
  impact 1.0
  describe xinetd_conf.services("telnet").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^telnet\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^telnet\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.9_Ensure_tftp_server_is_not_enabled" do
  title "Ensure tftp server is not enabled"
  desc  "Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot machines from a boot server. The packages tftp and atftp are both used to define and support a TFTP server.\n\nRationale: TFTP does not support authentication nor does it ensure the confidentiality or integrity of data. It is recommended that TFTP be removed, unless there is a specific need for TFTP. In that case, extreme caution must be used when configuring the services."
  impact 1.0
  describe xinetd_conf.services("tftp").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^tftp\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^tftp\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.1.10_Ensure_xinetd_is_not_enabled" do
  title "Ensure xinetd is not enabled"
  desc  "The eXtended InterNET Daemon (xinetd) is an open source super daemon that replaced the original inetd daemon. The xinetd daemon listens for well known services and dispatches the appropriate daemon to properly respond to service requests.\n\nRationale: If there are no xinetd services required, it is recommended that the daemon be disabled."
  impact 1.0
  a = command("systemctl is-enabled xinetd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.1.1_Ensure_time_synchronization_is_in_use" do
  title "Ensure time synchronization is in use"
  desc  "System time should be synchronized between all systems in an environment. This is typically done by establishing an authoritative time server or set of servers and having all systems synchronize their clocks to them.\n\nRationale: Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files have consistent time records across the enterprise, which aids in forensic investigations."
  impact 0.0
  describe.one do
    describe package("ntp") do
      it { should be_installed }
    end
    describe package("chrony") do
      it { should be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.1.2_Ensure_ntp_is_configured" do
  title "Ensure ntp is configured"
  desc  "ntp is a daemon which implements the Network Time Protocol (NTP). It is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on NTP can be found at  http://www.ntp.org . ntp can be configured to be a client and/or a server.\n                  \n                  \n                     \n                        \n                     \n                  \n                   This recommendation only applies if ntp is in use on the system.\n\nRationale: If ntp is in use on the system proper configuration is vital to ensuring time synchronization is working properly."
  impact 1.0
  describe.one do
    describe file("/etc/ntp.conf") do
      its("content") { should match(/^\s*restrict\s+(-4\s+)?default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/) }
    end
    describe file("/etc/ntp.conf") do
      its("content") { should match(/^\s*restrict\s+-6\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/) }
    end
    describe file("/etc/ntp.conf") do
      its("content") { should match(/^\s*server\s+\S+/) }
    end
    describe file("/etc/init.d/ntp") do
      its("content") { should match(/^\s*RUNASUSER\s*=\s*ntp\s*(?:#.*)?$/) }
    end
    describe package("ntp") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.1.3_Ensure_chrony_is_configured" do
  title "Ensure chrony is configured"
  desc  "chrony is a daemon which implements the Network Time Protocol (NTP) is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on chrony can be found at http://chrony.tuxfamily.org/\n                      . chrony can be configured to be a client and/or a server.\n\nRationale: If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working properly.\n                    This recommendation only applies if chrony is in use on the system."
  impact 1.0
  describe.one do
    describe file("/etc/chrony/chrony.conf") do
      its("content") { should match(/^\s*server\s+\S+/) }
    end
    processes(/^chronyd/).where { pid > 0 }.entries.each do |entry|
      a = passwd.where { user == "_chrony" }.uids.first
      describe user(entry.user) do
        its("uid") { should cmp a }
      end
    end
    describe package("chrony") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.2_Ensure_X_Window_System_is_not_installed" do
  title "Ensure X Window System is not installed"
  desc  "The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on workstations where users login, but not on servers where users typically do not login.\n\nRationale: Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface."
  impact 1.0
  describe packages(/^xserver-xorg.*/) do
    its("names") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.3_Ensure_Avahi_Server_is_not_enabled" do
  title "Ensure Avahi Server is not enabled"
  desc  "Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine.\n\nRationale: Automatic discovery of network services is not normally required for system functionality. It is recommended to disable the service to reduce the potential attach surface."
  impact 1.0
  a = command("systemctl is-enabled avahi-daemon.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.4_Ensure_CUPS_is_not_enabled" do
  title "Ensure CUPS is not enabled"
  desc  "The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.\n\nRationale: If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be disabled to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled cups.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.5_Ensure_DHCP_Server_is_not_enabled" do
  title "Ensure DHCP Server is not enabled"
  desc  "The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses.\n\nRationale: Unless a system is specifically set up to act as a DHCP server, it is recommended that this service be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled isc-dhcp-server.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
  a = command("systemctl is-enabled isc-dhcp-server6.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.6_Ensure_LDAP_server_is_not_enabled" do
  title "Ensure LDAP server is not enabled"
  desc  "The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.\n\nRationale: If the system will not need to act as an LDAP server, it is recommended that the software be disabled to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled slapd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.7_Ensure_NFS_and_RPC_are_not_enabled" do
  title "Ensure NFS and RPC are not enabled"
  desc  "The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.\n\nRationale: If the system does not export NFS shares or act as an NFS client, it is recommended that these services be disabled to reduce remote attack surface."
  impact 1.0
  a = command("systemctl is-enabled nfs-kernel-server.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
  a = command("systemctl is-enabled rpcbind.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.8_Ensure_DNS_Server_is_not_enabled" do
  title "Ensure DNS Server is not enabled"
  desc  "The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network.\n\nRationale: Unless a system is specifically designated to act as a DNS server, it is recommended that the package be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled bind9.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.9_Ensure_FTP_Server_is_not_enabled" do
  title "Ensure FTP Server is not enabled"
  desc  "The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.\n\nRationale: FTP does not protect the confidentiality of data or authentication credentials. It is recommended sftp be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled vsftpd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.10_Ensure_HTTP_server_is_not_enabled" do
  title "Ensure HTTP server is not enabled"
  desc  "HTTP or web servers provide the ability to host web site content.\n\nRationale: Unless there is a need to run the system as a web server, it is recommended that the package be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled apache2.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.11_Ensure_IMAP_and_POP3_server_is_not_enabled" do
  title "Ensure IMAP and POP3 server is not enabled"
  desc  "dovecot is an open source IMAP and POP3 server for Linux based systems.\n\nRationale: Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the service be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled dovecot.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.12_Ensure_Samba_is_not_enabled" do
  title "Ensure Samba is not enabled"
  desc  "The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Small Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.\n\nRationale: If there is no need to mount directories and file systems to Windows systems, then this service can be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled smbd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.13_Ensure_HTTP_Proxy_Server_is_not_enabled" do
  title "Ensure HTTP Proxy Server is not enabled"
  desc  "Squid is a standard proxy server used in many distributions and environments.\n\nRationale: If there is no need for a proxy server, it is recommended that the squid proxy be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled squid.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.14_Ensure_SNMP_Server_is_not_enabled" do
  title "Ensure SNMP Server is not enabled"
  desc  "The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.\n\nRationale: The SNMP server communicates using SNMP v1, which transmits data in the clear and does not require authentication to execute commands. Unless absolutely necessary, it is recommended that the SNMP service not be used."
  impact 1.0
  a = command("systemctl is-enabled snmpd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.15_Ensure_mail_transfer_agent_is_configured_for_local-only_mode" do
  title "Ensure mail transfer agent is configured for local-only mode"
  desc  "Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail.\n\nRationale: The software for all Mail Transfer Agents is complex and most have a long history of security issues. While it is important to ensure that the system can process local mail messages, it is not necessary to have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives and processes mail from other systems."
  impact 1.0
  describe port(25).where { protocol =~ /.*/ && address =~ /^(?!127\.0\.0\.1|::1).*$/ } do
    its("entries") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.16_Ensure_rsync_service_is_not_enabled" do
  title "Ensure rsync service is not enabled"
  desc  "The rsyncd service can be used to synchronize files between systems over network links.\n\nRationale: The rsyncd service presents a security risk as it uses unencrypted protocols for communication."
  impact 1.0
  a = command("systemctl is-enabled rsync.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.17_Ensure_NIS_Server_is_not_enabled" do
  title "Ensure NIS Server is not enabled"
  desc  "The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files.\n\nRationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be disabled and other, more secure services be used"
  impact 1.0
  a = command("systemctl is-enabled nis.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.1_Ensure_NIS_Client_is_not_installed" do
  title "Ensure NIS Client is not installed"
  desc  "The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client (ypbind) was used to bind a machine to an NIS server and receive the distributed configuration files.\n\nRationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed."
  impact 1.0
  describe package("nis") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.2_Ensure_rsh_client_is_not_installed" do
  title "Ensure rsh client is not installed"
  desc  "The rsh package contains the client commands for the rsh services.\n\nRationale: These legacy clients contain numerous security exposures and have been replaced with the more secure SSH package. Even if the server is removed, it is best to ensure the clients are also removed to prevent users from inadvertently attempting to use these commands and therefore exposing their credentials. Note that removing the rsh package removes the clients for rsh, rcp and rlogin."
  impact 1.0
  describe package("rsh-client") do
    it { should_not be_installed }
  end
  describe package("rsh-redone-client") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.3_Ensure_talk_client_is_not_installed" do
  title "Ensure talk client is not installed"
  desc  "The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client, which allows initialization of talk sessions, is installed by default.\n\nRationale: The software presents a security risk as it uses unencrypted protocols for communication."
  impact 1.0
  describe package("talk") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.4_Ensure_telnet_client_is_not_installed" do
  title "Ensure telnet client is not installed"
  desc  "The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol.\n\nRationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions."
  impact 1.0
  describe package("telnet") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.5_Ensure_LDAP_client_is_not_installed" do
  title "Ensure LDAP client is not installed"
  desc  "The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.\n\nRationale: If the system will not need to act as an LDAP client, it is recommended that the software be removed to reduce the potential attack surface."
  impact 1.0
  describe package("ldap-utils") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.1.1_Ensure_IP_forwarding_is_disabled" do
  title "Ensure IP forwarding is disabled"
  desc  "The net.ipv4.ip_forward flag is used to tell the system whether it can forward packets or not.\n\nRationale: Setting the flag to 0 ensures that a system with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router."
  impact 1.0
  describe kernel_parameter("net.ipv4.ip_forward") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.ip_forward") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.1.2_Ensure_packet_redirect_sending_is_disabled" do
  title "Ensure packet redirect sending is disabled"
  desc  "ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as a router (in a host only configuration), there is no need to send redirects.\n\nRationale: An attacker could use a compromised host to send invalid ICMP redirects to other router devices in an attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.1_Ensure_source_routed_packets_are_not_accepted" do
  title "Ensure source routed packets are not accepted"
  desc  "In networking, source routing allows a sender to partially or fully specify the route packets take through a network. In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used.\n\nRationale: Setting net.ipv4.conf.all.accept_source_route and net.ipv4.conf.default.accept_source_route to 0 disables the system from accepting source routed packets. Assume this system was capable of routing packets to Internet routable addresses on one interface and private addresses on another interface. Assume that the private addresses were not routable to the Internet routable addresses and vice versa. Under normal routing circumstances, an attacker from the Internet routable addresses could not use the system as a way to reach the private address systems. If, however, source routed packets were allowed, they could be used to gain access to the private address systems as the route could be specified, rather than rely on routing protocols that did not allow this routing."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.2_Ensure_ICMP_redirects_are_not_accepted" do
  title "Ensure ICMP redirects are not accepted"
  desc  "ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects to 0, the system will not accept any ICMP redirect messages, and therefore, won't allow outsiders to update the system's routing tables.\n\nRationale: Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables and get them to send packets to incorrect networks and allow your system packets to be captured."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.3_Ensure_secure_ICMP_redirects_are_not_accepted" do
  title "Ensure secure ICMP redirects are not accepted"
  desc  "Secure ICMP redirects are the same as ICMP redirects, except they come from gateways listed on the default gateway list. It is assumed that these gateways are known to your system, and that they are likely to be secure.\n\nRationale: It is still possible for even known gateways to be compromised. Setting net.ipv4.conf.all.secure_redirects to 0 protects the system from routing table updates by possibly compromised known gateways."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.secure_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.secure_redirects") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.secure_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.secure_redirects") do
    its("value") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.4_Ensure_suspicious_packets_are_logged" do
  title "Ensure suspicious packets are logged"
  desc  "When enabled, this feature logs packets with un-routable source addresses to the kernel log.\n\nRationale: Enabling this feature and logging these packets allows an administrator to investigate the possibility that an attacker is sending spoofed packets to their system."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should eq 1 }
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.5_Ensure_broadcast_ICMP_requests_are_ignored" do
  title "Ensure broadcast ICMP requests are ignored"
  desc  "Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo and timestamp requests to broadcast and multicast addresses.\n\nRationale: Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for your network could be used to trick your host into starting (or participating) in a Smurf attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed source address. All hosts receiving this message and responding would send echo-reply messages back to the spoofed address, which is probably not routable. If many hosts respond to the packets, the amount of traffic on the network could be significantly multiplied."
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.6_Ensure_bogus_ICMP_responses_are_ignored" do
  title "Ensure bogus ICMP responses are ignored"
  desc  "Setting icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from filling up with useless log messages.\n\nRationale: Some routers (and some attackers) will send responses that violate RFC-1122 and attempt to fill up a log file system with many useless error messages."
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses") do
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.7_Ensure_Reverse_Path_Filtering_is_enabled" do
  title "Ensure Reverse Path Filtering is enabled"
  desc  "Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 1 forces the Linux kernel to utilize reverse path filtering on a received packet to determine if the packet was valid. Essentially, with reverse path filtering, if the return packet does not go out the same interface that the corresponding source packet came from, the packet is dropped (and logged if log_martians is set).\n\nRationale: Setting these flags is a good way to deter attackers from sending your system bogus packets that cannot be responded to. One instance where this feature breaks down is if asymmetrical routing is employed. This would occur when using dynamic routing protocols (bgp, ospf, etc) on your system. If you are using asymmetrical routing on your system, you will not be able to enable this feature without breaking the routing."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.rp_filter") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.rp_filter") do
    its("value") { should eq 1 }
  end
  describe kernel_parameter("net.ipv4.conf.default.rp_filter") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.rp_filter") do
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.8_Ensure_TCP_SYN_Cookies_is_enabled" do
  title "Ensure TCP SYN Cookies is enabled"
  desc  "When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that encodes the source and destination IP address and port number and the time the packet was sent. A legitimate connection would send the ACK packet of the three way handshake with the specially crafted sequence number. This allows the system to verify that it has received a valid response to a SYN cookie and allow the connection, even though there is no corresponding SYN in the queue.\n\nRationale: Attackers use SYN flood attacks to perform a denial of service attacked on a system by sending many SYN packets without completing the three way handshake. This will quickly use up slots in the kernel's half-open connection queue and prevent legitimate connections from succeeding. SYN cookies allow the system to keep accepting valid connections, even if under a denial of service attack."
  impact 1.0
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.3.1_Ensure_IPv6_router_advertisements_are_not_accepted" do
  title "Ensure IPv6 router advertisements are not accepted"
  desc  "This setting disables the system's ability to accept IPv6 router advertisements.\n\nRationale: It is recommended that systems not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes."
  impact 0.0
  describe.one do
    describe kernel_parameter("net.ipv6.conf.all.accept_ra") do
      its("value") { should_not be_nil }
    end
    describe kernel_parameter("net.ipv6.conf.all.accept_ra") do
      its("value") { should eq 0 }
    end
    describe kernel_parameter("net.ipv6.conf.default.accept_ra") do
      its("value") { should_not be_nil }
    end
    describe kernel_parameter("net.ipv6.conf.default.accept_ra") do
      its("value") { should eq 0 }
    end
    describe file("/boot/grub/grub.cfg") do
      its("content") { should match(/^\s*kernel\S+(\s+\S+)+\s+ipv6\.disable=1^\s*linux\S*(\s+\S+)+\s+ipv6\.disable=1/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.3.2_Ensure_IPv6_redirects_are_not_accepted" do
  title "Ensure IPv6 redirects are not accepted"
  desc  "This setting prevents the system from accepting ICMP redirects. ICMP redirects tell the system about alternate routes for sending traffic.\n\nRationale: It is recommended that systems not accept ICMP redirects as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes."
  impact 0.0
  describe.one do
    describe kernel_parameter("net.ipv6.conf.all.accept_redirects") do
      its("value") { should_not be_nil }
    end
    describe kernel_parameter("net.ipv6.conf.all.accept_redirects") do
      its("value") { should eq 0 }
    end
    describe kernel_parameter("net.ipv6.conf.default.accept_redirects") do
      its("value") { should_not be_nil }
    end
    describe kernel_parameter("net.ipv6.conf.default.accept_redirects") do
      its("value") { should eq 0 }
    end
    describe file("/boot/grub/grub.cfg") do
      its("content") { should match(/^\s*linux\S*(\s+\S+)+\s+ipv6\.disable=1/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.3.3_Ensure_IPv6_is_disabled" do
  title "Ensure IPv6 is disabled"
  desc  "Although IPv6 has many advantages over IPv4, few organizations have implemented IPv6.\n\nRationale: If IPv6 is not to be used, it is recommended that it be disabled to reduce the attack surface of the system."
  impact 0.0
  describe file("/boot/grub/grub.cfg") do
    its("content") { should match(/^\s*linux\S*(\s+\S+)+\s+ipv6\.disable=1/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.1_Ensure_TCP_Wrappers_is_installed" do
  title "Ensure TCP Wrappers is installed"
  desc  "TCP Wrappers provides a simple access list and standardized logging method for services capable of supporting it. In the past, services that were called from inetd and xinetd supported the use of tcp wrappers. As inetd and xinetd have been falling in disuse, any service that can support tcp wrappers will have the libwrap.so library attached to it.\n\nRationale: TCP Wrappers provide a good simple access list mechanism to services that may not have that support built in. It is recommended that all services that can support TCP Wrappers, use it."
  impact 1.0
  describe package("tcpd") do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.2_Ensure_etchosts.allow_is_configured" do
  title "Ensure /etc/hosts.allow is configured"
  desc  "The /etc/hosts.allow file specifies which IP addresses are permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.deny file.\n\nRationale: The /etc/hosts.allow file supports access control by IP and helps ensure that only authorized systems can connect to the system."
  impact 1.0
  describe file("/etc/hosts.allow") do
    it { should exist }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.3_Ensure_etchosts.deny_is_configured" do
  title "Ensure /etc/hosts.deny is configured"
  desc  "The /etc/hosts.deny file specifies which IP addresses are not permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.allow file.\n\nRationale: The /etc/hosts.deny file serves as a failsafe so that any host not specified in /etc/hosts.allow is denied access to the system."
  impact 1.0
  describe file("/etc/hosts.deny") do
    its("content") { should match(/^ALL: ALL/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.4_Ensure_permissions_on_etchosts.allow_are_configured" do
  title "Ensure permissions on /etc/hosts.allow are configured"
  desc  "The /etc/hosts.allow file contains networking information that is used by many applications and therefore must be readable for these applications to operate.\n\nRationale: It is critical to ensure that the /etc/hosts.allow file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/hosts.allow") do
    it { should exist }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    its("sgid") { should equal false }
  end
  describe file("/etc/hosts.allow") do
    its("sticky") { should equal false }
  end
  describe file("/etc/hosts.allow") do
    its("suid") { should equal false }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/hosts.allow") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/hosts.allow") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.5_Ensure_permissions_on_etchosts.deny_are_644" do
  title "Ensure permissions on /etc/hosts.deny are 644"
  desc  "The /etc/hosts.deny file contains network information that is used by many system applications and therefore must be readable for these applications to operate.\n\nRationale: It is critical to ensure that the /etc/hosts.deny file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/hosts.deny") do
    it { should exist }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    its("sgid") { should equal false }
  end
  describe file("/etc/hosts.deny") do
    its("sticky") { should equal false }
  end
  describe file("/etc/hosts.deny") do
    its("suid") { should equal false }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/hosts.deny") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/hosts.deny") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.5.1_Ensure_DCCP_is_disabled" do
  title "Ensure DCCP is disabled"
  desc  "The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports streaming media and telephony. DCCP provides a way to gain access to congestion control, without having to do it at the application layer, but does not provide in-sequence delivery.\n\nRationale: If the protocol is not required, it is recommended that the drivers not be installed to reduce the potential attack surface."
  impact 0.0
  a = command("modprobe -n -v dccp").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^dccp\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.5.2_Ensure_SCTP_is_disabled" do
  title "Ensure SCTP is disabled"
  desc  "The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support message oriented communication, with several streams of messages in one connection. It serves a similar function as TCP and UDP, incorporating features of both. It is message-oriented like UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP.\n\nRationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
  impact 0.0
  a = command("modprobe -n -v sctp").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^sctp\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.5.3_Ensure_RDS_is_disabled" do
  title "Ensure RDS is disabled"
  desc  "The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide low-latency, high-bandwidth communications between cluster nodes. It was developed by the Oracle Corporation.\n\nRationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
  impact 0.0
  a = command("modprobe -n -v rds").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^rds\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.5.4_Ensure_TIPC_is_disabled" do
  title "Ensure TIPC is disabled"
  desc  "The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communication between cluster nodes.\n\nRationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
  impact 0.0
  a = command("modprobe -n -v tipc").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^tipc\s+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.6.1_Ensure_iptables_is_installed" do
  title "Ensure iptables is installed"
  desc  "iptables allows configuration of the IPv4 tables in the linux kernel and the rules stored within them. Most firewall configuration utilities operate as a front end to iptables.\n\nRationale: iptables is required for firewall management and configuration."
  impact 1.0
  describe package("iptables") do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.6.2_Ensure_default_deny_firewall_policy" do
  title "Ensure default deny firewall policy"
  desc  "A default deny all policy on connections ensures that any unconfigured network usage will be rejected.\n\nRationale: With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage."
  impact 1.0
  a = command("iptables -L").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^Chain INPUT \(policy (DROP|REJECT)\)$/) }
      end
    end
  end
  a = command("iptables -L").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^Chain FORWARD \(policy (DROP|REJECT)\)$/) }
      end
    end
  end
  a = command("iptables -L").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^Chain OUTPUT \(policy (DROP|REJECT)\)$/) }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.6.3_Ensure_loopback_traffic_is_configured" do
  title "Ensure loopback traffic is configured"
  desc  "Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (127.0.0.0/8).\n\nRationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (127.0.0.0/8) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure."
  impact 1.0
  a = command("iptables -L INPUT -v -n").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^\s*\S+\s+\S+\s+ACCEPT\s+all\s+--\s+lo\s+\*\s+0\.0\.0\.0\/0\s+0\.0\.0\.0\/0\s*$/) }
      end
    end
  end
  a = command("iptables -L INPUT -v -n").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^\s*\S+\s+\S+\s+DROP\s+all\s+--\s+\*\s+\*\s+127\.0\.0\.0\/8\s+0\.0\.0\.0\/0\s*$/) }
      end
    end
  end
  a = command("iptables -L OUTPUT -v -n").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^\s*\S+\s+\S+\s+ACCEPT\s+all\s+--\s+\*\s+lo\s+0\.0\.0\.0\/0\s+0\.0\.0\.0\/0\s*$/) }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.6.4_Ensure_outbound_and_established_connections_are_configured" do
  title "Ensure outbound and established connections are configured"
  desc  "Configure the firewall rules for new outbound, and established connections.\n\nRationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_3.6.5_Ensure_firewall_rules_exist_for_all_open_ports" do
  title "Ensure firewall rules exist for all open ports"
  desc  "Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.\n\nRationale: Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports."
  impact 1.0
  describe "SCAP oval resource shellcommand_test could not be loaded: shellcommand_test can only test with a line_selection content at the moment" do
    skip "SCAP oval resource shellcommand_test could not be loaded: shellcommand_test can only test with a line_selection content at the moment"
  end
  describe "SCAP oval resource shellcommand_test could not be loaded: SCAP::OVAL::ShellCommandTest cannot find node reference: state#state_ref" do
    skip "SCAP oval resource shellcommand_test could not be loaded: SCAP::OVAL::ShellCommandTest cannot find node reference: state#state_ref"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.7_Ensure_wireless_interfaces_are_disabled" do
  title "Ensure wireless interfaces are disabled"
  desc  "Wireless networking is used when wired networks are unavailable. Ubuntu contains a wireless tool kit to allow system administrators to configure and use wireless networks.\n\nRationale: If wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.1.1_Ensure_audit_log_storage_size_is_configured" do
  title "Ensure audit log storage size is configured"
  desc  "Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be rotated and a new log file will be started.\n\nRationale: It is important that an appropriate size is determined for log files so that they do not impact the system and audit data is not lost."
  impact 0.0
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*max_log_file\s*=\s*\S+\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.1.2_Ensure_system_is_disabled_when_audit_logs_are_full" do
  title "Ensure system is disabled when audit logs are full"
  desc  "The auditd daemon can be configured to halt the system when the audit logs are full.\n\nRationale: In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the system's availability."
  impact 1.0
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*space_left_action\s*=\s*email\s*(\s+#.*)?$/) }
  end
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*action_mail_acct\s*=\s*root\s*(\s+#.*)?$/) }
  end
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*admin_space_left_action\s*=\s*halt\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.1.3_Ensure_audit_logs_are_not_automatically_deleted" do
  title "Ensure audit logs are not automatically deleted"
  desc  "The max_log_file_action setting determines how to handle the audit log file reaching the max file size. A value of keep_logs will rotate the logs but never delete old logs.\n\nRationale: In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing the audit history."
  impact 1.0
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*max_log_file_action\s*=\s*keep_logs\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.2_Ensure_auditd_service_is_enabled" do
  title "Ensure auditd service is enabled"
  desc  "Turn on the auditd daemon to record system events.\n\nRationale: The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring."
  impact 1.0
  a = command("systemctl is-enabled auditd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.3_Ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled" do
  title "Ensure auditing for processes that start prior to auditd is enabled"
  desc  "Configure grub so that processes that are capable of being audited can be audited even if they start up prior to auditd startup.\n\nRationale: Audit events need to be captured on processes that start up prior to auditd, so that potential malicious activity cannot go undetected."
  impact 1.0
  describe file("/boot/grub/grub.cfg") do
    its("content") { should match(/^\s*linux\S*(\s+\S+)+\s+audit=1/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.4_Ensure_events_that_modify_date_and_time_information_are_collected" do
  title "Ensure events that modify date and time information are collected"
  desc  "Capture events where the system date and/or time has been modified. The parameters in this section are set to determine if the adjtimex (tune kernel clock), settimeofday (Set time, using timeval and timezone structures) stime (using seconds since 1/1/1970) or clock_settime (allows for the setting of several internal clocks and timers) system calls have been executed and always write an audit record to the /var/log/audit.log file upon exit, tagging the records with the identifier \"time-change\"\n\nRationale: Unexpected changes in system date and/or time could be a sign of malicious activity on the system."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-S\s+stime\s+-k\s+time-change *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+clock_settime\s+-k\s+time-change *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/localtime\s+-p\s+wa\s+-k\s+time-change *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-k\s+time-change *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+clock_settime\s+-k\s+time-change *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.5_Ensure_events_that_modify_usergroup_information_are_collected" do
  title "Ensure events that modify user/group information are collected"
  desc  "Record events affecting the group, passwd (user IDs), shadow and gshadow (passwords) or /etc/security/opasswd (old passwords, based on remember parameter in the PAM configuration) files. The parameters in this section will watch the files to see if they have been opened for write or have had attribute changes (e.g. permissions) and tag them with the identifier \"identity\" in the audit log file.\n\nRationale: Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/group\s+-p\s+wa\s+-k\s+identity *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/passwd\s+-p\s+wa\s+-k\s+identity *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/gshadow\s+-p\s+wa\s+-k\s+identity *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/shadow\s+-p\s+wa\s+-k\s+identity *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/security\/opasswd\s+-p\s+wa\s+-k\s+identity *$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.6_Ensure_events_that_modify_the_systems_network_environment_are_collected" do
  title "Ensure events that modify the system's network environment are collected"
  desc  "Record changes to network environment files or system calls. The below parameters monitor the sethostname (set the systems host name) or setdomainname (set the systems domainname) system calls, and write an audit event on system call exit. The other parameters monitor the /etc/issue and /etc/issue.net files (messages displayed pre-login), /etc/hosts (file containing host names and associated IP addresses) and /etc/sysconfig/network (directory containing network interface scripts and configurations) files.\n\nRationale: Monitoring sethostname and setdomainname will identify potential unauthorized changes to host and domainname of a system. The changing of these names could potentially break security parameters that are set based on those names. The /etc/hosts file is monitored for changes in the file that can indicate an unauthorized intruder is trying to change machine associations with IP addresses and trick users and processes into connecting to unintended machines. Monitoring /etc/issue and /etc/issue.net is important, as intruders could put disinformation into those files and trick users into providing information to the intruder. Monitoring /etc/sysconfig/network is important as it can show if network interfaces or scripts are being modified in a way that can lead to the machine becoming unavailable or compromised. All audit records will be tagged with the identifier \"system-locale.\""
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/issue\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/issue.net\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/hosts\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/network\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/networks\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.7_Ensure_events_that_modify_the_systems_Mandatory_Access_Controls_are_collected" do
  title "Ensure events that modify the system's Mandatory Access Controls are collected"
  desc  "Monitor SELinux/AppArmor mandatory access controls. The parameters below monitor any write access (potential additional, deletion or modification of files in the directory) or attribute changes to the /etc/selinux or /etc/apparmor and /etc/apparmor.d directories.\n\nRationale: Changes to files in these directories could indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of the system."
  impact 1.0
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-w\s+\/etc\/selinux\/\s+-p\s+wa\s+-k\s+MAC-policy *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-w\s+\/etc\/apparmor\/\s+-p\s+wa\s+-k\s+MAC-policy *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-w\s+\/etc\/apparmor.d\/\s+-p\s+wa\s+-k\s+MAC-policy *$/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.8_Ensure_login_and_logout_events_are_collected" do
  title "Ensure login and logout events are collected"
  desc  "Monitor login and logout events. The parameters below track changes to files associated with login/logout events. The file /var/log/faillog tracks failed events from login. The file /var/log/lastlog maintain records of the last time a user successfully logged in. The file /var/log/tallylog maintains records of failures via the pam_tally2 module\n\nRationale: Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/faillog\s+-p\s+wa\s+-k\s+logins *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/lastlog\s+-p\s+wa\s+-k\s+logins *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/tallylog\s+-p\s+wa\s+-k\s+logins *$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.9_Ensure_session_initiation_information_is_collected" do
  title "Ensure session initiation information is collected"
  desc  "Monitor session initiation events. The parameters in this section track changes to the files associated with session events. The file /var/run/utmp file tracks all currently logged in users. The /var/log/wtmp file tracks logins, logouts, shutdown, and reboot events. All audit records will be tagged with the identifier \"session.\" The file /var/log/btmp keeps track of failed login attempts and can be read by entering the command /usr/bin/last -f /var/log/btmp. All audit records will be tagged with the identifier \"logins.\"\n\nRationale: Monitoring these files for changes could alert a system administrator to logins occurring at unusual hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally log in)."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/run\/utmp\s+-p\s+wa\s+-k\s+session *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/wtmp\s+-p\s+wa\s+-k\s+session *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/btmp\s+-p\s+wa\s+-k\s+session *$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.10_Ensure_discretionary_access_control_permission_modification_events_are_collected" do
  title "Ensure discretionary access control permission modification events are collected"
  desc  "Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. The chmod, fchmod and fchmodat system calls affect the permissions associated with a file. The chown, fchown, fchownat and lchown system calls affect owner and group attributes on a file. The setxattr, lsetxattr, fsetxattr (set extended file attributes) and removexattr, lremovexattr, fremovexattr (remove extended file attributes) control extended file attributes. In all cases, an audit record will only be written for non-system user ids (auid >= 1000) and will ignore Daemon events (auid = 4294967295). All audit records will be tagged with the identifier \"perm_mod.\"\n\nRationale: Monitoring for changes in file attributes could alert a system administrator to activity that could indicate intruder activity or policy violation."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.11_Ensure_unsuccessful_unauthorized_file_access_attempts_are_collected" do
  title "Ensure unsuccessful unauthorized file access attempts are collected"
  desc  "Monitor for unsuccessful attempts to access files. The parameters below are associated with system calls that control creation (creat), opening (open, openat) and truncation (truncate, ftruncate) of files. An audit log record will only be written if the user is a non-privileged user (auid > = 1000), is not a Daemon event (auid=4294967295) and if the system call returned EACCES (permission denied to the file) or EPERM (some other permanent error associated with the specific system call). All audit records will be tagged with the identifier \"access.\"\n\nRationale: Failed attempts to open, create or truncate files could be an indication that an individual or process is trying to gain unauthorized access to the system."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.12_Ensure_use_of_privileged_commands_is_collected" do
  title "Ensure use of privileged commands is collected"
  desc  "Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to determine if unprivileged users are running these commands.\n\nRationale: Execution of privileged commands by non-privileged users could be an indication of someone trying to gain unauthorized access to the system."
  impact 1.0
  command("find / -regex .\\*/.\\+ -type f -perm /06000 -xdev").stdout.split.map { |x| "^\\-a (always,exit|exit,always) \\-F path=" + x.to_s }.map { |x| x.to_s + " \\-F perm=x \\-F auid>=1000 \\-F auid!=4294967295 \\-k privileged$" }.each do |entry|
    describe file("/etc/audit/audit.rules") do
      its("content") { should match Regexp.new(entry) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.13_Ensure_successful_file_system_mounts_are_collected" do
  title "Ensure successful file system mounts are collected"
  desc  "Monitor the use of the mount system call. The mount (and umount) system call controls the mounting and unmounting of file systems. The parameters below configure the system to create an audit record when the mount system call is used by a non-privileged user\n\nRationale: It is highly unusual for a non privileged user to mount file systems to the system. While tracking mount commands gives the system administrator evidence that external media may have been mounted (based on a review of the source of the mount and confirming it's an external media type), it does not conclusively indicate that data was exported to the media. System administrators who wish to determine if data were exported, would also have to track successful open, creat and truncate system calls requiring write access to a file under the mount point of the external media file system. This could give a fair indication that a write occurred. The only way to truly prove it, would be to track successful writes to the external media. Tracking write system calls could quickly fill up the audit log and is not recommended. Recommendations on configuration options to track data export to media is beyond the scope of this document."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.14_Ensure_file_deletion_events_by_users_are_collected" do
  title "Ensure file deletion events by users are collected"
  desc  "Monitor the use of system calls associated with the deletion or renaming of files and file attributes. This configuration statement sets up monitoring for the unlink (remove a file), unlinkat (remove a file attribute), rename (rename a file) and renameat (rename a file attribute) system calls and tags them with the identifier \"delete\".\n\nRationale: Monitoring these calls from non-privileged users could provide a system administrator with evidence that inappropriate removal of files and file attributes associated with protected files is occurring. While this audit option will look at all events, system administrators will want to look for specific privileged files that are being deleted or altered."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.15_Ensure_changes_to_system_administration_scope_sudoers_is_collected" do
  title "Ensure changes to system administration scope (sudoers) is collected"
  desc  "Monitor scope changes for system administrations. If the system has been properly configured to force system administrators to log in as themselves first and then use the sudo command to execute privileged commands, it is possible to monitor changes in scope. The file /etc/sudoers will be written to when the file or its attributes have changed. The audit records will be tagged with the identifier \"scope.\"\n\nRationale: Changes in the /etc/sudoers file can indicate that an unauthorized change has been made to scope of system administrator activity."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/sudoers\s+-p\s+wa\s+-k\s+scope *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/sudoers.d\s+-p\s+wa\s+-k\s+scope *$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.16_Ensure_system_administrator_actions_sudolog_are_collected" do
  title "Ensure system administrator actions (sudolog) are collected"
  desc  "Monitor the sudo log file. If the system has been properly configured to disable the use of the su command and force all administrators to have to log in first and then use sudo to execute privileged commands, then all administrator commands will be logged to /var/log/sudo.log. Any time a command is executed, an audit event will be triggered as the /var/log/sudo.log file will be opened for write and the executed administration command will be written to the log.\n\nRationale: Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file itself has been tampered with. Administrators will want to correlate the events written to the audit trail with the records written to /var/log/sudo.log to verify if unauthorized commands have been executed."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/sudo.log\s+-p\s+wa\s+-k\s+actions *$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.17_Ensure_kernel_module_loading_and_unloading_is_collected" do
  title "Ensure kernel module loading and unloading is collected"
  desc  "Monitor the loading and unloading of kernel modules. The programs insmod (install a kernel module), rmmod (remove a kernel module), and modprobe (a more sophisticated program to load and unload modules, as well as some other features) control loading and unloading of modules. The init_module (load a module) and delete_module (delete a module) system calls control loading and unloading of modules. Any execution of the loading and unloading module programs and system calls will trigger an audit record with an identifier of \"modules\".\n\nRationale: Monitoring the use of insmod, rmmod and modprobe could provide system administrators with evidence that an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system. Monitoring of the init_module and delete_module system calls would reflect an unauthorized user attempting to use a different program to load and unload modules."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/sbin\/insmod\s+-p\s+x\s+-k\s+modules *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/sbin\/rmmod\s+-p\s+x\s+-k\s+modules *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/sbin\/modprobe\s+-p\s+x\s+-k\s+modules *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+arch=b32\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+arch=b64\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should eq "x86_64" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.18_Ensure_the_audit_configuration_is_immutable" do
  title "Ensure the audit configuration is immutable"
  desc  "Set system audit so that audit rules cannot be modified with auditctl. Setting the flag \"-e 2\" forces audit to be put in immutable mode. Audit changes can only be made on system reboot.\n\nRationale: In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. Users would most likely notice a system reboot and that could alert administrators of an attempt to make unauthorized audit changes."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-e\s+2 *$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.1_Ensure_rsyslog_Service_is_enabled" do
  title "Ensure rsyslog Service is enabled"
  desc  "Once the rsyslog package is installed it needs to be activated.\n\nRationale: If the rsyslog service is not activated the system may default to the syslogd service or lack logging instead."
  impact 1.0
  describe.one do
    a = command("systemctl is-enabled rsyslog.service").stdout.scan(/enabled/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/.+/) }
      end
    end
    describe package("rsyslog") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.2_Ensure_logging_is_configured" do
  title "Ensure logging is configured"
  desc  "The /etc/rsyslog.conf file specifies rules for logging and which files are to be used to log certain classes of messages.\n\nRationale: A great deal of important security-related information is sent via rsyslog (e.g., successful and failed su attempts, failed login attempts, root login attempts, etc.)."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.3_Ensure_rsyslog_default_file_permissions_configured" do
  title "Ensure rsyslog default file permissions configured"
  desc  "rsyslog will create logfiles that do not already exist on the system. This setting controls what permissions will be applied to these newly created files.\n\nRationale: It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected."
  impact 1.0
  describe.one do
    describe file("/etc/rsyslog.conf") do
      its("content") { should match(/^\s*\$FileCreateMode\s+0[6420][40]0\s*(\s+#.*)?$/) }
    end
    describe package("rsyslog") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.4_Ensure_rsyslog_is_configured_to_send_logs_to_a_remote_log_host" do
  title "Ensure rsyslog is configured to send logs to a remote log host"
  desc  "The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or to receive messages from remote hosts, reducing administrative overhead.\n\nRationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system"
  impact 1.0
  describe.one do
    describe file("/etc/rsyslog.conf") do
      its("content") { should match(/^\s*\*\.\*\s+@/) }
    end
    describe package("rsyslog") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.5_Ensure_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts." do
  title "Ensure remote rsyslog messages are only accepted on designated log hosts."
  desc  "By default, rsyslog does not listen for log messages coming in from remote systems. The ModLoad tells rsyslog to load the imtcp.so module so it can listen over a network via TCP. The InputTCPServerRun option instructs rsyslogd to listen on the specified TCP port.\n\nRationale: The guidance in the section ensures that remote log hosts are configured to only accept rsyslog data from hosts within the specified domain and that those systems that are not designed to be log hosts do not accept any remote rsyslog messages. This provides protection from spoofed log data and ensures that system administrators are reviewing reasonably complete syslog data in a central location."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2.1_Ensure_syslog-ng_service_is_enabled" do
  title "Ensure syslog-ng service is enabled"
  desc  "Once the syslog-ng package is installed it needs to be activated.\n\nRationale: If the syslog-ng service is not activated the system may default to the syslogd service or lack logging instead."
  impact 1.0
  describe.one do
    a = command("systemctl is-enabled syslog-ng.service").stdout.scan(/enabled/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/.+/) }
      end
    end
    describe package("syslog-ng") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2.2_Ensure_logging_is_configured" do
  title "Ensure logging is configured"
  desc  "The /etc/syslog-ng/syslog-ng.conf file specifies rules for logging and which files are to be used to log certain classes of messages.\n\nRationale: A great deal of important security-related information is sent via syslog-ng (e.g., successful and failed su attempts, failed login attempts, root login attempts, etc.)."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2.3_Ensure_syslog-ng_default_file_permissions_configured" do
  title "Ensure syslog-ng default file permissions configured"
  desc  "syslog-ng will create logfiles that do not already exist on the system. This setting controls what permissions will be applied to these newly created files.\n\nRationale: It is important to ensure that log files exist and have the correct permissions to ensure that sensitive syslog-ng data is archived and protected."
  impact 1.0
  describe.one do
    describe file("/etc/syslog-ng/syslog-ng.conf") do
      its("content") { should match(/^\s*options\s+\{\s*(\S+;\s*)*perm\(0[6420][40]0\);\s*(\S+;\s*)*\};\s*(\s+#.*)?$/) }
    end
    describe package("syslog-ng") do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2.4_Ensure_syslog-ng_is_configured_to_send_logs_to_a_remote_log_host" do
  title "Ensure syslog-ng is configured to send logs to a remote log host"
  desc  "The syslog-ng utility supports the ability to send logs it gathers to a remote log host or to receive messages from remote hosts, reducing administrative overhead.\n\nRationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system"
  impact 1.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2.5_Ensure_remote_syslog-ng_messages_are_only_accepted_on_designated_log_hosts" do
  title "Ensure remote syslog-ng messages are only accepted on designated log hosts"
  desc  "By default, syslog-ng does not listen for log messages coming in from remote systems.\n\nRationale: The guidance in the section ensures that remote log hosts are configured to only accept syslog-ng data from hosts within the specified domain and that those systems that are not designed to be log hosts do not accept any remote syslog-ng messages. This provides protection from spoofed log data and ensures that system administrators are reviewing reasonably complete syslog data in a central location."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.3_Ensure_rsyslog_or_syslog-ng_is_installed" do
  title "Ensure rsyslog or syslog-ng is installed"
  desc  "The rsyslog and syslog-ng software are recommended replacements to the original syslogd daemon which provide improvements over syslogd, such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server.\n\nRationale: The security enhancements of rsyslog and syslog-ng such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server) justify installing and configuring the package."
  impact 1.0
  describe.one do
    describe package("rsyslog") do
      it { should be_installed }
    end
    describe package("syslog-ng") do
      it { should be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.4_Ensure_permissions_on_all_logfiles_are_configured" do
  title "Ensure permissions on all logfiles are configured"
  desc  "Log files stored in /var/log/ contain logged information from many services on the system, or on log hosts others as well.\n\nRationale: It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected."
  impact 1.0
  describe command("find /var/log -regex .\\*/.\\* \\! -perm -00037 -xdev") do
    its("stdout") { should_not be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.3_Ensure_logrotate_is_configured" do
  title "Ensure logrotate is configured"
  desc  "The system includes the capability of rotating log files regularly to avoid filling up the system with logs or making the logs unmanageable large. The file /etc/logrotate.d/syslog is the configuration file used to rotate log files created by syslog or rsyslog.\n\nRationale: By keeping the log files smaller and more manageable, a system administrator can easily archive these files to another system and spend less time looking through inordinately large log files."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.1_Ensure_cron_daemon_is_enabled" do
  title "Ensure cron daemon is enabled"
  desc  "The cron daemon is used to execute batch jobs on the system.\n\nRationale: While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run, and cron is used to execute them."
  impact 1.0
  a = command("systemctl is-enabled cron.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.2_Ensure_permissions_on_etccrontab_are_configured" do
  title "Ensure permissions on /etc/crontab are configured"
  desc  "The /etc/crontab file is used by cron to control its own jobs. The commands in this item make sure that root is the user and group owner of the file and that only the owner can access the file.\n\nRationale: This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access to these files could provide users with the ability to gain insight on system jobs that run on the system and could provide them a way to gain unauthorized privileged access."
  impact 1.0
  describe file("/etc/crontab") do
    it { should exist }
  end
  describe file("/etc/crontab") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/crontab") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/crontab") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/crontab") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.3_Ensure_permissions_on_etccron.hourly_are_configured" do
  title "Ensure permissions on /etc/cron.hourly are configured"
  desc  "This directory contains system cron jobs that need to run on an hourly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.hourly") do
    it { should exist }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.4_Ensure_permissions_on_etccron.daily_are_configured" do
  title "Ensure permissions on /etc/cron.daily are configured"
  desc  "The /etc/cron.daily directory contains system cron jobs that need to run on a daily basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.daily") do
    it { should exist }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.daily") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.daily") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.5_Ensure_permissions_on_etccron.weekly_are_configured" do
  title "Ensure permissions on /etc/cron.weekly are configured"
  desc  "The /etc/cron.weekly directory contains system cron jobs that need to run on a weekly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.weekly") do
    it { should exist }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.6_Ensure_permissions_on_etccron.monthly_are_configured" do
  title "Ensure permissions on /etc/cron.monthly are configured"
  desc  "The /etc/cron.monthly directory contains system cron jobs that need to run on a monthly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.monthly") do
    it { should exist }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.7_Ensure_permissions_on_etccron.d_are_configured" do
  title "Ensure permissions on /etc/cron.d are configured"
  desc  "The /etc/cron.d directory contains system cron jobs that need to run in a similar manner to the hourly, daily weekly and monthly jobs from /etc/crontab, but require more granular control as to when they run. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.d") do
    it { should exist }
  end
  describe file("/etc/cron.d") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.d") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.d") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.d") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.8_Ensure_atcron_is_restricted_to_authorized_users" do
  title "Ensure at/cron is restricted to authorized users"
  desc  "Configure /etc/cron.allow and /etc/at.allow to allow specific users to use these services. If /etc/cron.allow or /etc/at.allow do not exist, then /etc/at.deny and /etc/cron.deny are checked. Any user not specifically defined in those files is allowed to use at and cron. By removing the files, only users in /etc/cron.allow and /etc/at.allow are allowed to use at and cron. Note that even though a given user is not listed in cron.allow, cron jobs can still be run as that user. The cron.allow file only controls administrative access to the crontab command for scheduling and modifying cron jobs.\n\nRationale: On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file to control who can run cron jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files."
  impact 1.0
  describe file("/etc/cron.deny") do
    it { should_not exist }
  end
  describe file("/etc/at.deny") do
    it { should_not exist }
  end
  describe file("/etc/cron.allow") do
    it { should exist }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.allow") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/at.allow") do
    it { should exist }
  end
  describe file("/etc/at.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/at.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/at.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/at.allow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.1_Ensure_permissions_on_etcsshsshd_config_are_configured" do
  title "Ensure permissions on /etc/ssh/sshd_config are configured"
  desc  "The /etc/ssh/sshd_config file contains configuration specifications for sshd. The command below sets the owner and group of the file to root.\n\nRationale: The /etc/ssh/sshd_config file needs to be protected from unauthorized changes by non-privileged users."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    it { should exist }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.2_Ensure_SSH_Protocol_is_set_to_2" do
  title "Ensure SSH Protocol is set to 2"
  desc  "SSH supports two different and incompatible protocols: SSH1 and SSH2. SSH1 was the original protocol and was subject to security issues. SSH2 is more advanced and secure.\n\nRationale: SSH v1 suffers from insecurities that do not affect SSH v2."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*Protocol\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*Protocol\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "2" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.3_Ensure_SSH_LogLevel_is_set_to_INFO" do
  title "Ensure SSH LogLevel is set to INFO"
  desc  "The INFO parameter specifies that login and logout activity will be logged.\n\nRationale: SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically not recommended other than strictly for debugging SSH communications since it provides so much data that it is difficult to identify important security information. INFO level is the basic level that only records login activity of SSH users. In many situations, such as Incident Response, it is important to determine when a particular user was active on a system. The logout record can eliminate those users who disconnected, which helps narrow the field."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*LogLevel\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*LogLevel\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "INFO" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.4_Ensure_SSH_X11_forwarding_is_disabled" do
  title "Ensure SSH X11 forwarding is disabled"
  desc  "The X11Forwarding parameter provides the ability to tunnel X11 traffic through the connection to enable remote graphic connections.\n\nRationale: Disable X11 forwarding unless there is an operational requirement to use X11 applications directly. There is a small risk that the remote X11 servers of users who are logged in via SSH with X11 forwarding could be compromised by other users on the X11 server. Note that even if X11 forwarding is disabled, users can always install their own forwarders."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*X11Forwarding\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*X11Forwarding\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.5_Ensure_SSH_MaxAuthTries_is_set_to_4_or_less" do
  title "Ensure SSH MaxAuthTries is set to 4 or less"
  desc  "The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. When the login failure count reaches half the number, error messages will be written to the syslog file detailing the login failure.\n\nRationale: Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. While the recommended setting is 4, set the number based on site policy."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*MaxAuthTries\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*MaxAuthTries\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 4 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.6_Ensure_SSH_IgnoreRhosts_is_enabled" do
  title "Ensure SSH IgnoreRhosts is enabled"
  desc  "The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication.\n\nRationale: Setting this parameter forces users to enter a password when authenticating with ssh."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*IgnoreRhosts\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*IgnoreRhosts\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "yes" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.7_Ensure_SSH_HostbasedAuthentication_is_disabled" do
  title "Ensure SSH HostbasedAuthentication is disabled"
  desc  "The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user of .rhosts, or /etc/hosts.equiv, along with successful public key client host authentication. This option only applies to SSH Protocol Version 2.\n\nRationale: Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf, disabling the ability to use .rhosts files in SSH provides an additional layer of protection ."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*HostbasedAuthentication\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*HostbasedAuthentication\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.8_Ensure_SSH_root_login_is_disabled" do
  title "Ensure SSH root login is disabled"
  desc  "The PermitRootLogin parameter specifies if the root user can log in using ssh(1). The default is no.\n\nRationale: Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root via sudo or su. This in turn limits opportunity for non-repudiation and provides a clear audit trail in the event of a security incident"
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PermitRootLogin\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitRootLogin\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.9_Ensure_SSH_PermitEmptyPasswords_is_disabled" do
  title "Ensure SSH PermitEmptyPasswords is disabled"
  desc  "The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts with empty password strings.\n\nRationale: Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system"
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PermitEmptyPasswords\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitEmptyPasswords\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.10_Ensure_SSH_PermitUserEnvironment_is_disabled" do
  title "Ensure SSH PermitUserEnvironment is disabled"
  desc  "The PermitUserEnvironment option allows users to present environment options to the ssh daemon.\n\nRationale: Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has ssh executing trojan'd programs)"
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PermitUserEnvironment\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitUserEnvironment\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.11_Ensure_only_approved_MAC_algorithms_are_used" do
  title "Ensure only approved MAC algorithms are used"
  desc  "This variable limits the types of MAC algorithms that SSH can use during communication.\n\nRationale: MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase exploitability in SSH downgrade attacks. Weak algorithms continue to have a great deal of attention as a weak spot that can be exploited with expanded computing power. An attacker that breaks the algorithm could take advantage of a MiTM position to decrypt the SSH tunnel and capture credentials and information"
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*MACs\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*MACs\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp(/^((hmac-sha2-512-etm@openssh\.com|hmac-sha2-256-etm@openssh\.com|umac-128-etm@openssh\.com|hmac-sha2-512|hmac-sha2-256|umac-128@openssh\.com|curve25519-sha256@libssh\.org|diffie-hellman-group-exchange-sha256),)*(hmac-sha2-512-etm@openssh\.com|hmac-sha2-256-etm@openssh\.com|umac-128-etm@openssh\.com|hmac-sha2-512|hmac-sha2-256|umac-128@openssh\.com)$/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.12_Ensure_SSH_Idle_Timeout_Interval_is_configured" do
  title "Ensure SSH Idle Timeout Interval is configured"
  desc  "The two options ClientAliveInterval and ClientAliveCountMax control the timeout of ssh sessions. When the ClientAliveInterval variable is set, ssh sessions that have no activity for the specified length of time are terminated. When the ClientAliveCountMax variable is set, sshd will send client alive messages at every ClientAliveInterval interval. When the number of consecutive client alive messages are sent with no response from the client, the ssh session is terminated. For example, if the ClientAliveInterval is set to 15 seconds and the ClientAliveCountMax is set to 3, the client ssh session will be terminated after 45 seconds of idle time.\n\nRationale: Having no timeout value associated with a connection could allow an unauthorized user access to another user's ssh session (e.g. user walks away from their computer and doesn't lock the screen). Setting a timeout value at least reduces the risk of this happening.. While the recommended setting is 300 seconds (5 minutes), set this timeout value based on site policy. The recommended setting for ClientAliveCountMax is 0. In this case, the client session will be terminated after 5 minutes of idle time and no keepalive messages will be sent."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*ClientAliveInterval\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveInterval\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 300 }
    end
  end
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*ClientAliveCountMax\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveCountMax\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 3 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.13_Ensure_SSH_LoginGraceTime_is_set_to_one_minute_or_less" do
  title "Ensure SSH LoginGraceTime is set to one minute or less"
  desc  "The LoginGraceTime parameter specifies the time allowed for successful authentication to the SSH server. The longer the Grace period is the more open unauthenticated connections can exist. Like other session controls in this session the Grace Period should be limited to appropriate organizational limits to ensure the service is available for needed access.\n\nRationale: Setting the LoginGraceTime parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. It will also limit the number of concurrent unauthenticated connections While the recommended setting is 60 seconds (1 Minute), set the number based on site policy."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*LoginGraceTime\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*LoginGraceTime\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 60 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.14_Ensure_SSH_access_is_limited" do
  title "Ensure SSH access is limited"
  desc  "There are several options available to limit which users and group can access the system via SSH. It is recommended that at least one of the following options be leveraged:\n               \n                   AllowUsers\n                  \n                The AllowUsers variable gives the system administrator the option of allowing specific users to ssh into the system. The list consists of comma separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by only allowing the allowed users to log in from a particular host, the entry can be specified in the form of user@host.\n               \n                   AllowGroups\n                  \n                The AllowGroups variable gives the system administrator the option of allowing specific groups of users to ssh into the system. The list consists of comma separated group names. Numeric group IDs are not recognized with this variable.\n               \n                   DenyUsers\n                  \n                The DenyUsers variable gives the system administrator the option of denying specific users to ssh into the system. The list consists of comma separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by specifically denying a user's access from a particular host, the entry can be specified in the form of user@host.\n               \n                   DenyGroups\n                  \n                The DenyGroups variable gives the system administrator the option of denying specific groups of users to ssh into the system. The list consists of comma separated group names. Numeric group IDs are not recognized with this variable.\n\nRationale: Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\s+(\S+)/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.15_Ensure_SSH_warning_banner_is_configured" do
  title "Ensure SSH warning banner is configured"
  desc  "The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. By default, no banner is displayed.\n\nRationale: Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning message prior to the normal user login may assist the prosecution of trespassers on the computer system."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*Banner\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*Banner\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3.1_Ensure_password_creation_requirements_are_configured" do
  title "Ensure password creation requirements are configured"
  desc  "The pam_pwquality.so module checks the strength of passwords. It performs checks such as making sure a password is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. The following are definitions of the  pam_pwquality.so options.\n               \n                  \n                      try_first_pass - retrieve the password from a previous stacked PAM module. If not available, then prompt the user for a password.\n                        \n                           \n                        \n                     \n                  \n                  \n                      retry=3 - Allow 3 tries before sending back a failure.\n                The following options are set in the /etc/security/pwquality.conf file:\n               \n                   minlen=14 - password must be 14 characters or more\n                   dcredit=-1 - provide at least one digit\n                   ucredit=-1 - provide at least one uppercase character\n                   ocredit=-1 - provide at least one special character\n                   lcredit=-1 - provide at least one lowercase character\n               \n                 The settings shown above are one possible policy. Alter these values to conform to your own organization's password policies.\n\nRationale: Strong passwords protect systems from being hacked through brute force methods."
  impact 1.0
  describe file("/etc/pam.d/common-password") do
    its("content") { should match(/^\s*password\s+requisite\s+pam_pwquality\.so\s+(\S+\s+)*try_first_pass/) }
  end
  describe file("/etc/pam.d/common-password") do
    its("content") { should match(/^\s*password\s+requisite\s+pam_pwquality\.so\s+(\S+\s+)*retry=[3210]/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*minlen\s*=\s*(1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\s*(\s+#.*)?$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*dcredit\s*=\s*-[1-9][0-9]*\s*(\s+#.*)?$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*lcredit\s*=\s*-[1-9][0-9]*\s*(\s+#.*)?$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*ucredit\s*=\s*-[1-9][0-9]*\s*(\s+#.*)?$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*ocredit\s*=\s*-[1-9][0-9]*\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3.2_Ensure_lockout_for_failed_password_attempts_is_configured" do
  title "Ensure lockout for failed password attempts is configured"
  desc  "Lock out users after n unsuccessful consecutive login attempts. The first sets of changes are made to the PAM configuration files. The second set of changes are applied to the program specific PAM configuration file. The second set of changes must be applied to each program that will lock out users. Check the documentation for each secondary program for instructions on how to configure them to work with PAM. Set the lockout number to the policy in effect at your site.\n\nRationale: Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3.3_Ensure_password_reuse_is_limited" do
  title "Ensure password reuse is limited"
  desc  "The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords.\n\nRationale: Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password. Note that these change only apply to accounts configured on the local system."
  impact 1.0
  describe file("/etc/pam.d/common-password") do
    its("content") { should match(/^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*remember=([56789]|[1-9][0-9]+)/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3.4_Ensure_password_hashing_algorithm_is_SHA-512" do
  title "Ensure password hashing algorithm is SHA-512"
  desc  "The commands below change password encryption from md5 to sha512 (a much stronger hashing algorithm). All existing accounts will need to perform a password change to upgrade the stored hashes to the new algorithm.\n\nRationale: The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by increasing the level of effort for an attacker to successfully determine passwords. Note that these change only apply to accounts configured on the local system."
  impact 1.0
  describe file("/etc/pam.d/common-password") do
    its("content") { should match(/^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.1.1_Ensure_password_expiration_is_90_days_or_less" do
  title "Ensure password expiration is 90 days or less"
  desc  "The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age. It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 90 days.\n\nRationale: The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity."
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MAX_DAYS\s+(90|[1-8][0-9]|[1-9])\s*(\s+#.*)?$/) }
  end
  shadow.users(/.+/).entries.each do |entry|
    describe.one do
      describe entry do
        its("passwords") { should_not cmp(/^[^!*]/) }
      end
      describe entry do
        its("max_days") { should_not cmp > 90 }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.1.2_Ensure_minimum_days_between_password_changes_is_7_or_more" do
  title "Ensure minimum days between password changes is 7 or more"
  desc  "The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to prevent users from changing their password until a minimum number of days have passed since the last time the user changed their password. It is recommended that PASS_MIN_DAYS parameter be set to 7 or more days.\n\nRationale: By restricting the frequency of password changes, an administrator can prevent users from repeatedly changing their password in an attempt to circumvent password reuse controls."
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MIN_DAYS\s+([789]|[1-9][0-9]+)\s*(\s+#.*)?$/) }
  end
  shadow.users(/.+/).entries.each do |entry|
    describe.one do
      describe entry do
        its("passwords") { should_not cmp(/^[^!*]/) }
      end
      describe entry do
        its("min_days") { should_not cmp < 7 }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.1.3_Ensure_password_expiration_warning_days_is_7_or_more" do
  title "Ensure password expiration warning days is 7 or more"
  desc  "The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users that their password will expire in a defined number of days. It is recommended that the PASS_WARN_AGE parameter be set to 7 or more days.\n\nRationale: Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered."
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_WARN_AGE\s+([789]|[1-9][0-9]+)\s*(\s+#.*)?$/) }
  end
  shadow.users(/.+/).entries.each do |entry|
    describe.one do
      describe entry do
        its("passwords") { should_not cmp(/^[^!*]/) }
      end
      describe entry do
        its("warn_days") { should_not cmp < 7 }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.1.4_Ensure_inactive_password_lock_is_30_days_or_less" do
  title "Ensure inactive password lock is 30 days or less"
  desc  "User accounts that have been inactive for over a given period of time can be automatically disabled. It is recommended that accounts that are inactive for 30 days after password expiration be disabled.\n\nRationale: Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies."
  impact 1.0
  describe file("/etc/default/useradd") do
    its("content") { should match(/^\s*INACTIVE\s*=\s*(30|[1-2][0-9]|[1-9])\s*(\s+#.*)?$/) }
  end
  shadow.users(/.+/).entries.each do |entry|
    describe.one do
      describe entry do
        its("passwords") { should_not cmp(/^[^!*]/) }
      end
      describe entry do
        its("inactive_days") { should_not cmp > 30 }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.2_Ensure_system_accounts_are_non-login" do
  title "Ensure system accounts are non-login"
  desc  "There are a number of accounts provided with Ubuntu that are used to manage applications and are not intended to provide an interactive shell.\n\nRationale: It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, Ubuntu sets the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to /sbin/nologin. This prevents the account from potentially being used to run any commands."
  impact 1.0
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ } do
    its("entries") { should_not be_empty }
  end
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ && uid.to_i < 1000 && shell != "/usr/sbin/nologin" } do
    its("entries") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.3_Ensure_default_group_for_the_root_account_is_GID_0" do
  title "Ensure default group for the root account is GID 0"
  desc  "The usermod command can be used to specify which group the root user belongs to. This affects permissions of files that are created by the root user.\n\nRationale: Using GID 0 for the  root account helps prevent  root -owned files from accidentally becoming accessible to non-privileged users."
  impact 1.0
  describe passwd.where { user == "root" } do
    its("entries") { should_not be_empty }
  end
  describe passwd.where { user == "root" && gid.to_i == 0 } do
    its("entries") { should_not be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.4_Ensure_default_user_umask_is_027_or_more_restrictive" do
  title "Ensure default user umask is 027 or more restrictive"
  desc  "The default umask determines the permissions of files created by users. The user creating the file has the discretion of making their files and directories readable by others via the chmod command. Users who wish to allow their files and directories to be readable by others by default may choose a different default umask by inserting the umask command into the standard shell configuration files (.profile, .bashrc, etc.) in their home directories.\n\nRationale: Setting a very secure default value for umask ensures that users make a conscious choice about their file permissions. A default umask setting of 077 causes files and directories created by users to not be readable by any other user on the system. A umask of 027 would make files and directories readable by users in the same Unix group, while a umask of 022 would make files readable by every user on the system."
  impact 1.0
  describe file("/etc/bash.bashrc") do
    its("content") { should match(/^\s*umask\s+[01234567][2367]7\s*(\s+#.*)?$/) }
  end
  describe file("/etc/bash.bashrc") do
    its("content") { should_not match(/^\s*umask\s+[01234567](0[7654321]|[7654321][654321])\s*(\s+#.*)?$/) }
  end
  describe file("/etc/profile") do
    its("content") { should match(/^\s*umask\s+[01234567][2367]7\s*(\s+#.*)?$/) }
  end
  describe file("/etc/profile") do
    its("content") { should_not match(/^\s*umask\s+[01234567](0[7654321]|[7654321][654321])\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5_Ensure_root_login_is_restricted_to_system_console" do
  title "Ensure root login is restricted to system console"
  desc  "The file /etc/securetty contains a list of valid terminals that may be logged in directly as root.\n\nRationale: Since the system console has special properties to handle emergency situations, it is important to ensure that the console is in a physically secure location and that unauthorized consoles have not been defined."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_5.6_Ensure_access_to_the_su_command_is_restricted" do
  title "Ensure access to the su command is restricted"
  desc  "The su command allows a user to run a command or shell as another user. The program has been superseded by sudo, which allows for more granular control over privileged access. Normally, the su command can be executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su, the su command will only allow users in the wheel group to execute su.\n\nRationale: Restricting the use of su, and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via sudo, whereas su can only record that a user executed the su program."
  impact 1.0
  describe file("/etc/pam.d/su") do
    its("content") { should match(/^\s*auth\s+required\s+pam_wheel.so\s+use_uid\s*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.1_Audit_system_file_permissions" do
  title "Audit system file permissions"
  desc  "The Debian package manager has a number of useful options. One of these, the --verify option, can be used to verify that system packages are correctly installed. The --verify option can be used to verify a particular package or to verify all system packages. If no output is returned, the package is installed correctly. The following table describes the meaning of output from the verify option: Code MeaningS File size differs.M File mode differs (includes permissions and file type).5 The MD5 checksum differs.D The major and minor version numbers differ on a device file.L A mismatch occurs in a link.U The file ownership differs.G The file group owner differs.T The file time (mtime) differs. The dpkg -S command can be used to determine which package a particular file belongs to. For example the following commands determines which package the /bin/bash file belongs to:\n                # dpkg -S /bin/bashbash: /bin/bash\n                To verify the settings for the package that controls the /bin/bash file, run the following: # dpkg --verify bash??5?????? c /etc/bash.bashrc\n\nRationale: It is important to confirm that packaged system files and directories are maintained with the permissions they were intended to have from the OS vendor."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.2_Ensure_permissions_on_etcpasswd_are_configured" do
  title "Ensure permissions on /etc/passwd are configured"
  desc  "The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate.\n\nRationale: It is critical to ensure that the /etc/passwd file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/passwd") do
    it { should exist }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/passwd") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/passwd") do
    its("sgid") { should equal false }
  end
  describe file("/etc/passwd") do
    its("sticky") { should equal false }
  end
  describe file("/etc/passwd") do
    its("suid") { should equal false }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/passwd") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/passwd") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.3_Ensure_permissions_on_etcshadow_are_configured" do
  title "Ensure permissions on /etc/shadow are configured"
  desc  "The /etc/shadow file is used to store the information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the user accounts."
  impact 1.0
  describe file("/etc/shadow") do
    it { should exist }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/shadow") do
    its("gid") { should cmp 42 }
  end
  describe file("/etc/shadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/shadow") do
    its("sgid") { should equal false }
  end
  describe file("/etc/shadow") do
    its("sticky") { should equal false }
  end
  describe file("/etc/shadow") do
    its("suid") { should equal false }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/shadow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.4_Ensure_permissions_on_etcgroup_are_configured" do
  title "Ensure permissions on /etc/group are configured"
  desc  "The /etc/group file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else.\n\nRationale: The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs."
  impact 1.0
  describe file("/etc/group") do
    it { should exist }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/group") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/group") do
    its("sgid") { should equal false }
  end
  describe file("/etc/group") do
    its("sticky") { should equal false }
  end
  describe file("/etc/group") do
    its("suid") { should equal false }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/group") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/group") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.5_Ensure_permissions_on_etcgshadow_are_configured" do
  title "Ensure permissions on /etc/gshadow are configured"
  desc  "The /etc/gshadow file is used to store the information about groups that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/gshadow file (such as group administrators) could also be useful to subvert the group."
  impact 1.0
  describe file("/etc/gshadow") do
    it { should exist }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/gshadow") do
    its("gid") { should cmp 42 }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/gshadow") do
    its("sgid") { should equal false }
  end
  describe file("/etc/gshadow") do
    its("sticky") { should equal false }
  end
  describe file("/etc/gshadow") do
    its("suid") { should equal false }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/gshadow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.6_Ensure_permissions_on_etcpasswd-_are_configured" do
  title "Ensure permissions on /etc/passwd- are configured"
  desc  "The /etc/passwd- file contains backup user account information.\n\nRationale: It is critical to ensure that the /etc/passwd- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/passwd-") do
    it { should exist }
  end
  describe file("/etc/passwd-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/passwd-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/passwd-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/passwd-") do
    its("sgid") { should equal false }
  end
  describe file("/etc/passwd-") do
    its("sticky") { should equal false }
  end
  describe file("/etc/passwd-") do
    its("suid") { should equal false }
  end
  describe file("/etc/passwd-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/passwd-") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.7_Ensure_permissions_on_etcshadow-_are_configured" do
  title "Ensure permissions on /etc/shadow- are configured"
  desc  "The  /etc/shadow-  file is used to store backup information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/shadow-") do
    it { should exist }
  end
  describe file("/etc/shadow-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/shadow-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/shadow-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/shadow-") do
    its("sgid") { should equal false }
  end
  describe file("/etc/shadow-") do
    its("sticky") { should equal false }
  end
  describe file("/etc/shadow-") do
    its("suid") { should equal false }
  end
  describe file("/etc/shadow-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/shadow-") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.8_Ensure_permissions_on_etcgroup-_are_configured" do
  title "Ensure permissions on /etc/group- are configured"
  desc  "The /etc/group- file contains a backup list of all the valid groups defined in the system.\n\nRationale: It is critical to ensure that the /etc/group- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/group-") do
    it { should exist }
  end
  describe file("/etc/group-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/group-") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/group-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/group-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/group-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/group-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/group-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/group-") do
    its("sgid") { should equal false }
  end
  describe file("/etc/group-") do
    its("sticky") { should equal false }
  end
  describe file("/etc/group-") do
    its("suid") { should equal false }
  end
  describe file("/etc/group-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/group-") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.9_Ensure_permissions_on_etcgshadow-_are_configured" do
  title "Ensure permissions on /etc/gshadow- are configured"
  desc  "The /etc/gshadow- file is used to store backup information about groups that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/gshadow-") do
    it { should exist }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/gshadow-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/gshadow-") do
    its("sgid") { should equal false }
  end
  describe file("/etc/gshadow-") do
    its("sticky") { should equal false }
  end
  describe file("/etc/gshadow-") do
    its("suid") { should equal false }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/gshadow-") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.10_Ensure_no_world_writable_files_exist" do
  title "Ensure no world writable files exist"
  desc  "Unix-based systems support variable settings to control access to files. World writable files are the least secure. See the chmod(2) man page for more information.\n\nRationale: Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity."
  impact 1.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.11_Ensure_no_unowned_files_or_directories_exist" do
  title "Ensure no unowned files or directories exist"
  desc  "Sometimes when administrators delete users from the password file they neglect to remove all files owned by those users from the system.\n\nRationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended."
  impact 1.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.12_Ensure_no_ungrouped_files_or_directories_exist" do
  title "Ensure no ungrouped files or directories exist"
  desc  "Sometimes when administrators delete users or groups from the system they neglect to remove all files owned by those users or groups.\n\nRationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended."
  impact 1.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.13_Audit_SUID_executables" do
  title "Audit SUID executables"
  desc  "The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SUID program is to enable users to perform functions (such as changing their password) that require root privileges.\n\nRationale: There are valid reasons for SUID programs, but it is important to identify and review such programs to ensure they are legitimate."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.14_Audit_SGID_executables" do
  title "Audit SGID executables"
  desc  "The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SGID program is to enable users to perform functions (such as changing their password) that require root privileges.\n\nRationale: There are valid reasons for SGID programs, but it is important to identify and review such programs to ensure they are legitimate. Review the files returned by the action in the audit section and check to see if system binaries have a different md5 checksum than what from the package. This is an indication that the binary may have been replaced."
  impact 0.0
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.1_Ensure_password_fields_are_not_empty" do
  title "Ensure password fields are not empty"
  desc  "An account with an empty password field means that anybody may log in as that user without providing a password.\n\nRationale: All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user."
  impact 1.0
  shadow.users(/.+/).entries.each do |entry|
    describe entry do
      its("passwords") { should cmp(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.2_Ensure_no_legacy__entries_exist_in_etcpasswd" do
  title "Ensure no legacy \"+\" entries exist in /etc/passwd"
  desc  "The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.\n\nRationale: These entries may provide an avenue for attackers to gain privileged access on the system."
  impact 1.0
  describe file("/etc/passwd") do
    its("content") { should_not match(/^\+:/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.3_Ensure_no_legacy__entries_exist_in_etcshadow" do
  title "Ensure no legacy \"+\" entries exist in /etc/shadow"
  desc  "The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.\n\nRationale: These entries may provide an avenue for attackers to gain privileged access on the system."
  impact 1.0
  describe file("/etc/shadow") do
    its("content") { should_not match(/^\+:/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.4_Ensure_no_legacy__entries_exist_in_etcgroup" do
  title "Ensure no legacy \"+\" entries exist in /etc/group"
  desc  "The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.\n\nRationale: These entries may provide an avenue for attackers to gain privileged access on the system."
  impact 1.0
  describe file("/etc/group") do
    its("content") { should_not match(/^\+:/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.5_Ensure_root_is_the_only_UID_0_account" do
  title "Ensure root is the only UID 0 account"
  desc  "Any account with UID 0 has superuser privileges on the system.\n\nRationale: This access must be limited to only the default root account and only from the system console. Administrative access must be through an unprivileged account using an approved mechanism as noted in Item 5.6 Ensure access to the su command is restricted."
  impact 1.0
  describe file("/etc/passwd") do
    its("content") { should_not match(/^(?!root:)[^:]*:[^:]*:0/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.6_Ensure_root_PATH_Integrity" do
  title "Ensure root PATH Integrity"
  desc  "The root user can execute any command on the system and could be fooled into executing programs unintentionally if the PATH is not set correctly.\n\nRationale: Including the current working directory (.) or other writable directory in root's executable path makes it likely that an attacker can gain superuser access by forcing an administrator operating as root to execute a Trojan horse program."
  impact 1.0
  describe os_env("PATH").content.to_s.split(":") do
    it { should_not be_empty }
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe entry do
      it { should_not eq "" }
    end
  end
  describe os_env("PATH").content.to_s.split(":") do
    it { should_not be_empty }
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe entry do
      it { should_not eq "." }
    end
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe file(entry) do
      it { should exist }
    end
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
    describe file(entry) do
      its("uid") { should cmp 0 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.7_Ensure_all_users_home_directories_exist" do
  title "Ensure all users' home directories exist"
  desc  "Users can be defined in /etc/passwd without a home directory or with a home directory that does not actually exist.\n\nRationale: If the user's home directory does not exist or is unassigned, the user will be placed in \"/\" and will not be able to write any files or have local environment variables set."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.each do |entry|
    describe file(entry) do
      it { should exist }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.8_Ensure_users_home_directories_permissions_are_750_or_more_restrictive" do
  title "Ensure users' home directories permissions are 750 or more restrictive"
  desc  "While the system administrator can establish secure permissions for users' home directories, the users can easily override these.\n\nRationale: Group or world-writable user home directories may enable malicious users to steal or modify other users' data or to gain another user's system privileges."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.each do |entry|
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_executable.by "other" }
    end
    describe file(entry) do
      it { should_not be_readable.by "other" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.9_Ensure_users_own_their_home_directories" do
  title "Ensure users own their home directories"
  desc  "The user home directory is space defined for the particular user to set local environment variables and to store personal files.\n\nRationale: Since the user is accountable for files stored in the user home directory, the user must be the owner of the directory."
  impact 1.0
  a = command("cat /etc/passwd | awk -F: '{ print $1 \" \" $3 \" \" $6 }' | while read user uid dir; do if [ $uid -ge 1000 -a -d \"$dir\" -a $user != \"nfsnobody\" ]; then owner=$(stat -L -c \"%U\" \"$dir\"); if [ \"$owner\" != \"$user\" ]; then echo \"The home directory ($dir) of user $user is owned by $owner.\"; fi; fi; done").stdout.scan(/.+/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.10_Ensure_users_dot_files_are_not_group_or_world_writable" do
  title "Ensure users' dot files are not group or world writable"
  desc  "While the system administrator can establish secure permissions for users' \"dot\" files, the users can easily override these.\n\nRationale: Group or world-writable user configuration files may enable malicious users to steal or modify other users' data or to gain another user's system privileges."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| command("find #{x} -maxdepth 1 -type f -regex '.*/\..+'").stdout.split }.flatten.each do |entry|
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.11_Ensure_no_users_have_.forward_files" do
  title "Ensure no users have .forward files"
  desc  "The .forward file specifies an email address to forward the user's mail to.\n\nRationale: Use of the .forward file poses a security risk in that sensitive data may be inadvertently transferred outside the organization. The .forward file also poses a risk as it can be used to execute commands that may perform unintended actions."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".forward"}.each do |entry|
    describe file(entry) do
      it { should_not exist }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.12_Ensure_no_users_have_.netrc_files" do
  title "Ensure no users have .netrc files"
  desc  "The .netrc file contains data for logging into a remote host for file transfers via FTP.\n\nRationale: The .netrc file presents a significant security risk since it stores passwords in unencrypted form. Even if FTP is disabled, user accounts may have brought over .netrc files from other systems which could pose a risk to those systems."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".netrc"}.each do |entry|
    describe file(entry) do
      it { should_not exist }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.13_Ensure_users_.netrc_Files_are_not_group_or_world_accessible" do
  title "Ensure users' .netrc Files are not group or world accessible"
  desc  "While the system administrator can establish secure permissions for users' .netrc files, the users can easily override these.\n\nRationale: .netrc files may contain unencrypted passwords that may be used to attack other systems."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".netrc"}.each do |entry|
    describe file(entry) do
      it { should_not be_executable.by "group" }
    end
    describe file(entry) do
      it { should_not be_readable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_executable.by "other" }
    end
    describe file(entry) do
      it { should_not be_readable.by "other" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.14_Ensure_no_users_have_.rhosts_files" do
  title "Ensure no users have .rhosts files"
  desc  "While no .rhosts files are shipped by default, users can easily create them.\n\nRationale: This action is only meaningful if .rhosts support is permitted in the file /etc/pam.conf. Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf, they may have been brought over from other systems and could contain information useful to an attacker for those other systems."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".rhosts"}.each do |entry|
    describe file(entry) do
      it { should_not exist }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.15_Ensure_all_groups_in_etcpasswd_exist_in_etcgroup" do
  title "Ensure all groups in /etc/passwd exist in /etc/group"
  desc  "Over time, system administration errors and changes can lead to groups being defined in /etc/passwd but not in /etc/group.\n\nRationale: Groups defined in the /etc/passwd file but not in the /etc/group file pose a threat to system security since group permissions are not properly managed."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.gids.map { |x| "^[^:]*:[^:]*:" + x.to_s }.map { |x| x.to_s + ":[^:]*$" }.each do |entry|
    describe file("/etc/group") do
      its("content") { should match Regexp.new(entry) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.16_Ensure_no_duplicate_UIDs_exist" do
  title "Ensure no duplicate UIDs exist"
  desc  "Although the useradd program will not let you create a duplicate User ID (UID), it is possible for an administrator to manually edit the /etc/passwd file and change the UID field.\n\nRationale: Users must be assigned unique UIDs for accountability and to ensure appropriate access protections."
  impact 1.0
  describe passwd.where { user =~ /.*/ }.uids do
    its("length") { should_not eq 0 }
  end
  a = passwd.where { user =~ /.*/ }.uids.uniq.length
  describe passwd.where { user =~ /.*/ }.uids do
    its("length") { should cmp == a }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.17_Ensure_no_duplicate_GIDs_exist" do
  title "Ensure no duplicate GIDs exist"
  desc  "Although the groupadd program will not let you create a duplicate Group ID (GID), it is possible for an administrator to manually edit the /etc/group file and change the GID field.\n\nRationale: User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections."
  impact 1.0
  describe file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten do
    its("length") { should_not eq 0 }
  end
  a = file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten.uniq.length
  describe file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten do
    its("length") { should cmp == a }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.18_Ensure_no_duplicate_user_names_exist" do
  title "Ensure no duplicate user names exist"
  desc  "Although the useradd program will not let you create a duplicate user name, it is possible for an administrator to manually edit the /etc/passwd file and change the user name.\n\nRationale: If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in /etc/passwd. For example, if \"test4\" has a UID of 1000 and a subsequent \"test4\" entry has a UID of 2000, logging in as \"test4\" will use UID 1000. Effectively, the UID is shared, which is a security problem."
  impact 1.0
  describe file("/etc/passwd").content.to_s.scan(/^([^:]+):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$/).flatten do
    its("length") { should_not eq 0 }
  end
  a = file("/etc/passwd").content.to_s.scan(/^([^:]+):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$/).flatten.uniq.length
  describe file("/etc/passwd").content.to_s.scan(/^([^:]+):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$/).flatten do
    its("length") { should cmp == a }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.19_Ensure_no_duplicate_group_names_exist" do
  title "Ensure no duplicate group names exist"
  desc  "Although the groupadd program will not let you create a duplicate group name, it is possible for an administrator to manually edit the /etc/group file and change the group name.\n\nRationale: If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in /etc/group. Effectively, the GID is shared, which is a security problem."
  impact 1.0
  describe file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten do
    its("length") { should_not eq 0 }
  end
  a = file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten.uniq.length
  describe file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten do
    its("length") { should cmp == a }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.20_Ensure_shadow_group_is_empty" do
  title "Ensure shadow group is empty"
  desc  "The shadow group allows system programs which require access the ability to read the /etc/shadow file. No users should be assigned to the shadow group.\n\nRationale: Any users assigned to the shadow group would be granted read access to the /etc/shadow file. If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed passwords to break them. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert additional user accounts."
  impact 1.0
  describe file("/etc/group") do
    its("content") { should_not match(/^shadow:[^:]*:[^:]*:[^:]+$/) }
  end
end
