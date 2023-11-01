%define kmod_name		iwlwifi
%define kmod_vendor		redhat
%define kmod_driver_version	4.18.0_107_dup8.0
%define kmod_driver_epoch	%{nil}
%define kmod_rpm_release	5
%define kmod_kernel_version	4.18.0-80.el8
%define kmod_kernel_version_min	%{nil}
%define kmod_kernel_version_dep	%{nil}
%define kmod_kbuild_dir		drivers/net/wireless/intel/iwlwifi
%define kmod_dependencies       (dracut >= 049-10.git20190115.el8_0.1 if kernel > 4.18.0-80.el8)
%define kmod_dist_build_deps	%{nil}
%define kmod_build_dependencies	%{nil}
%define kmod_devel_package	1
%define kmod_install_path	extra/kmod-redhat-iwlwifi
%define kernel_pkg		kernel
%define kernel_devel_pkg	kernel-devel
%define kernel_modules_pkg	kernel-modules

%{!?dist: %define dist .el8_0}
%{!?make_build: %define make_build make}

%if "%{kmod_kernel_version_dep}" == ""
%define kmod_kernel_version_dep %{kmod_kernel_version}
%endif

%if "%{kmod_dist_build_deps}" == ""
%if (0%{?rhel} > 7) || (0%{?centos} > 7)
%define kmod_dist_build_deps redhat-rpm-config kernel-abi-whitelists elfutils-libelf-devel kernel-rpm-macros kmod
%else
%define kmod_dist_build_deps redhat-rpm-config kernel-abi-whitelists
%endif
%endif

Source0:	%{kmod_name}-%{kmod_vendor}-%{kmod_driver_version}.tar.bz2
# Source code patches
Patch0:	0001-Revert-netlink-make-validation-more-configurable-for.patch
Patch1:	0002-Revert-iwlwifi-mvm-fix-merge-damage-in-iwl_mvm_vif_d.patch
Patch2:	0003-Revert-iwlwifi-mvm-fix-pointer-reference-when-settin.patch
Patch3:	0004-Revert-iwlwifi-remove-unnecessary-goto-out-in-iwl_pa.patch
Patch4:	0005-Revert-iwlwifi-Use-struct_size-in-kzalloc.patch
Patch5:	0006-Revert-mac80211-update-HE-IEs-to-D3.3.patch
Patch6:	0007-Revert-iwlwifi-mvm-report-FTM-start-time-TSF-when-ap.patch
Patch7:	0008-Revert-iwlwifi-mvm-support-rtt-confidence-indication.patch
Patch8:	0009-Revert-iwlwifi-fix-64-bit-division.patch
Patch9:	0010-Revert-iwlwifi-mvm-add-debug-prints-for-FTM.patch
Patch10:	0011-Revert-iwlwifi-mvm-add-support-for-new-FTM-fw-API.patch
Patch11:	0012-Revert-iwlwifi-mvm-support-FTM-initiator.patch
Patch12:	0013-Revert-iwlwifi-mvm-support-FTM-responder.patch
Patch13:	0014-Revert-iwlwifi-mvm-support-HE-context-cmd-API-change.patch
Patch14:	0015-Revert-iwlwifi-mvm-support-multiple-BSSID.patch
Patch15:	0016-Revert-iwlwifi-mvm-advertise-support-for-TWT-in-the-.patch
Patch16:	0017-Revert-iwlwifi-mvm-limit-AMSDU-size-to-8K.patch
Patch17:	0018-Revert-iwlwifi-mvm-bring-back-mvm-GSO-code.patch
Patch18:	0019-Revert-iwlwifi-mvm-support-mac80211-AMSDU.patch
Patch19:	0020-Revert-iwlwifi-mvm-remove-redundant-condition.patch
Patch20:	0021-Revert-iwlwifi-mvm-stop-static-queues-correctly.patch
Patch21:	0022-Revert-iwlwifi-mvm-remove-buggy-and-unnecessary-hw_q.patch
Patch22:	0023-Revert-iwlwifi-mvm-support-mac80211-TXQs-model.patch
Patch23:	0024-Revert-iwlwifi-nvm-parse-advertise-IEEE80211_VHT_EXT.patch
Patch24:	0025-Revert-iwlwifi-mvm-set-HW-capability-VHT_EXT_NSS_BW.patch
Patch25:	0026-Revert-iwlwifi-mvm-config-mac-ctxt-to-HE-before-TLC.patch
Patch26:	0027-Revert-iwlwifi-mvm-send-the-STA_HE_CTXT-command-in-A.patch
Patch27:	0028-Revert-iwlwifi-trust-calling-function.patch
Patch28:	0029-Revert-iwlwifi-split-HE-capabilities-between-AP-and-.patch
Patch29:	0030-Revert-wireless-align-to-draft-11ax-D3.0.patch
Patch30:	0031-Revert-iwlwifi-add-module-parameter-to-disable-802.1.patch
Patch31:	0032-Revert-iwlwifi-mvm-limit-TLC-according-to-our-HE-cap.patch
Patch32:	0033-Revert-iwlwifi-rs-consider-LDPC-capability-in-case-o.patch
Patch33:	0034-Revert-iwlwifi-mvm-fix-HE-radiotap-data4-for-HE-TB-P.patch
Patch34:	0035-Revert-iwlwifi-mvm-radiotap-remove-UL_DL-bit-in-HE-T.patch
Patch35:	0036-Revert-iwlwifi-mvm-report-all-NO_DATA-events-to-mac8.patch
Patch36:	0037-Revert-iwlwifi-mvm-fix-the-spatial-reuse-parsing-for.patch
Patch37:	0038-Revert-iwlwifi-mvm-clean-up-NO_PSDU-case.patch
Patch38:	0039-Revert-iwlwifi-mvm-don-t-hide-HE-radiotap-data-in-SK.patch
Patch39:	0040-Revert-iwlwifi-mvm-add-HE-TB-PPDU-SIG-A-BW-to-radiot.patch
Patch40:	0041-Revert-iwlwifi-iwlmvm-ignore-HE-PPDU-type-regarding-.patch
Patch41:	0042-Revert-iwlwifi-mvm-add-L-SIG-length-to-radiotap.patch
Patch42:	0043-Revert-iwlwifi-mvm-change-PHY-data-RX-for-HE-radiota.patch
Patch43:	0044-Revert-iwlwifi-mvm-remove-set-but-not-used-variable-.patch
Patch44:	0045-Revert-iwlwifi-mvm-show-more-HE-radiotap-data-for-TB.patch
Patch45:	0046-Revert-iwlwifi-mvm-decode-HE-information-for-MU-with.patch
Patch46:	0047-Revert-iwlwifi-mvm-add-more-information-to-HE-radiot.patch
Patch47:	0048-Revert-iwlwifi-mvm-add-LDPC-XSYM-to-HE-radiotap-data.patch
Patch48:	0049-Revert-iwlwifi-mvm-add-TXOP-to-HE-radiotap-data.patch
Patch49:	0050-Revert-iwlwifi-mvm-move-HE-MU-LTF_NUM-parsing-to-he_.patch
Patch50:	0051-Revert-iwlwifi-mvm-clean-up-HE-radiotap-RU-allocatio.patch
Patch51:	0052-Revert-iwlwifi-mvm-pull-some-he_phy_data-decoding-in.patch
Patch52:	0053-Revert-iwlwifi-mvm-put-HE-SIG-B-symbols-users-data-c.patch
Patch53:	0054-Revert-iwlwifi-mvm-minor-cleanups-to-HE-radiotap-cod.patch
Patch54:	0055-Revert-iwlwifi-mvm-remove-unnecessary-overload-varia.patch
Patch55:	0056-Revert-iwlwifi-mvm-report-RU-offset-is-known.patch
Patch56:	0057-Revert-iwlwifi-mvm-decode-HE-TB-PPDU-data.patch
Patch57:	0058-Revert-iwlwifi-mvm-remove-channel-2-from-HE-radiotap.patch
Patch58:	0059-Revert-iwlwifi-mvm-report-of-LTF-symbols-for-extende.patch
Patch59:	0060-Revert-iwlwifi-mvm-properly-decode-HE-GI-duration.patch
Patch60:	0061-Revert-iwlwifi-mvm-put-LTF-symbol-size-into-HE-radio.patch
Patch61:	0062-Revert-iwlwifi-RX-API-remove-unnecessary-anonymous-s.patch
Patch62:	0063-Revert-iwlwifi-mvm-implement-extended-HE-MU-sniffer-.patch
Patch63:	0064-Revert-iwlwifi-mvm-move-he-RX-handling-to-a-separate.patch
Patch64:	0065-Revert-iwlwifi-iwlmvm-fix-typo-when-checking-for-TX-.patch
Patch65:	0066-Revert-iwlwifi-mvm-move-he-RX-handling-to-a-separate.patch
Patch66:	0067-Revert-iwlwifi-mvm-add-support-for-RX_AMPDU_EOF-bit-.patch
Patch67:	0068-Revert-iwlwifi-mvm-add-bss-color-to-radiotap.patch
Patch68:	0069-Revert-iwlwifi-support-new-rx_mpdu_desc-api.patch
Patch69:	0070-Revert-iwlwifi-mvm-add-radiotap-data-for-HE.patch
Patch70:	0071-Revert-iwlwifi-mvm-set-MAC_FILTER_IN_11AX-in-AP-mode.patch
Patch71:	0072-Revert-iwlwifi-add-support-for-IEEE802.11ax.patch
Patch72:	0073-Revert-iwlwifi-mvm-update-firmware-when-MU-EDCA-para.patch
Patch73:	0074-Revert-iwlwifi-mvm-report-delayed-beacon-count-to-FW.patch
Patch74:	0075-Revert-iwlwifi-mvm-track-changes-in-beacon-count-dur.patch
Patch75:	0076-Revert-iwlwifi-mvm-disconnect-in-case-of-bad-channel.patch
Patch76:	0077-Revert-iwlwifi-mvm-notify-FW-on-quiet-mode-in-CSA.patch
Patch77:	0078-Revert-iwlwifi-mvm-track-CSA-beacons.patch
Patch78:	0079-Revert-iwlwifi-mvm-implement-CSA-abort.patch
Patch79:	0080-Revert-iwlwifi-nvm-parse-use-struct_size-in-kzalloc.patch
Patch80:	0081-Revert-iwlwifi-support-new-NVM-response-API.patch
Patch81:	0082-Revert-iwlwifi-add-support-for-6-7-GHz-channels.patch
Patch82:	0083-Revert-iwlwifi-use-kmemdup-in-iwl_parse_nvm_mcc_info.patch
Patch83:	0084-Revert-cfg80211-make-wmm_rule-part-of-the-reg_rule-s.patch
Patch84:	0085-Revert-iwlwifi-Use-correct-channel_profile-iniwl_get.patch
Patch85:	0086-Revert-iwlwifi-mvm-report-all-NO_DATA-events-to-mac8.patch
Patch86:	0087-Revert-iwlwifi-mvm-add-read-debugfs-for-he_sniffer_p.patch
Patch87:	0088-Revert-iwlwifi-mvm-include-configured-sniffer-AID-in.patch
Patch88:	0089-Revert-iwlwifi-mvm-implement-CSI-reporting.patch
Patch89:	0090-Revert-iwlwifi-iwlmvm-in-monitor-NDP-notif-take-the-.patch
Patch90:	0091-Revert-iwlwifi-mvm-handle-RX-no-data-notification.patch
Patch91:	0092-Revert-iwlwifi-mvm-fix-merge-damage-in-iwl_mvm_rx_mp.patch
Patch92:	0093-Revert-iwlwifi-mvm-implement-VHT-extended-NSS-suppor.patch
Patch93:	0094-Revert-iwlwifi-fw-do-not-set-sgi-bits-for-HE-connect.patch
Patch94:	0095-Revert-iwlwifi-mvm-fix-wrong-DCM-TLC-config.patch
Patch95:	0096-Revert-iwlwifi-rs-fw-support-dcm.patch
Patch96:	0097-Revert-iwlwifi-rs-fw-enable-STBC-in-he-correctly.patch
Patch97:	0000-add-back-rate_name-items-rs_sta_dbgfs_drv_tx_stats_read.patch
Patch98:	0000-add-iwlwifi_backport_compat-h.patch
Patch99:	0000-bump-module-version.patch
Patch100:	0000-define-IEEE80211_MAX_AMPDU_BUF_HT.patch
Patch101:	0000-fixup-firmware-modinfo.patch
Patch102:	0000-no-cap_he-check-iwl_mvm_max_amsdu_size.patch
Patch103:	0000-use-DUP-firmware-files.patch
Patch104:	_RHEL8_PATCH_17-45_iwlwifi_mvm_remove_d3_sram_debugfs_file.patch
Patch105:	_RHEL8_PATCH_18-45_iwlwifi_fix_load_in_rfkill_flow_for_unified_firmwar.patch
Patch106:	_RHEL8_PATCH_19-45_iwlwifi_clear_persistence_bit_according_to_device_f.patch
Patch107:	_RHEL8_PATCH_20-45_iwlwifi_print_fseq_info_upon_fw_assert.patch
Patch108:	_RHEL8_PATCH_21-45_iwlwifi_fix_AX201_killer_sku_loading_firmware_issue.patch
Patch109:	_RHEL8_PATCH_22-45_iwlwifi_Fix_double-free_problems_in_iwl_req_fw_call.patch
Patch110:	_RHEL8_PATCH_23-45_iwlwifi_mvm_change_TLC_config_cmd_sent_by_rs_to_be_.patch

%define findpat %( echo "%""P" )
%define __find_requires /usr/lib/rpm/redhat/find-requires.ksyms
%define __find_provides /usr/lib/rpm/redhat/find-provides.ksyms %{kmod_name} %{?epoch:%{epoch}:}%{version}-%{release}
%define sbindir %( if [ -d "/sbin" -a \! -h "/sbin" ]; then echo "/sbin"; else echo %{_sbindir}; fi )
%define dup_state_dir %{_localstatedir}/lib/rpm-state/kmod-dups
%define kver_state_dir %{dup_state_dir}/kver
%define kver_state_file %{kver_state_dir}/%{kmod_kernel_version}.%(arch)
%define dup_module_list %{dup_state_dir}/rpm-kmod-%{kmod_name}-modules

Name:		kmod-redhat-iwlwifi
Version:	%{kmod_driver_version}
Release:	%{kmod_rpm_release}%{?dist}
%if "%{kmod_driver_epoch}" != ""
Epoch:		%{kmod_driver_epoch}
%endif
Summary:	iwlwifi kernel module for Driver Update Program
Group:		System/Kernel
License:	GPLv2
URL:		https://www.kernel.org/
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:	%kernel_devel_pkg = %kmod_kernel_version
%if "%{kmod_dist_build_deps}" != ""
BuildRequires:	%{kmod_dist_build_deps}
%endif
ExclusiveArch:	x86_64
%global kernel_source() /usr/src/kernels/%{kmod_kernel_version}.$(arch)

%global _use_internal_dependency_generator 0
%if "%{?kmod_kernel_version_min}" != ""
Provides:	%kernel_modules_pkg >= %{kmod_kernel_version_min}.%{_target_cpu}
%else
Provides:	%kernel_modules_pkg = %{kmod_kernel_version_dep}.%{_target_cpu}
%endif
Provides:	kmod-%{kmod_name} = %{?epoch:%{epoch}:}%{version}-%{release}
Requires(post):	%{sbindir}/weak-modules
Requires(postun):	%{sbindir}/weak-modules
Requires:	kernel >= 4.18.0-80.el8

Requires:	kernel < 4.18.0-81.el8
%if 1
Requires: firmware(%{kmod_name}) = 20190516_dup8.0
%endif
%if "%{kmod_build_dependencies}" != ""
BuildRequires:  %{kmod_build_dependencies}
%endif
%if "%{kmod_dependencies}" != ""
Requires:       %{kmod_dependencies}
%endif
# if there are multiple kmods for the same driver from different vendors,
# they should conflict with each other.
Conflicts:	kmod-%{kmod_name}

%description
iwlwifi kernel module for Driver Update Program

%if 1

%package -n kmod-redhat-iwlwifi-firmware
Version:	20190516_dup8.0
Summary:	iwlwifi firmware for Driver Update Program
Provides:	firmware(%{kmod_name}) = 20190516_dup8.0
%if "%{kmod_kernel_version_min}" != ""
Provides:	%kernel_modules_pkg >= %{kmod_kernel_version_min}.%{_target_cpu}
%else
Provides:	%kernel_modules_pkg = %{kmod_kernel_version_dep}.%{_target_cpu}
%endif
%description -n  kmod-redhat-iwlwifi-firmware
iwlwifi firmware for Driver Update Program


%files -n kmod-redhat-iwlwifi-firmware
%defattr(644,root,root,755)
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-41.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-34.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-34.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-29.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-41.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265-17.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-27.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-27.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-43.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-38.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-46.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-10.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7260-17.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-21.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-31.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-27.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-21.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-22.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-3168-22.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-16.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-17.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7260-16.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-3168-27.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-3168-21.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-22.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-16.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-22.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-34.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-3160-17.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-46.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-36.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-3160-16.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-3168-29.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-cc-a0-46.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-21.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-38.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-43.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-33.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-33.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-34.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-36.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-31.ucode
/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265-16.ucode


%endif

# Development package
%if 0%{kmod_devel_package}
%package -n kmod-redhat-iwlwifi-devel
Version:	%{kmod_driver_version}
Requires:	kernel >= 4.18.0-80.el8

Requires:	kernel < 4.18.0-81.el8
Summary:	iwlwifi development files for Driver Update Program

%description -n  kmod-redhat-iwlwifi-devel
iwlwifi development files for Driver Update Program


%files -n kmod-redhat-iwlwifi-devel
%defattr(644,root,root,755)
/usr/share/kmod-%{kmod_vendor}-%{kmod_name}/Module.symvers
%endif

%post
modules=( $(find /lib/modules/%{kmod_kernel_version}.%(arch)/%{kmod_install_path} | grep '\.ko$') )
printf '%s\n' "${modules[@]}" | %{sbindir}/weak-modules --add-modules --no-initramfs

mkdir -p "%{kver_state_dir}"
touch "%{kver_state_file}"

exit 0

%posttrans
# We have to re-implement part of weak-modules here because it doesn't allow
# calling initramfs regeneration separately
if [ -f "%{kver_state_file}" ]; then
	kver_base="%{kmod_kernel_version_dep}"
	kvers=$(ls -d "/lib/modules/${kver_base%%.*}"*)

	for k_dir in $kvers; do
		k="${k_dir#/lib/modules/}"

		tmp_initramfs="/boot/initramfs-$k.tmp"
		dst_initramfs="/boot/initramfs-$k.img"

		# The same check as in weak-modules: we assume that the kernel present
		# if the symvers file exists.
		if [ -e "/boot/symvers-$k.gz" ]; then
			/usr/bin/dracut -f "$tmp_initramfs" "$k" || exit 1
			cmp -s "$tmp_initramfs" "$dst_initramfs"
			if [ "$?" = 1 ]; then
				mv "$tmp_initramfs" "$dst_initramfs"
			else
				rm -f "$tmp_initramfs"
			fi
		fi
	done

	rm -f "%{kver_state_file}"
	rmdir "%{kver_state_dir}" 2> /dev/null
fi

rmdir "%{dup_state_dir}" 2> /dev/null

exit 0

%preun
if rpm -q --filetriggers kmod 2> /dev/null| grep -q "Trigger for weak-modules call on kmod removal"; then
	mkdir -p "%{kver_state_dir}"
	touch "%{kver_state_file}"
fi

mkdir -p "%{dup_state_dir}"
rpm -ql kmod-redhat-iwlwifi-%{kmod_driver_version}-%{kmod_rpm_release}%{?dist}.$(arch) | \
	grep '\.ko$' > "%{dup_module_list}"

%postun
if rpm -q --filetriggers kmod 2> /dev/null| grep -q "Trigger for weak-modules call on kmod removal"; then
	initramfs_opt="--no-initramfs"
else
	initramfs_opt=""
fi

modules=( $(cat "%{dup_module_list}") )
rm -f "%{dup_module_list}"
printf '%s\n' "${modules[@]}" | %{sbindir}/weak-modules --remove-modules $initramfs_opt

rmdir "%{dup_state_dir}" 2> /dev/null

exit 0

%files
%defattr(644,root,root,755)
/lib/modules/%{kmod_kernel_version}.%(arch)
/etc/depmod.d/%{kmod_name}.conf
/usr/share/doc/kmod-%{kmod_name}/greylist.txt

%prep
%setup -n %{kmod_name}-%{kmod_vendor}-%{kmod_driver_version}

%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
%patch9 -p1
%patch10 -p1
%patch11 -p1
%patch12 -p1
%patch13 -p1
%patch14 -p1
%patch15 -p1
%patch16 -p1
%patch17 -p1
%patch18 -p1
%patch19 -p1
%patch20 -p1
%patch21 -p1
%patch22 -p1
%patch23 -p1
%patch24 -p1
%patch25 -p1
%patch26 -p1
%patch27 -p1
%patch28 -p1
%patch29 -p1
%patch30 -p1
%patch31 -p1
%patch32 -p1
%patch33 -p1
%patch34 -p1
%patch35 -p1
%patch36 -p1
%patch37 -p1
%patch38 -p1
%patch39 -p1
%patch40 -p1
%patch41 -p1
%patch42 -p1
%patch43 -p1
%patch44 -p1
%patch45 -p1
%patch46 -p1
%patch47 -p1
%patch48 -p1
%patch49 -p1
%patch50 -p1
%patch51 -p1
%patch52 -p1
%patch53 -p1
%patch54 -p1
%patch55 -p1
%patch56 -p1
%patch57 -p1
%patch58 -p1
%patch59 -p1
%patch60 -p1
%patch61 -p1
%patch62 -p1
%patch63 -p1
%patch64 -p1
%patch65 -p1
%patch66 -p1
%patch67 -p1
%patch68 -p1
%patch69 -p1
%patch70 -p1
%patch71 -p1
%patch72 -p1
%patch73 -p1
%patch74 -p1
%patch75 -p1
%patch76 -p1
%patch77 -p1
%patch78 -p1
%patch79 -p1
%patch80 -p1
%patch81 -p1
%patch82 -p1
%patch83 -p1
%patch84 -p1
%patch85 -p1
%patch86 -p1
%patch87 -p1
%patch88 -p1
%patch89 -p1
%patch90 -p1
%patch91 -p1
%patch92 -p1
%patch93 -p1
%patch94 -p1
%patch95 -p1
%patch96 -p1
%patch97 -p1
%patch98 -p1
%patch99 -p1
%patch100 -p1
%patch101 -p1
%patch102 -p1
%patch103 -p1
%patch104 -p1
%patch105 -p1
%patch106 -p1
%patch107 -p1
%patch108 -p1
%patch109 -p1
%patch110 -p1
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
rm -rf obj
cp -r source obj

PWD_PATH="$PWD"
%if "%{workaround_no_pwd_rel_path}" != "1"
PWD_PATH=$(realpath --relative-to="%{kernel_source}" . 2>/dev/null || echo "$PWD")
%endif
%{make_build} -C %{kernel_source} V=1 M="$PWD_PATH/obj/%{kmod_kbuild_dir}" \
	NOSTDINC_FLAGS="-I$PWD_PATH/obj/include -I$PWD_PATH/obj/include/uapi" \
	EXTRA_CFLAGS="%{nil}" \
	%{nil}
# mark modules executable so that strip-to-file can strip them
find obj/%{kmod_kbuild_dir} -name "*.ko" -type f -exec chmod u+x '{}' +

whitelist="/lib/modules/kabi-current/kabi_whitelist_%{_target_cpu}"
for modules in $( find obj/%{kmod_kbuild_dir} -name "*.ko" -type f -printf "%{findpat}\n" | sed 's|\.ko$||' | sort -u ) ; do
	# update depmod.conf
	module_weak_path=$(echo "$modules" | sed 's/[\/]*[^\/]*$//')
	if [ -z "$module_weak_path" ]; then
		module_weak_path=%{name}
	else
		module_weak_path=%{name}/$module_weak_path
	fi
	echo "override $(echo $modules | sed 's/.*\///')" \
	     "$(echo "%{kmod_kernel_version_dep}" |
	        sed 's/\.[^\.]*$//;
		     s/\([.+?^$\/\\|()\[]\|\]\)/\\\0/g').*" \
		     "weak-updates/$module_weak_path" >> source/depmod.conf

	# update greylist
	nm -u obj/%{kmod_kbuild_dir}/$modules.ko | sed 's/.*U //' |  sed 's/^\.//' | sort -u | while read -r symbol; do
		grep -q "^\s*$symbol\$" $whitelist || echo "$symbol" >> source/greylist
	done
done
sort -u source/greylist | uniq > source/greylist.txt

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=%{kmod_install_path}
PWD_PATH="$PWD"
%if "%{workaround_no_pwd_rel_path}" != "1"
PWD_PATH=$(realpath --relative-to="%{kernel_source}" . 2>/dev/null || echo "$PWD")
%endif
make -C %{kernel_source} modules_install \
	M=$PWD_PATH/obj/%{kmod_kbuild_dir}
# Cleanup unnecessary kernel-generated module dependency files.
find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;

install -m 644 -D source/depmod.conf $RPM_BUILD_ROOT/etc/depmod.d/%{kmod_name}.conf
install -m 644 -D source/greylist.txt $RPM_BUILD_ROOT/usr/share/doc/kmod-%{kmod_name}/greylist.txt
%if 1
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-41.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-41.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8000C-34.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-34.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8265-34.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-34.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7265D-29.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-29.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-41.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-41.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7265-17.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265-17.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8000C-27.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-27.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8265-27.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-27.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-43.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-43.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-38.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-38.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-46.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-46.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7265D-10.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-10.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7260-17.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7260-17.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8000C-21.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-21.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8000C-31.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-31.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7265D-27.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-27.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8265-21.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-21.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7265D-22.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-22.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-3168-22.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-3168-22.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7265D-16.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-16.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7265D-17.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-17.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7260-16.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7260-16.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-3168-27.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-3168-27.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-3168-21.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-3168-21.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8000C-22.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-22.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8000C-16.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-16.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8265-22.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-22.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-34.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-34.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-3160-17.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-3160-17.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-46.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-46.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8000C-36.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8000C-36.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-3160-16.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-3160-16.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-3168-29.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-3168-29.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-cc-a0-46.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-cc-a0-46.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7265D-21.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265D-21.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-38.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-38.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-43.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-43.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-33.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9000-pu-b0-jf-b0-33.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-33.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-33.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-34.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-9260-th-b0-jf-b0-34.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8265-36.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-36.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-8265-31.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-8265-31.ucode
install -m 644 -D source/firmware/iwlwifi_dup8.0/iwlwifi-7265-16.ucode $RPM_BUILD_ROOT/lib/firmware/iwlwifi_dup8.0/iwlwifi-7265-16.ucode

%endif
%if 0%{kmod_devel_package}
install -m 644 -D $PWD/obj/%{kmod_kbuild_dir}/Module.symvers $RPM_BUILD_ROOT/usr/share/kmod-%{kmod_vendor}-%{kmod_name}/Module.symvers
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Fri Oct 04 2019 Eugene Syromiatnikov <esyr@redhat.com> 4.18.0_107_dup8.0-5
- e67217ec68636d7570e69bab9e3b1ed1728b8292
- iwlwifi kernel module for Driver Update Program
- Resolves: #bz1755919
