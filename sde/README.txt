#BEGIN_LEGAL
#Copyright (c) 2004-2017, Intel Corporation. All rights reserved.
#
#The source code contained or described herein and all documents
#related to the source code ("Material") are owned by Intel Corporation
#or its suppliers or licensors. Title to the Material remains with
#Intel Corporation or its suppliers and licensors. The Material
#contains trade secrets and proprietary and confidential information of
#Intel or its suppliers and licensors. The Material is protected by
#worldwide copyright and trade secret laws and treaty provisions. No
#part of the Material may be used, copied, reproduced, modified,
#published, uploaded, posted, transmitted, distributed, or disclosed in
#any way without Intel's prior express written permission.
#
#No license under any patent, copyright, trade secret or other
#intellectual property right is granted to or conferred upon you by
#disclosure or delivery of the Materials, either expressly, by
#implication, inducement, estoppel or otherwise. Any license under such
#intellectual property rights must be express and approved by Intel in
#writing.
#END_LEGAL

Documentation:

  http://www.intel.com/software/sde

Support is via Intel Software Network Forums:

 AVX and new-instruction related questions:

  http://software.intel.com/en-us/forums/intel-avx-and-cpu-instructions/

 SDE usage questions:

  http://software.intel.com/en-us/forums/intel-software-development-emulator/

==============================================================
Linux Notes:

 RH systems: You must turn off SELinux to allow pin to work. Put
 "SELINUX=disabled" in /etc/sysconfig/selinux

 Ubuntu systems: Need to disable yama once, as root:
   $ echo 0 > /proc/sys/kernel/yama/ptrace_scope

 To use the debugging support, you must use gdb 7.5 or later.

==============================================================

Windows Notes:

 Winzip adds executable permissions to every file. Cygwin users must
 do a "chmod -R +x ." in the unpacked kit directory.

 To use the debugging support you must install the MSI from our web
 site and be using the final version MSVS2012 (not a release
 candidate).

==============================================================
Mac OS X notes:

 Intel SDE is using the MACH taskport APIs. By default, when trying 
 to use these APIs, user-authentication is required once per a GUI 
 session. In order to allow PIN/SDE run without this authentication 
 you need to disable it. This is done by configuring the machine 
 to auto-confirm takeover of the process as described in SDE web page
 in the system configuration section.

 The debugger connection support does not work yet on Mac OSX.
