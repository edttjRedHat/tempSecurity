This directory contains disclosure of Photon BaseOS packages of VMWare
${osmRelInfo/:/ }.

If you would like to perform a build and install of these packages, please
follow the instructions listed in below sections.

One package name might be mapped to a different file name. Besides, several
package names might be mapped to a standalone file name. The mapping relations
are described in oss.yaml file. Please refer to oss.yaml file for more details.

1. Build:
Any commands that need to be executed for the disclosure should be executed on a
"Photon (x86_64)" system.  You can just install the Photon 1.0 with default
configuration and gcc, make, rpm, rpmbuild installed.

Assuming you copy <package-name>.src.rpm files to the directory
"/usr/vmware/src".

cd /usr/vmware/src
mkdir -p /usr/src/photon/BUILD,SRPMS,RPMS,SPECS,SOURCES
rpm -ivh --nodeps --force <package-name>.src.rpm
cd /usr/src/photon/SPECS
rpmbuild -bb <package-name>.spec

Then under /usr/src/photon/RPMS/, you can find final RPMs.

If you would like to verify the installation of this package, please create the
binary disclosure file for this package using the command:

tar cvf /usr/vmware/src/disclosure.tar -C /usr/src/packages/RPMS x86_64 # Or "noarch".

This file is used in the installation instructions.

2: Install:
Copy the binary disclosure files,  disclosure.tar to the directory "/tmp"
on a VMware ${osmRelInfo/:/_},
execute the following commands as root:

tar xvf disclosure.tar
cd x86_64
rpm -Uvh --force <package-name>.rpm

After updating, reboot the system.
