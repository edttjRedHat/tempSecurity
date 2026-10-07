This directory contains disclosure of Ubuntu BaseOS packages of VMWare
${osmRelInfo/:/ }.

If you would like to perform a build and install of these packages, please
follow the instructions listed in below sections.

Prerequisites:

1. Install build dependencies:

    a. Launch Ubuntu system.

    b. Install apt-build.
       \$ sudo apt-get install apt-build

2. Create build repo with source:

   a. Extract ${osmRelInfo/:/ } sources.
      \$ mkdir -p '/${osmRelInfo/:/_}/src/'
      \$ tar -xf '${osmRelInfo/:/_}-repo-with-sources.tar.gz' -C '/${osmRelInfo/:/_}/src'

   b. Add repo with sources.
        cat > /etc/apt/sources.list <<EOF
        deb http://archive.ubuntu.com/ubuntu bionic main universe
        deb http://archive.ubuntu.com/ubuntu bionic-updates main universe
        deb-src [trusted=yes] file:///${osmRelInfo/:/_}/src bionic main
        EOF

   c. Update apt.
      \$ apt update


Install:
    Assuming you copied the generated packages to ~/.
    Run the following commands as root to install the packages:

    Example adduser package:
    # cd ~/
    # sudo dpkg -r adduser
    # sudo dpkg -i --force-all  ~/adduser_*.deb
    # reboot
