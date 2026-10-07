This directory contains disclosure of Debian BaseOS packages of VMWare
${osmRelInfo/:/ }.

If you would like to perform a build and install of these packages, please
follow the instructions listed in below sections.

Prerequisites:

1. Install build dependencies:

    a. Launch Debian system.

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

Build :

  Following instructions are for building a debian package

   a. Use "apt-build" to build debian package
      Example if you need to build "adduser" package use
      \$ apt-build build-sources adduser

   b.Copy debian package to gateway device
      Example copy adduser_*.deb to ~/

Install:
    Assuming you copied the generated packages to ~/.
    Run the following commands as root to install the packages:

    Example adduser package:
    # cd ~/
    # sudo dpkg -r adduser
    # sudo dpkg -i --force-all  ~/adduser_*.deb
    # reboot
