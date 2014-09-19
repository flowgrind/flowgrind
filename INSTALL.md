RELEASE VERSION Installation
============================

Flowgrind is part of Debian (since Jessie), Ubuntu (since Utopic), Gentoo, FreeBSD and Mac OS X (Homebrew). The installation of flowgrind in those distributions is straight forward.

* **Debian & Ubuntu**: Installation using apt-get:

        # apt-get update
        # aptitude install flowgrind

* **Gentoo**: If you want to use all flowgrind features, enable some use flags:

        # euse --enable gsl
        # euse --enable pcap

 Installation using Portage:

        # echo "net-analyzer/flowgrind ~amd64" >> /etc/portage/package.keywords/flowgrind
        # emerge flowgrind

* **FreeBSD**: Installation using port tree:

        # cd /usr/ports/benchmarks/flowgrind
        # make install clean

* **Mac OS X**: Installation using Homebrew:

        # brew install flowgrind


TARBALL or GIT VERSION Installation
===================================

Flowgrind depends on the following tools and libraries:

* GNU Build System (aka Autotools)
* libxmlrpc-c with curl transport and abyss server

These libraries as well as their headers and tools need to be installed (install appropriate -dev packages too).

The following dependencies are optional and only required for advanced features:

* libpcap (for automatic dump, optional)
* libgsl (for advanced traffic generation, optional)


Debian & Ubuntu
---------------

* Install essentials and required xmlrpc-c library:

        # sudo apt-get install build-essential debhelper cdbs autotools-dev
        # sudo apt-get install libxmlrpc-core-c3 libxmlrpc-core-c3-dev libcurl4-gnutls-dev

* Install optional libGSL and libpcap library if you want to use all flowgrind features:

        # sudo apt-get install libpcap-dev
        # sudo apt-get install libgsl0-dev

* Download and extract archive:

        # tar xjvf flowgrind-*.tar.bz2
        # cd flowgrind-*

  OR checkout flowgrind from the git repository:

        # git clone git://github.com/flowgrind/flowgrind.git
        # cd flowgrind
        # autoreconf -i

* Build Debian package:

        # dpkg-buildpackage -rfakeroot -uc -b

* Install resulting packages:

        # cd ..
        # sudo dpkg -i *.deb

Gentoo
------

If you want to install the GIT version from the git repository, you can use the provided ebuild with git support.

* Copying ebuild files into local portage overlay (e.g. /usr/local/portage)

        # tar xfvj flowgrind-*.tar.bz2
        # cp -R flowgrind-*/gentoo/net-analyzer/ /usr/local/portage

* Unmask and emerge:

        # echo "net-analyzer/flowgrind ** > /etc/portage/package.keywords/flowgrind
        # emerge flowgrind

* Hint: you can select a different git branch (e.g., next) by setting the environment for the ebuild like this:

        # mkdir -p /etc/portage/env/
        # echo 'EGIT_BRANCH="next"' > /etc/portage/env/flowgrind-git-branch
        # echo "net-analyzer/flowgrind flowgrind-git-branch" >>/etc/portage/package.env


FreeBSD
-------

* Install required xmlrpc-c library:

        # cd /usr/ports/net/xmlrpc-c; make install clean (activate curl)

* Install optional libGSL and libpcap library if you want to use all flowgrind features:

        # cd /usr/ports/math/gsl
        # make install clean
        # cd /usr/ports/net/libpcap
        # make install clean

* Download and extract archive:

        # tar xjvf flowgrind-*.tar.bz2
        # cd flowgrind-*

  OR checkout flowgrind from the git repository:

        # git clone git://github.com/flowgrind/flowgrind.git
        # cd flowgrind
        # autoreconf -i

* Build and install flowgrind:

        # ./configure
        # make
        # make install


Mac OS X
--------

* Install essentials and required xmlrpc-c library:

        # brew install gettext
        # brew install xmlrpc-c

* Install optional libGSL if you want to use all flowgrind features:

        # brew install gsl

* Download and extract archive:

        # tar xjvf flowgrind-*.tar.bz2
        # cd flowgrind-*

  OR checkout flowgrind from the git repository:

        # git clone git://github.com/flowgrind/flowgrind.git
        # cd flowgrind
        # autoreconf -i

* Build and install flowgrind:

        # ./configure
        # make
        # make install
