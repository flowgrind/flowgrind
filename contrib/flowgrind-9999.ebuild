# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="2"

inherit eutils 

DESCRIPTION="Flowgrind - network performance measurement tool"
HOMEPAGE="http://www.umic-mesh.net/research/flowgrind"
LICENSE="GPL-2"
SLOT="0"
if [[ ${PV} == "9999" ]] ; then
	inherit subversion autotools
	ESVN_REPO_URI="svn://svn.umic-mesh.net/flowgrind/trunk/"
	SLOT="svn"
	KEYWORDS=""
else
	SRC_URI="http://www.umic-mesh.net/downloads/files/${P}.tar.bz2"
	SLOT="0"
	KEYWORDS="~x86 ~amd64"
fi

IUSE="pcap gsl debug"

RDEPEND="
	<dev-libs/xmlrpc-c-1.14[curl]
	pcap? ( sys-libs/libcap )
	gsl? ( sci-libs/gsl )
"
DEPEND="${RDEPEND}"

if [[ ${PV} == "9999" ]] ; then
	src_prepare() {
		eautoreconf || die
	}
fi

src_configure() {
	econf \
	$(use_enable pcap) \
	$(use_enable debug) \
	$(use_enable gsl) || die 
}

src_compile() {
	emake || die
}

src_install() {
	einstall || die
	prepalldocs
	doman man/*.1
	dodoc AUTHORS ChangeLog NEWS README TODO
}
