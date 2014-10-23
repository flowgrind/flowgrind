# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="2"

inherit eutils

DESCRIPTION="network performance measurement tool"
HOMEPAGE="http://www.flowgrind.net"
if [[ ${PV} == "9999" ]] ; then
	inherit git-r3 autotools
	EGIT_REPO_URI="git://github.com/${PN}/${PN}.git 
				   http://github.com/${PN}/${PN}.git"
	SLOT="git"
	KEYWORDS=""
else
	SRC_URI="https://github.com/${PN}/${PN}/releases/download/${P}/${P}.tar.bz2"
	SLOT="0"
	KEYWORDS="~amd64 ~x86"
fi
LICENSE="GPL-3"
IUSE="debug gsl pcap"

RDEPEND="gsl?  ( sci-libs/gsl )
         pcap? ( net-libs/libpcap )
         dev-libs/xmlrpc-c[abyss,curl]"
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
	emake DESTDIR="${D}" install || die
	prepalldocs
	doman man/*.1 || die
	dodoc AUTHORS NEWS README.md COPYING INSTALL.Gentoo || die
}
