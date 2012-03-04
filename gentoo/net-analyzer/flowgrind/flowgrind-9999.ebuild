# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="2"

inherit eutils

DESCRIPTION="network performance measurement tool"
HOMEPAGE="http://www.umic-mesh.net/research/flowgrind"
if [[ ${PV} == "9999" ]] ; then
	inherit subversion autotools
	ESVN_REPO_URI="svn://svn.umic-mesh.net/flowgrind/trunk/"
	SLOT="svn"
	KEYWORDS=""
else
	SRC_URI="https://launchpad.net/flowgrind/trunk/${P}/+download/${P}.tar.bz2"
	SLOT="0"
	KEYWORDS="~amd64 ~x86"
fi
LICENSE="GPL-2"
IUSE="debug gsl pcap"

RDEPEND="gsl?  ( sci-libs/gsl )
         pcap? ( sys-libs/libcap )
         dev-libs/xmlrpc-c[curl]"
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
	dodoc AUTHORS NEWS README TODO || die
}
