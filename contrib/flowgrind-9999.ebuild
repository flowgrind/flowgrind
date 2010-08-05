# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="2"

inherit eutils 

DESCRIPTION="Flowgrind"
HOMEPAGE="http://www.umic-mesh.net/research/flowgrind"
LICENSE="GPL-2"
SLOT="0"
if [[ ${PV} == "9999" ]] ; then
	inherit subversion autotools
	ESVN_REPO_URI="svn://svn.umic-mesh.net/flowgrind/trunk/"
#	ESVN_STORE_DIR="${PORTAGE_ACTUAL_DISTDIR:-${DISTDIR}}/svn-src/flowgrind"
	SLOT="svn"
else
	SRC_URI="http://www.umic-mesh.net/downloads/flowgrind/files/flowgrind-${P}.bz2"
	SLOT="0"
fi

KEYWORDS="~x86 ~amd64"

IUSE="pcap debug"

RDEPEND="
	dev-libs/xmlrpc-c[abyss,curl]
	pcap? ( sys-libs/libcap )
"
DEPEND="${RDEPEND}"

if [[ ${PV} == "9999" ]] ; then
	src_prepare() {
		eautoreconf
	}
fi


src_compile() {
	econf \
	$(use_enable libpcap) \
	$(use_enable debug) || die 

	emake || die
}

src_install() {
	einstall ||
	prepalldocs
	dodoc AUTHORS ChangeLog NEWS README
}
