/**
 * @file flowgrind.h
 * @brief Flowgrind Controller
 */

/*
 * Copyright (C) 2013-2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
 * Copyright (C) 2010-2013 Arnd Hannemann <arnd@arndnet.de>
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 * Copyright (C) 2009 Tim Kosse <tim.kosse@gmx.de>
 * Copyright (C) 2007-2008 Daniel Schaffrath <daniel.schaffrath@mac.com>
 *
 * This file is part of Flowgrind. Flowgrind is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2 as published by the Free Software Foundation.
 *
 * Flowgrind distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _FLOWGRINDD_H_
#define _FLOWGRINDD_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/** Print flowgrind usage and exit */
static void usage(void) __attribute__((noreturn));

/** Print hint upon an error while parsing the command line */
inline static void usage_hint(void) __attribute__((noreturn));

/**
 * Parse command line options to initialize global options
 *
 * @param[in] argc number of command line arguments
 * @param[in] argv arguments provided by the command line
 */
static void parse_option(int argc, char *argv[])

#endif /* _FLOWGRINDD_H_ */
