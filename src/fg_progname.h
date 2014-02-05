/**
 * @file fg_progname.h
 * @brief Program name management
 */

/*
 * Copyright (C) 2014 Alexander Zimmermann <alexander.zimmermann@netapp.com>
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

#ifndef _FG_PROGNAME_H_
#define _FG_PROGNAME_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/** String containing name the program is called with */
extern const char *progname;

/**
 * Set global variable 'progname', based on argv[0]
 *
 * @param[in] argv0 the name by which the program was called (argv[0])
 */
void set_progname(const char *argv0);

#endif /* _FG_PROGNAME_H_*/
