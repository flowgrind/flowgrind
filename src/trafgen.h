/**
 * @file trafgen.h
 * @brief Routines used by the Flowgrind Daemon for advanced traffic generation
 */

/*
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
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

#ifndef _TRAFGEN_H_
#define _TRAFGEN_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

extern int next_request_block_size(struct _flow *);
extern int next_response_block_size(struct _flow *);
extern double next_interpacket_gap(struct _flow *);

#endif /* _TRAFGEN_H_ */
