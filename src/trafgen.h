/*
 * trafgen.h - Routines used by the Flowgrind Daemon for advanced traffic generation
 *
 * Copyright (C) Christian Samsel <christian.samsel@rwth-aachen.de>, 2010-2013
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _TRAFGEN_H_
#define _TRAFGEN_H_

extern int next_request_block_size(struct _flow *);
extern int next_response_block_size(struct _flow *);
extern double next_interpacket_gap(struct _flow *);

#endif
