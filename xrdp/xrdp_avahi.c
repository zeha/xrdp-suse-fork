/*
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   xrdp: A Remote Desktop Protocol server.
   Copyright (C) Novell, Inc. 2008

   avahi integration

*/

#include "xrdp.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/thread-watch.h>

static AvahiClient       *client = NULL;
static AvahiThreadedPoll *threaded_poll = NULL;
static AvahiEntryGroup   *avahi_group = NULL;

static const char *_service_name = "RDP service on %s";

static void
avahi_client_callback (AvahiClient      *c,
		       AvahiClientState state,
		       void             *userdata)
{
    switch (state) {
    case AVAHI_CLIENT_S_RUNNING:
	avahi_group = avahi_entry_group_new (c, 0, 0);
	if (avahi_group)
	{
	    char hname[512];
	    char name[576];
	    char port[8];

	    if (gethostname (hname, sizeof (hname)))
		break;

	    sprintf (name, _service_name, hname);

	    xrdp_listen_get_port (port, sizeof (port));

	    avahi_entry_group_add_service (avahi_group,
					   AVAHI_IF_UNSPEC,
					   AVAHI_PROTO_UNSPEC,
					   0, 
					   name,
					   "_rdp._tcp",
					   0,
					   0,
					   atoi (port),
					   NULL);

	    avahi_entry_group_commit (avahi_group);
	}
	break;
    case AVAHI_CLIENT_FAILURE:
    case AVAHI_CLIENT_S_COLLISION:
    case AVAHI_CLIENT_CONNECTING:
	break;
    case AVAHI_CLIENT_S_REGISTERING:
	if (avahi_group)
	    avahi_entry_group_reset (avahi_group);
    default:
	break;
    }
}

int APP_CC
xrdp_avahi_init (void)
{
    if (!(threaded_poll = avahi_threaded_poll_new ()))
	return 1;

    if (!(client = avahi_client_new (avahi_threaded_poll_get (threaded_poll),
				    0, 
				    avahi_client_callback,
				    NULL,
				    NULL)))
       return 1;

   if (avahi_threaded_poll_start (threaded_poll) < 0)
       return 1;

   return 0;
}

void APP_CC
xrdp_avahi_fini (void)
{
    avahi_threaded_poll_stop (threaded_poll);
    if (avahi_group)
	avahi_entry_group_free (avahi_group);
    avahi_client_free (client);
    avahi_threaded_poll_free (threaded_poll);
}
