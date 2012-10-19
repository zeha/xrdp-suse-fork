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
*/

#include <stdlib.h>
#include "arch.h"

const char* APP_CC
get_keylayout_name(int keylayout)
{
  const char *layout_name;
  switch (keylayout)
  {
    case 0x409: /* us en */
        layout_name = "us";
      break;
    case 0x40c: /* france */
        layout_name = "fr";
      break;
    case 0x809: /* en-uk or en-gb */
        layout_name = "uk";
      break;
    case 0x407: /* german */
        layout_name = "de";
      break;
    case 0x416: /* Portuguese (Brazil) */
        layout_name = "pt";
      break;
    case 0x410: /* italy */
        layout_name = "it";
      break;
    case 0x41d: /* swedish */
        layout_name = "sv";
      break;
    case 0x405: /* czech */
        layout_name = "cs";
      break;
    case 0x419: /* russian */
        layout_name = "su";
      break;
    default:
        layout_name = NULL;
  }
  return layout_name;
}
