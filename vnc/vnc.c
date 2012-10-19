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
   Copyright (C) Jay Sorg 2004-2008

   libvnc

*/

#include "vnc.h"

/******************************************************************************/
/* taken from vncauth.c */
void DEFAULT_CC
rfbEncryptBytes(char* bytes, char* passwd)
{
  char key[12];

  /* key is simply password padded with nulls */
  g_memset(key, 0, sizeof(key));
  g_strncpy(key, passwd, 8);
  rfbDesKey((unsigned char*)key, EN0); /* 0, encrypt */
  rfbDes((unsigned char*)bytes, (unsigned char*)bytes);
  rfbDes((unsigned char*)(bytes + 8), (unsigned char*)(bytes + 8));
}

/******************************************************************************/
/* returns error */
int DEFAULT_CC
lib_recv(struct vnc* v, char* data, int len)
{
  int rcvd;

  if (v->sck_closed)
  {
    return 1;
  }
  while (len > 0)
  {
    rcvd = g_tcp_recv(v->sck, data, len, 0);
    if (rcvd == -1)
    {
      if (g_tcp_last_error_would_block(v->sck))
      {
        if (v->server_is_term(v))
        {
          return 1;
        }
        g_tcp_can_recv(v->sck, 10);
      }
      else
      {
        return 1;
      }
    }
    else if (rcvd == 0)
    {
      v->sck_closed = 1;
      return 1;
    }
    else
    {
      data += rcvd;
      len -= rcvd;
    }
  }
  return 0;
}

/*****************************************************************************/
/* returns error */
int DEFAULT_CC
lib_send(struct vnc* v, char* data, int len)
{
  int sent;

  if (v->sck_closed)
  {
    return 1;
  }
  while (len > 0)
  {
    sent = g_tcp_send(v->sck, data, len, 0);
    if (sent == -1)
    {
      if (g_tcp_last_error_would_block(v->sck))
      {
        if (v->server_is_term(v))
        {
          return 1;
        }
        g_tcp_can_send(v->sck, 10);
      }
      else
      {
        return 1;
      }
    }
    else if (sent == 0)
    {
      v->sck_closed = 1;
      return 1;
    }
    else
    {
      data += sent;
      len -= sent;
    }
  }
  return 0;
}

/******************************************************************************/
static int DEFAULT_CC
lib_process_channel_data(struct vnc* v, int chanid, int size, struct stream* s)
{
  int type;
  int status;
  int length;
  int index;
  int format;
  struct stream* out_s;

  if (chanid == v->clip_chanid)
  {
    in_uint16_le(s, type);
    in_uint16_le(s, status);
    in_uint32_le(s, length);
    //g_writeln("clip data type %d status %d length %d", type, status, length);
    //g_hexdump(s->p, s->end - s->p);
    switch (type)
    {
      case 2: /* CLIPRDR_FORMAT_ANNOUNCE */
        make_stream(out_s);
        init_stream(out_s, 8192);
        out_uint16_le(out_s, 3);
        out_uint16_le(out_s, 1);
        out_uint32_le(out_s, 0);
        out_uint8s(out_s, 4); /* pad */
        s_mark_end(out_s);
        length = (int)(out_s->end - out_s->data);
        v->server_send_to_channel(v, v->clip_chanid, out_s->data, length);
        free_stream(out_s);
        break;
      case 3: /* CLIPRDR_FORMAT_ACK */
        break;
      case 4: /* CLIPRDR_DATA_REQUEST */
        format = 0;
        if (length >= 4)
        {
          in_uint32_le(s, format);
        }
        /* only support CF_TEXT and CF_UNICODETEXT */
        if ((format != 1) && (format != 13))
        {
          break;
        }
        make_stream(out_s);
        init_stream(out_s, 8192);
        out_uint16_le(out_s, 5);
        out_uint16_le(out_s, 1);
        if (format == 13) /* CF_UNICODETEXT */
        {
          out_uint32_le(out_s, v->clip_data_size * 2 + 2);
          for (index = 0; index < v->clip_data_size; index++)
          {
            out_uint8(out_s, v->clip_data[index]);
            out_uint8(out_s, 0);
          }
          out_uint8s(out_s, 2);
        }
        else if (format == 1) /* CF_TEXT */
        {
          out_uint32_le(out_s, v->clip_data_size + 1);
          for (index = 0; index < v->clip_data_size; index++)
          {
            out_uint8(out_s, v->clip_data[index]);
          }
          out_uint8s(out_s, 1);
        }
        out_uint8s(out_s, 4); /* pad */
        s_mark_end(out_s);
        length = (int)(out_s->end - out_s->data);
        v->server_send_to_channel(v, v->clip_chanid, out_s->data, length);
        free_stream(out_s);
        break;
    }
  }
  return 0;
}

/******************************************************************************/
static int APP_CC
unicode_to_keysym(int unicode)
{
  int keysym;

  switch (unicode)
  {
    case 0x017e:
      keysym = 0x01be; /* XK_zcaron */
      break;
    case 0x0401:
      keysym = 0x06b3; /* XK_Cyrillic_IO */
      break;
    case 0x0410:
      keysym = 0x06e1; /* XK_Cyrillic_A */
      break;
    case 0x0411:
      keysym = 0x06e2; /* XK_Cyrillic_BE */
      break;
    case 0x0412:
      keysym = 0x06f7; /* XK_Cyrillic_VE */
      break;
    case 0x0413:
      keysym = 0x06e7; /* XK_Cyrillic_GHE */
      break;
    case 0x0414:
      keysym = 0x06e4; /* XK_Cyrillic_DE */
      break;
    case 0x0415:
      keysym = 0x06e5; /* XK_Cyrillic_IE */
      break;
    case 0x0416:
      keysym = 0x06f6; /* XK_Cyrillic_ZHE */
      break;
    case 0x0417:
      keysym = 0x06fa; /* XK_Cyrillic_ZE */
      break;
    case 0x0418:
      keysym = 0x06e9; /* XK_Cyrillic_I */
      break;
    case 0x0419:
      keysym = 0x06ea; /* XK_Cyrillic_SHORTI */
      break;
    case 0x041a:
      keysym = 0x06eb; /* XK_Cyrillic_KA */
      break;
    case 0x041b:
      keysym = 0x06ec; /* XK_Cyrillic_EL */
      break;
    case 0x041c:
      keysym = 0x06ed; /* XK_Cyrillic_EM */
      break;
    case 0x041d:
      keysym = 0x06ee; /* XK_Cyrillic_EN */
      break;
    case 0x041e:
      keysym = 0x06ef; /* XK_Cyrillic_O */
      break;
    case 0x041f:
      keysym = 0x06f0; /* XK_Cyrillic_PE */
      break;
    case 0x0420:
      keysym = 0x06f2; /* XK_Cyrillic_ER */
      break;
    case 0x0423:
      keysym = 0x06f5; /* XK_Cyrillic_U */
      break;
    case 0x0424:
      keysym = 0x06e6; /* XK_Cyrillic_EF */
      break;
    case 0x0425:
      keysym = 0x06e8; /* XK_Cyrillic_HA */
      break;
    case 0x0426:
      keysym = 0x06e3; /* XK_Cyrillic_TSE */
      break;
    case 0x0428:
      keysym = 0x06fb; /* XK_Cyrillic_SHA */
      break;
    case 0x0429:
      keysym = 0x06fd; /* XK_Cyrillic_SHCHA */
      break;
    case 0x042a:
      keysym = 0x06ff; /* XK_Cyrillic_HARDSIGN */
      break;
    case 0x042b:
      keysym = 0x06f9; /* XK_Cyrillic_YERU */
      break;
    case 0x042d:
      keysym = 0x06fc; /* XK_Cyrillic_E */
      break;
    case 0x042f:
      keysym = 0x06f1; /* XK_Cyrillic_YA */
      break;
    case 0x0427:
      keysym = 0x06fe; /* XK_Cyrillic_CHE */
      break;
    case 0x0421:
      keysym = 0x06f3; /* XK_Cyrillic_ES */
      break;
    case 0x0422:
      keysym = 0x06f4; /* XK_Cyrillic_TE */
      break;
    case 0x042c:
      keysym = 0x06f8; /* XK_Cyrillic_SOFTSIGN */
      break;
    case 0x042e:
      keysym = 0x06e0; /* XK_Cyrillic_YU */
      break;
    case 0x0430:
      keysym = 0x06c1; /* XK_Cyrillic_a */
      break;
    case 0x0431:
      keysym = 0x06c2; /* XK_Cyrillic_be */
      break;
    case 0x0432:
      keysym = 0x06d7; /* XK_Cyrillic_ve */
      break;
    case 0x0433:
      keysym = 0x06c7; /* XK_Cyrillic_ghe */
      break;
    case 0x0434:
      keysym = 0x06c4; /* XK_Cyrillic_de */
      break;
    case 0x0435:
      keysym = 0x06c5; /* XK_Cyrillic_ie */
      break;
    case 0x0436:
      keysym = 0x06d6; /* XK_Cyrillic_zhe */
      break;
    case 0x0437:
      keysym = 0x06da; /* XK_Cyrillic_ze */
      break;
    case 0x0438:
      keysym = 0x06c9; /* XK_Cyrillic_i */
      break;
    case 0x0439:
      keysym = 0x06ca; /* XK_Cyrillic_shorti */
      break;
    case 0x043a:
      keysym = 0x06cb; /* XK_Cyrillic_ka */
      break;
    case 0x043b:
      keysym = 0x06cc; /* XK_Cyrillic_el */
      break;
    case 0x043c:
      keysym = 0x06cd; /* XK_Cyrillic_em */
      break;
    case 0x043d:
      keysym = 0x06ce; /* XK_Cyrillic_en */
      break;
    case 0x043e:
      keysym = 0x06cf; /* XK_Cyrillic_o */
      break;
    case 0x043f:
      keysym = 0x06d0; /* XK_Cyrillic_pe */
      break;
    case 0x0440:
      keysym = 0x06d2; /* XK_Cyrillic_er */
      break;
    case 0x0441:
      keysym = 0x06d3; /* XK_Cyrillic_es */
      break;
    case 0x0442:
      keysym = 0x06d4; /* XK_Cyrillic_te */
      break;
    case 0x0443:
      keysym = 0x06d5; /* XK_Cyrillic_u */
      break;
    case 0x0444:
      keysym = 0x06c6; /* XK_Cyrillic_ef */
      break;
    case 0x0445:
      keysym = 0x06c8; /* XK_Cyrillic_ha */
      break;
    case 0x0446:
      keysym = 0x06c3; /* XK_Cyrillic_tse */
      break;
    case 0x0447:
      keysym = 0x06de; /* XK_Cyrillic_che */
      break;
    case 0x0448:
      keysym = 0x06db; /* XK_Cyrillic_sha */
      break;
    case 0x0449:
      keysym = 0x06dd; /* XK_Cyrillic_shcha */
      break;
    case 0x044a:
      keysym = 0x06df; /* XK_Cyrillic_hardsign */
      break;
    case 0x044b:
      keysym = 0x06d9; /* XK_Cyrillic_yeru */
      break;
    case 0x044c:
      keysym = 0x06d8; /* XK_Cyrillic_softsign */
      break;
    case 0x044d:
      keysym = 0x06dc; /* XK_Cyrillic_e */
      break;
    case 0x044e:
      keysym = 0x06c0; /* XK_Cyrillic_yu */
      break;
    case 0x044f:
      keysym = 0x06d1; /* XK_Cyrillic_ya */
      break;
    case 0x0451:
      keysym = 0x06a3; /* XK_Cyrillic_io */
      break;
    default:
      keysym = unicode;
      break;
  }
  return keysym;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_event(struct vnc* v, int msg, long param1, long param2,
              long param3, long param4)
{
  struct stream* s;
  int key;
  int error;
  int x;
  int y;
  int cx;
  int cy;
  int size;
  int chanid;
  char* data;
  char text[256];

  error = 0;
  make_stream(s);
  if (msg == 0x5555) /* channel data */
  {
    chanid = (int)param1;
    size = (int)param2;
    data = (char*)param3;
    if ((size >= 0) && (size <= (32 * 1024)) && (data != 0))
    {
      init_stream(s, size);
      out_uint8a(s, data, size);
      s_mark_end(s);
      s->p = s->data;
      error = lib_process_channel_data(v, chanid, size, s);
    }
    else
    {
      error = 1;
    }
  }
  else if ((msg >= 15) && (msg <= 16)) /* key events */
  {
    key = 0;
    if (param2 == 0xffff) /* ascii char */
    {
      key = unicode_to_keysym(param1);
    }
    else /* non ascii key event */
    {
      switch (param1)
      {
        case 0x0001: /* ecs */
          key = 0xff1b; /* XK_Escape */
          break;
        case 0x000e: /* backspace */
          key = 0xff08; /* XK_BackSpace */
          break;
        case 0x000f: /* tab(0xff09) or left tab(0xfe20) */
          /* some documentation says don't send left tab */
          /* just send tab and if the shift modifier is down */
          /* the server will know */
          /* for now, sending left tab, I don't know which is best */
          /* nope, sending tab always */
          /* key = (v->shift_state) ? 0xfe20 : 0xff09; */
          key = 0xff09; /* XK_Tab */
          break;
        case 0x001c: /* enter */
          key = 0xff0d; /* XK_Return */
          break;
        case 0x001d: /* left-right control */
          key = (param2 & 0x0100) ? 0xffe4 : 0xffe3; /* XK_Control_R */
                                                     /* XK_Control_L */
          break;
        case 0x002a: /* left shift */
          key = 0xffe1; /* XK_Shift_L */
          v->shift_state = (msg == 15);
          break;
        case 0x0036: /* right shift */
          key = 0xffe2; /* XK_Shift_R */
          v->shift_state = (msg == 15);
          break;
        case 0x0038: /* left-right alt */
          if (param2 & 0x0100) /* right alt */
          {
            /* only en-us keymap can send right alt(alt-gr) */
            if (v->keylayout == 0x409) /* todo */
            {
              key = 0xffea; /* XK_Alt_R */
            }
          }
          else /* left alt */
          {
            key = 0xffe9; /* XK_Alt_L */
          }
          break;
        case 0x003b: /* F1 */
          key = 0xffbe; /* XK_F1 */
          break;
        case 0x003c: /* F2 */
          key = 0xffbf; /* XK_F2 */
          break;
        case 0x003d: /* F3 */
          key = 0xffc0; /* XK_F3 */
          break;
        case 0x003e: /* F4 */
          key = 0xffc1; /* XK_F4 */
          break;
        case 0x003f: /* F5 */
          key = 0xffc2; /* XK_F5 */
          break;
        case 0x0040: /* F6 */
          key = 0xffc3; /* XK_F6 */
          break;
        case 0x0041: /* F7 */
          key = 0xffc4; /* XK_F7 */
          break;
        case 0x0042: /* F8 */
          key = 0xffc5; /* XK_F8 */
          break;
        case 0x0043: /* F9 */
          key = 0xffc6; /* XK_F9 */
          break;
        case 0x0044: /* F10 */
          key = 0xffc7; /* XK_F10 */
          break;
        case 0x0047: /* home */
          key = 0xff50; /* XK_Home */
          break;
        case 0x0048: /* up arrow */
          key = 0xff52; /* XK_Up */
          break;
        case 0x0049: /* page up */
          key = 0xff55; /* XK_Prior */
          break;
        case 0x004b: /* left arrow */
          key = 0xff51; /* XK_Left */
          break;
        case 0x004d: /* right arrow */
          key = 0xff53; /* XK_Right */
          break;
        case 0x004f: /* end */
          key = 0xff57; /* XK_End */
          break;
        case 0x0050: /* down arrow */
          key = 0xff54; /* XK_Down */
          break;
        case 0x0051: /* page down */
          key = 0xff56; /* XK_Next */
          break;
        case 0x0052: /* insert */
          key = 0xff63; /* XK_Insert */
          break;
        case 0x0053: /* delete */
          key = 0xffff; /* XK_Delete */
          break;
        case 0x0057: /* F11 */
          key = 0xffc8; /* XK_F11 */
          break;
        case 0x0058: /* F12 */
          key = 0xffc9; /* XK_F12 */
          break;
        /* not sure about the next three, I don't think rdesktop */
        /* sends them right */
        case 0x0037: /* Print Screen */
          key = 0xff61; /* XK_Print */
          break;
        case 0x0046: /* Scroll Lock */
          key = 0xff14; /* XK_Scroll_Lock */
          break;
        case 0x0045: /* Pause */
          key = 0xff13; /* XK_Pause */
          break;
        default:
          g_sprintf(text, "unkown key lib_mod_event msg %d \
param1 0x%4.4x param2 0x%4.4x", msg, param1, param2);
          v->server_msg(v, text, 1);
          break;
      }
    }
    if (key > 0)
    {
      init_stream(s, 8192);
      out_uint8(s, 4);
      out_uint8(s, msg == 15); /* down flag */
      out_uint8s(s, 2);
      out_uint32_be(s, key);
      error = lib_send(v, s->data, 8);
    }
  }
  else if (msg >= 100 && msg <= 110) /* mouse events */
  {
    switch (msg)
    {
      case 100: break; /* WM_MOUSEMOVE */
      case 101: v->mod_mouse_state &= ~1; break; /* WM_LBUTTONUP */
      case 102: v->mod_mouse_state |= 1; break; /* WM_LBUTTONDOWN */
      case 103: v->mod_mouse_state &= ~4; break; /* WM_RBUTTONUP */
      case 104: v->mod_mouse_state |= 4; break; /* WM_RBUTTONDOWN */
      case 105: v->mod_mouse_state &= ~2; break;
      case 106: v->mod_mouse_state |= 2; break;
      case 107: v->mod_mouse_state &= ~8; break;
      case 108: v->mod_mouse_state |= 8; break;
      case 109: v->mod_mouse_state &= ~16; break;
      case 110: v->mod_mouse_state |= 16; break;
    }
    init_stream(s, 8192);
    out_uint8(s, 5);
    out_uint8(s, v->mod_mouse_state);
    out_uint16_be(s, param1);
    out_uint16_be(s, param2);
    error = lib_send(v, s->data, 6);
  }
  else if (msg == 200) /* invalidate */
  {
    /* FrambufferUpdateRequest */
    init_stream(s, 8192);
    out_uint8(s, 3);
    out_uint8(s, 0);
    x = (param1 >> 16) & 0xffff;
    out_uint16_be(s, x);
    y = param1 & 0xffff;
    out_uint16_be(s, y);
    cx = (param2 >> 16) & 0xffff;
    out_uint16_be(s, cx);
    cy = param2 & 0xffff;
    out_uint16_be(s, cy);
    error = lib_send(v, s->data, 10);
  }
  free_stream(s);
  return error;
}

//******************************************************************************
int DEFAULT_CC
get_pixel_safe(char* data, int x, int y, int width, int height, int bpp)
{
  int start;
  int shift;

  if (x < 0)
  {
    return 0;
  }
  if (y < 0)
  {
    return 0;
  }
  if (x >= width)
  {
    return 0;
  }
  if (y >= height)
  {
    return 0;
  }
  if (bpp == 1)
  {
    width = (width + 7) / 8;
    start = (y * width) + x / 8;
    shift = x % 8;
    return (data[start] & (0x80 >> shift)) != 0;
  }
  else if (bpp == 4)
  {
    width = (width + 1) / 2;
    start = y * width + x / 2;
    shift = x % 2;
    if (shift == 0)
    {
      return (data[start] & 0xf0) >> 4;
    }
    else
    {
      return data[start] & 0x0f;
    }
  }
  else if (bpp == 8)
  {
    return *(((unsigned char*)data) + (y * width + x));
  }
  else if (bpp == 15 || bpp == 16)
  {
    return *(((unsigned short*)data) + (y * width + x));
  }
  else if (bpp == 24 || bpp == 32)
  {
    return *(((unsigned int*)data) + (y * width + x));
  }
  else
  {
    g_writeln("error in get_pixel_safe bpp %d", bpp);
  }
  return 0;
}

/******************************************************************************/
void DEFAULT_CC
set_pixel_safe(char* data, int x, int y, int width, int height, int bpp,
               int pixel)
{
  int start;
  int shift;

  if (x < 0)
  {
    return;
  }
  if (y < 0)
  {
    return;
  }
  if (x >= width)
  {
    return;
  }
  if (y >= height)
  {
    return;
  }
  if (bpp == 1)
  {
    width = (width + 7) / 8;
    start = (y * width) + x / 8;
    shift = x % 8;
    if (pixel & 1)
    {
      data[start] = data[start] | (0x80 >> shift);
    }
    else
    {
      data[start] = data[start] & ~(0x80 >> shift);
    }
  }
  else if (bpp == 15 || bpp == 16)
  {
    *(((unsigned short*)data) + (y * width + x)) = pixel;
  }
  else if (bpp == 24)
  {
    *(data + (3 * (y * width + x)) + 0) = pixel >> 0;
    *(data + (3 * (y * width + x)) + 1) = pixel >> 8;
    *(data + (3 * (y * width + x)) + 2) = pixel >> 16;
  }
  else
  {
    g_writeln("error in set_pixel_safe bpp %d", bpp);
  }
}

/******************************************************************************/
int DEFAULT_CC
split_color(int pixel, int* r, int* g, int* b, int bpp, int* palette)
{
  if (bpp == 8)
  {
    if (pixel >= 0 && pixel < 256 && palette != 0)
    {
      *r = (palette[pixel] >> 16) & 0xff;
      *g = (palette[pixel] >> 8) & 0xff;
      *b = (palette[pixel] >> 0) & 0xff;
    }
  }
  else if (bpp == 16)
  {
    *r = ((pixel >> 8) & 0xf8) | ((pixel >> 13) & 0x7);
    *g = ((pixel >> 3) & 0xfc) | ((pixel >> 9) & 0x3);
    *b = ((pixel << 3) & 0xf8) | ((pixel >> 2) & 0x7);
  }
  else if (bpp == 24 || bpp == 32)
  {
    *r = (pixel >> 16) & 0xff;
    *g = (pixel >> 8) & 0xff;
    *b = pixel & 0xff;
  }
  else
  {
    g_writeln("error in split_color bpp %d", bpp);
  }
  return 0;
}

/******************************************************************************/
int DEFAULT_CC
make_color(int r, int g, int b, int bpp)
{
  if (bpp == 24)
  {
    return (r << 16) | (g << 8) | b;
  }
  else
  {
    g_writeln("error in make_color bpp %d", bpp);
  }
  return 0;
}

/******************************************************************************/
int DEFAULT_CC
lib_framebuffer_update(struct vnc* v)
{
  char* data;
  char* d1;
  char* d2;
  char cursor_data[32 * (32 * 3)];
  char cursor_mask[32 * (32 / 8)];
  char text[256];
  int num_recs;
  int i;
  int j;
  int k;
  int x;
  int y;
  int cx;
  int cy;
  int srcx;
  int srcy;
  int encoding;
  int Bpp;
  int pixel;
  int r;
  int g;
  int b;
  int data_size;
  int need_size;
  int error;
  struct stream* s;

  data_size = 0;
  data = 0;
  num_recs = 0;
  Bpp = (v->mod_bpp + 7) / 8;
  if (Bpp == 3)
  {
    Bpp = 4;
  }
  make_stream(s);
  init_stream(s, 8192);
  error = lib_recv(v, s->data, 3);
  if (error == 0)
  {
    in_uint8s(s, 1);
    in_uint16_be(s, num_recs);
    error = v->server_begin_update(v);
  }
  for (i = 0; i < num_recs; i++)
  {
    if (error != 0)
    {
      break;
    }
    init_stream(s, 8192);
    error = lib_recv(v, s->data, 12);
    if (error == 0)
    {
      in_uint16_be(s, x);
      in_uint16_be(s, y);
      in_uint16_be(s, cx);
      in_uint16_be(s, cy);
      in_uint32_be(s, encoding);
      if (encoding == 0) /* raw */
      {
        need_size = cx * cy * Bpp;
        if (need_size > data_size)
        {
          g_free(data);
          data = (char*)g_malloc(need_size, 0);
          data_size = need_size;
        }
        error = lib_recv(v, data, need_size);
        if (error == 0)
        {
          error = v->server_paint_rect(v, x, y, cx, cy, data, cx, cy, 0, 0);
        }
      }
      else if (encoding == 1) /* copy rect */
      {
        init_stream(s, 8192);
        error = lib_recv(v, s->data, 4);
        if (error == 0)
        {
          in_uint16_be(s, srcx);
          in_uint16_be(s, srcy);
          error = v->server_screen_blt(v, x, y, cx, cy, srcx, srcy);
        }
      }
      else if (encoding == 0xffffff11) /* cursor */
      {
        g_memset(cursor_data, 0, 32 * (32 * 3));
        g_memset(cursor_mask, 0, 32 * (32 / 8));
        j = cx * cy * Bpp;
        k = ((cx + 7) / 8) * cy;
        init_stream(s, j + k);
        error = lib_recv(v, s->data, j + k);
        if (error == 0)
        {
          in_uint8p(s, d1, j);
          in_uint8p(s, d2, k);
          for (j = 0; j < 32; j++)
          {
            for (k = 0; k < 32; k++)
            {
              pixel = get_pixel_safe(d2, k, 31 - j, cx, cy, 1);
              set_pixel_safe(cursor_mask, k, j, 32, 32, 1, !pixel);
              if (pixel)
              {
                pixel = get_pixel_safe(d1, k, 31 - j, cx, cy, v->mod_bpp);
                split_color(pixel, &r, &g, &b, v->mod_bpp, v->palette);
                pixel = make_color(r, g, b, 24);
                set_pixel_safe(cursor_data, k, j, 32, 32, 24, pixel);
              }
            }
          }
          /* keep these in 32x32, vnc cursor can be alot bigger */
          if (x > 31)
          {
            x = 31;
          }
          if (y > 31)
          {
            y = 31;
          }
          error = v->server_set_cursor(v, x, y, cursor_data, cursor_mask);
        }
      }
      else
      {
        g_sprintf(text, "error in lib_framebuffer_update encoding = %8.8x",
                  encoding);
        v->server_msg(v, text, 1);
      }
    }
  }
  if (error == 0)
  {
    error = v->server_end_update(v);
  }
  g_free(data);
  if (error == 0)
  {
    /* FrambufferUpdateRequest */
    init_stream(s, 8192);
    out_uint8(s, 3);
    out_uint8(s, 1);
    out_uint16_be(s, 0);
    out_uint16_be(s, 0);
    out_uint16_be(s, v->mod_width);
    out_uint16_be(s, v->mod_height);
    error = lib_send(v, s->data, 10);
  }
  free_stream(s);
  return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_clip_data(struct vnc* v)
{
  struct stream* s;
  struct stream* out_s;
  int size;
  int error;

  g_free(v->clip_data);
  v->clip_data = 0;
  v->clip_data_size = 0;
  make_stream(s);
  init_stream(s, 8192);
  error = lib_recv(v, s->data, 7);
  if (error == 0)
  {
    in_uint8s(s, 3);
    in_uint32_be(s, size);
    v->clip_data = (char*)g_malloc(size, 0);
    v->clip_data_size = size;
    error = lib_recv(v, v->clip_data, size);
  }
  if (error == 0)
  {
    make_stream(out_s);
    init_stream(out_s, 8192);
    out_uint16_le(out_s, 2);
    out_uint16_le(out_s, 0);
    out_uint32_le(out_s, 0x90);
    out_uint8(out_s, 0x0d);
    out_uint8s(out_s, 35);
    out_uint8(out_s, 0x10);
    out_uint8s(out_s, 35);
    out_uint8(out_s, 0x01);
    out_uint8s(out_s, 35);
    out_uint8(out_s, 0x07);
    out_uint8s(out_s, 35);
    out_uint8s(out_s, 4);
    s_mark_end(out_s);
    size = (int)(out_s->end - out_s->data);
    error = v->server_send_to_channel(v, v->clip_chanid, out_s->data, size);
    free_stream(out_s);
  }
  free_stream(s);
  return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_palette_update(struct vnc* v)
{
  struct stream* s;
  int first_color;
  int num_colors;
  int i;
  int r;
  int g;
  int b;
  int error;

  make_stream(s);
  init_stream(s, 8192);
  error = lib_recv(v, s->data, 5);
  if (error == 0)
  {
    in_uint8s(s, 1);
    in_uint16_be(s, first_color);
    in_uint16_be(s, num_colors);
    init_stream(s, 8192);
    error = lib_recv(v, s->data, num_colors * 6);
  }
  if (error == 0)
  {
    for (i = 0; i < num_colors; i++)
    {
      in_uint16_be(s, r);
      in_uint16_be(s, g);
      in_uint16_be(s, b);
      r = r >> 8;
      g = g >> 8;
      b = b >> 8;
      v->palette[first_color + i] = (r << 16) | (g << 8) | b;
    }
    error = v->server_begin_update(v);
  }
  if (error == 0)
  {
    error = v->server_palette(v, v->palette);
  }
  if (error == 0)
  {
    error = v->server_end_update(v);
  }
  free_stream(s);
  return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_signal(struct vnc* v)
{
  char type;
  int error;
  char text[256];

  error = lib_recv(v, &type, 1);
  if (error == 0)
  {
    if (type == 0) /* framebuffer update */
    {
      error = lib_framebuffer_update(v);
    }
    else if (type == 1) /* palette */
    {
      error = lib_palette_update(v);
    }
    else if (type == 3) /* clipboard */
    {
      error = lib_clip_data(v);
    }
    else
    {
      g_sprintf(text, "unknown in lib_mod_signal %d", type);
      v->server_msg(v, text, 1);
    }
  }
  return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_start(struct vnc* v, int w, int h, int bpp)
{
  v->server_begin_update(v);
  v->server_set_fgcolor(v, 0);
  v->server_fill_rect(v, 0, 0, w, h);
  v->server_end_update(v);
  v->server_width = w;
  v->server_height = h;
  v->server_bpp = bpp;
  return 0;
}

/******************************************************************************/
static int APP_CC
lib_open_clip_channel(struct vnc* v)
{
  char init_data[12] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  v->clip_chanid = v->server_get_channel_id(v, "cliprdr");
  if (v->clip_chanid >= 0)
  {
    v->server_send_to_channel(v, v->clip_chanid, init_data, 12);
  }
  return 0;
}

/******************************************************************************/
/*
  return error
*/
int DEFAULT_CC
lib_mod_connect(struct vnc* v)
{
  char cursor_data[32 * (32 * 3)];
  char cursor_mask[32 * (32 / 8)];
  char con_port[256];
  char text[256];
  struct stream* s;
  struct stream* pixel_format;
  int error;
  int i;
  int check_sec_result;

  v->server_msg(v, "started connecting", 0);
  check_sec_result = 1;
  /* only support 8 and 16 bpp connections from rdp client */
  if ((v->server_bpp != 8) && (v->server_bpp != 16) && (v->server_bpp != 24))
  {
    v->server_msg(v, "error - only supporting 8, 16 and 24 bpp rdp \
connections", 0);
    return 1;
  }
  if (g_strcmp(v->ip, "") == 0)
  {
    v->server_msg(v, "error - no ip set", 0);
    return 1;
  }
  make_stream(s);
  g_sprintf(con_port, "%s", v->port);
  make_stream(pixel_format);
  v->sck = g_tcp_socket();
  v->sck_obj = g_create_wait_obj_from_socket(v->sck, 0);
  v->sck_closed = 0;
  g_sprintf(text, "connecting to %s %s", v->ip, con_port);
  v->server_msg(v, text, 0);
  error = g_tcp_connect(v->sck, v->ip, con_port);
  if (error == 0)
  {
    v->server_msg(v, "tcp connected", 0);
    g_tcp_set_non_blocking(v->sck);
    g_tcp_set_no_delay(v->sck);
    /* protocal version */
    init_stream(s, 8192);
    error = lib_recv(v, s->data, 12);
    if (error == 0)
    {
      error = lib_send(v, "RFB 003.003\n", 12);
    }
    /* sec type */
    if (error == 0)
    {
      init_stream(s, 8192);
      error = lib_recv(v,  s->data, 4);
    }
    if (error == 0)
    {
      in_uint32_be(s, i);
      g_sprintf(text, "security level is %d (1 = none, 2 = standard)", i);
      v->server_msg(v, text, 0);
      if (i == 1) /* none */
      {
        check_sec_result = 0;
      }
      else if (i == 2) /* dec the password and the server random */
      {
        init_stream(s, 8192);
        error = lib_recv(v, s->data, 16);
        if (error == 0)
        {
          rfbEncryptBytes(s->data, v->password);
          error = lib_send(v, s->data, 16);
        }
      }
      else
      {
        error = 1;
      }
    }
  }
  if (error == 0 && check_sec_result)
  {
    /* sec result */
    init_stream(s, 8192);
    error = lib_recv(v, s->data, 4);
    if (error == 0)
    {
      in_uint32_be(s, i);
      if (i != 0)
      {
        v->server_msg(v, "password failed", 0);
        error = 2;
      }
      else
      {
        v->server_msg(v, "password ok", 0);
      }
    }
  }
  if (error == 0)
  {
    v->server_msg(v, "sending share flag", 0);
    init_stream(s, 8192);
    s->data[0] = 1;
    error = lib_send(v, s->data, 1); /* share flag */
  }
  if (error == 0)
  {
    v->server_msg(v, "receiving server init", 0);
    error = lib_recv(v, s->data, 4); /* server init */
  }
  if (error == 0)
  {
    in_uint16_be(s, v->mod_width);
    in_uint16_be(s, v->mod_height);
    init_stream(pixel_format, 8192);
    v->server_msg(v, "receiving pixel format", 0);
    error = lib_recv(v, pixel_format->data, 16);
  }
  if (error == 0)
  {
    v->mod_bpp = v->server_bpp;
    init_stream(s, 8192);
    v->server_msg(v, "receiving name length", 0);
    error = lib_recv(v, s->data, 4); /* name len */
  }
  if (error == 0)
  {
    in_uint32_be(s, i);
    if (i > 255 || i < 0)
    {
      error = 3;
    }
    else
    {
      v->server_msg(v, "receiving name", 0);
      error = lib_recv(v, v->mod_name, i);
      v->mod_name[i] = 0;
    }
  }
  /* should be connected */
  if (error == 0)
  {
    /* SetPixelFormat */
    init_stream(s, 8192);
    out_uint8(s, 0);
    out_uint8(s, 0);
    out_uint8(s, 0);
    out_uint8(s, 0);
    init_stream(pixel_format, 8192);
    if (v->mod_bpp == 8)
    {
      out_uint8(pixel_format, 8); /* bits per pixel */
      out_uint8(pixel_format, 8); /* depth */
#if defined(B_ENDIAN)
      out_uint8(pixel_format, 1); /* big endian */
#else
      out_uint8(pixel_format, 0); /* big endian */
#endif
      out_uint8(pixel_format, 0); /* true color flag */
      out_uint16_be(pixel_format, 0); /* red max */
      out_uint16_be(pixel_format, 0); /* green max */
      out_uint16_be(pixel_format, 0); /* blue max */
      out_uint8(pixel_format, 0); /* red shift */
      out_uint8(pixel_format, 0); /* green shift */
      out_uint8(pixel_format, 0); /* blue shift */
      out_uint8s(pixel_format, 3); /* pad */
    }
    else if (v->mod_bpp == 16)
    {
      out_uint8(pixel_format, 16); /* bits per pixel */
      out_uint8(pixel_format, 16); /* depth */
#if defined(B_ENDIAN)
      out_uint8(pixel_format, 1); /* big endian */
#else
      out_uint8(pixel_format, 0); /* big endian */
#endif
      out_uint8(pixel_format, 1); /* true color flag */
      out_uint16_be(pixel_format, 31); /* red max */
      out_uint16_be(pixel_format, 63); /* green max */
      out_uint16_be(pixel_format, 31); /* blue max */
      out_uint8(pixel_format, 11); /* red shift */
      out_uint8(pixel_format, 5); /* green shift */
      out_uint8(pixel_format, 0); /* blue shift */
      out_uint8s(pixel_format, 3); /* pad */
    }
    else if (v->mod_bpp == 24)
    {
      out_uint8(pixel_format, 32); /* bits per pixel */
      out_uint8(pixel_format, 24); /* depth */
#if defined(B_ENDIAN)
      out_uint8(pixel_format, 1); /* big endian */
#else
      out_uint8(pixel_format, 0); /* big endian */
#endif
      out_uint8(pixel_format, 1); /* true color flag */
      out_uint16_be(pixel_format, 255); /* red max */
      out_uint16_be(pixel_format, 255); /* green max */
      out_uint16_be(pixel_format, 255); /* blue max */
      out_uint8(pixel_format, 16); /* red shift */
      out_uint8(pixel_format, 8); /* green shift */
      out_uint8(pixel_format, 0); /* blue shift */
      out_uint8s(pixel_format, 3); /* pad */
    }
    out_uint8a(s, pixel_format->data, 16);
    v->server_msg(v, "sending pixel format", 0);
    error = lib_send(v, s->data, 20);
  }
  if (error == 0)
  {
    /* SetEncodings */
    init_stream(s, 8192);
    out_uint8(s, 2);
    out_uint8(s, 0);
    out_uint16_be(s, 3);
    out_uint32_be(s, 0); /* raw */
    out_uint32_be(s, 1); /* copy rect */
    out_uint32_be(s, 0xffffff11); /* cursor */
    v->server_msg(v, "sending encodings", 0);
    error = lib_send(v, s->data, 4 + 3 * 4);
  }
  if (error == 0)
  {
    error = v->server_reset(v, v->mod_width, v->mod_height, v->mod_bpp);
  }
  if (error == 0)
  {
    /* FrambufferUpdateRequest */
    init_stream(s, 8192);
    out_uint8(s, 3);
    out_uint8(s, 0);
    out_uint16_be(s, 0);
    out_uint16_be(s, 0);
    out_uint16_be(s, v->mod_width);
    out_uint16_be(s, v->mod_height);
    v->server_msg(v, "sending framebuffer update request", 0);
    error = lib_send(v, s->data, 10);
  }
  if (error == 0)
  {
    if (v->server_bpp != v->mod_bpp)
    {
      v->server_msg(v, "error - server and client bpp don't match", 0);
      error = 1;
    }
  }
  if (error == 0)
  {
    /* set almost null cursor, this is the little dot cursor */
    g_memset(cursor_data, 0, 32 * (32 * 3));
    g_memset(cursor_data + (32 * (32 * 3) - 1 * 32 * 3), 0xff, 9);
    g_memset(cursor_data + (32 * (32 * 3) - 2 * 32 * 3), 0xff, 9);
    g_memset(cursor_data + (32 * (32 * 3) - 3 * 32 * 3), 0xff, 9);
    g_memset(cursor_mask, 0xff, 32 * (32 / 8));
    v->server_msg(v, "sending cursor", 0);
    error = v->server_set_cursor(v, 3, 3, cursor_data, cursor_mask);
  }
  free_stream(s);
  free_stream(pixel_format);
  if (error == 0)
  {
    v->server_msg(v, "connection complete, connected ok", 0);
    lib_open_clip_channel(v);
  }
  else
  {
    v->server_msg(v, "error - problem connecting", 0);
  }
  return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_end(struct vnc* v)
{
  if (v->vnc_desktop != 0)
  {
  }
  g_free(v->clip_data);
  v->clip_data = 0;
  v->clip_data_size = 0;
  return 0;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_set_param(struct vnc* v, char* name, char* value)
{
  if (g_strcasecmp(name, "username") == 0)
  {
    g_strncpy(v->username, value, 255);
  }
  else if (g_strcasecmp(name, "password") == 0)
  {
    g_strncpy(v->password, value, 255);
  }
  else if (g_strcasecmp(name, "ip") == 0)
  {
    g_strncpy(v->ip, value, 255);
  }
  else if (g_strcasecmp(name, "port") == 0)
  {
    g_strncpy(v->port, value, 255);
  }
  else if (g_strcasecmp(name, "keylayout") == 0)
  {
    v->keylayout = g_atoi(value);
  }
  return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_get_wait_objs(struct vnc* v, tbus* read_objs, int* rcount,
                      tbus* write_objs, int* wcount, int* timeout)
{
  int i;

  i = *rcount;
  if (v != 0)
  {
    if (v->sck_obj != 0)
    {
      read_objs[i++] = v->sck_obj;
    }
  }
  *rcount = i;
  return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_check_wait_objs(struct vnc* v)
{
  int rv;

  rv = 0;
  if (v != 0)
  {
    if (v->sck_obj != 0)
    {
      if (g_is_wait_obj_set(v->sck_obj))
      {
        rv = lib_mod_signal(v);
      }
    }
  }
  return rv;
}

/******************************************************************************/
struct vnc* EXPORT_CC
mod_init(void)
{
  struct vnc* v;

  v = (struct vnc*)g_malloc(sizeof(struct vnc), 1);
  /* set client functions */
  v->size = sizeof(struct vnc);
  v->handle = (long)v;
  v->mod_connect = lib_mod_connect;
  v->mod_start = lib_mod_start;
  v->mod_event = lib_mod_event;
  v->mod_signal = lib_mod_signal;
  v->mod_end = lib_mod_end;
  v->mod_set_param = lib_mod_set_param;
  v->mod_get_wait_objs = lib_mod_get_wait_objs;
  v->mod_check_wait_objs = lib_mod_check_wait_objs;
  return v;
}

/******************************************************************************/
int EXPORT_CC
mod_exit(struct vnc* v)
{
  if (v == 0)
  {
    return 0;
  }
  g_delete_wait_obj_from_socket(v->sck_obj);
  g_tcp_close(v->sck);
  g_free(v);
  return 0;
}
