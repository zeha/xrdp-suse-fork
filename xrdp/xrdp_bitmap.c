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

   bitmap, drawable
   this is a object that can be drawn on with a painter
   all windows, bitmaps, even the screen are of this type
   maybe it should be called xrdp_drawable

*/

#include "xrdp.h"

static int g_crc_seed = 0xffffffff;
static int g_crc_table[256] =
{
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
  0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
  0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
  0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
  0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
  0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
  0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
  0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
  0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
  0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
  0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
  0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
  0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
  0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
  0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
  0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
  0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
  0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
  0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
  0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
  0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
  0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

#define CRC_START(in_crc) (in_crc) = g_crc_seed
#define CRC_PASS(in_pixel, in_crc) \
  (in_crc) = g_crc_table[((in_crc) ^ (in_pixel)) & 0xff] ^ ((in_crc) >> 8)
#define CRC_END(in_crc) (in_crc) = ((in_crc) ^ g_crc_seed)

/*****************************************************************************/
struct xrdp_bitmap* APP_CC
xrdp_bitmap_create(int width, int height, int bpp,
                   int type, struct xrdp_wm* wm)
{
  struct xrdp_bitmap* self;
  int Bpp;

  self = (struct xrdp_bitmap*)g_malloc(sizeof(struct xrdp_bitmap), 1);
  self->type = type;
  self->width = width;
  self->height = height;
  self->bpp = bpp;
  Bpp = 4;
  switch (bpp)
  {
    case 8: Bpp = 1; break;
    case 15: Bpp = 2; break;
    case 16: Bpp = 2; break;
  }
  if (self->type == WND_TYPE_BITMAP ||
      self->type == WND_TYPE_IMAGE ||
      self->type == WND_TYPE_TILE)
  {
    self->data = (char*)g_malloc(width * height * Bpp, 0);
  }
  if (self->type != WND_TYPE_BITMAP)
  {
    self->child_list = list_create();
  }
  self->line_size = width * Bpp;
  self->line_width = width;
  self->lines = height;
  if (self->type == WND_TYPE_COMBO)
  {
    self->string_list = list_create();
    self->string_list->auto_free = 1;
    self->data_list = list_create();
    self->data_list->auto_free = 1;
  }
  self->wm = wm;
  return self;
}

/*****************************************************************************/
struct xrdp_bitmap* APP_CC
xrdp_bitmap_create_with_data(int width, int height,
                             int bpp, char* data,
                             struct xrdp_wm* wm)
{
  struct xrdp_bitmap* self;

  self = (struct xrdp_bitmap*)g_malloc(sizeof(struct xrdp_bitmap), 1);
  self->type = WND_TYPE_BITMAP;
  self->width = width;
  self->height = height;
  self->bpp = bpp;
  self->data = data;
  self->line_width = width;
  self->lines = height;
  self->do_not_free_data = 1;
  self->wm = wm;
  return self;
}

/*****************************************************************************/
void APP_CC
xrdp_bitmap_delete(struct xrdp_bitmap* self)
{
  int i;
  struct xrdp_mod_data* mod_data;

  if (self == 0)
  {
    return;
  }
  if (self->wm != 0)
  {
    if (self->wm->focused_window != 0)
    {
      if (self->wm->focused_window->focused_control == self)
      {
        self->wm->focused_window->focused_control = 0;
      }
    }
    if (self->wm->focused_window == self)
    {
      self->wm->focused_window = 0;
    }
    if (self->wm->dragging_window == self)
    {
      self->wm->dragging_window = 0;
    }
    if (self->wm->button_down == self)
    {
      self->wm->button_down = 0;
    }
    if (self->wm->popup_wnd == self)
    {
      self->wm->popup_wnd = 0;
    }
    if (self->wm->login_window == self)
    {
      self->wm->login_window = 0;
    }
    if (self->wm->log_wnd == self)
    {
      self->wm->log_wnd = 0;
    }
  }
  if (self->child_list != 0)
  {
    for (i = self->child_list->count - 1; i >= 0; i--)
    {
      xrdp_bitmap_delete((struct xrdp_bitmap*)self->child_list->items[i]);
    }
    list_delete(self->child_list);
  }
  if (self->parent != 0)
  {
    i = list_index_of(self->parent->child_list, (long)self);
    if (i >= 0)
    {
      list_remove_item(self->parent->child_list, i);
    }
  }
  if (self->string_list != 0) /* for combo */
  {
    list_delete(self->string_list);
  }
  if (self->data_list != 0) /* for combo */
  {
    for (i = 0; i < self->data_list->count; i++)
    {
      mod_data = (struct xrdp_mod_data*)list_get_item(self->data_list, i);
      if (mod_data != 0)
      {
        list_delete(mod_data->names);
        list_delete(mod_data->values);
      }
    }
    list_delete(self->data_list);
  }
  if (!self->do_not_free_data)
  {
    g_free(self->data);
  }
  g_free(self->caption1);
  g_free(self);
}

/*****************************************************************************/
struct xrdp_bitmap* APP_CC
xrdp_bitmap_get_child_by_id(struct xrdp_bitmap* self, int id)
{
  int i;
  struct xrdp_bitmap* b;

  for (i = 0; i < self->child_list->count; i++)
  {
    b = (struct xrdp_bitmap*)list_get_item(self->child_list, i);
    if (b->id == id)
    {
      return b;
    }
  }
  return 0;
}

/*****************************************************************************/
/* if focused is true focus this window else unfocus it */
/* returns error */
int APP_CC
xrdp_bitmap_set_focus(struct xrdp_bitmap* self, int focused)
{
  struct xrdp_painter* painter;

  if (self == 0)
  {
    return 0;
  }
  if (self->type != WND_TYPE_WND) /* 1 */
  {
    return 0;
  }
  painter = xrdp_painter_create(self->wm, self->wm->session);
  xrdp_painter_font_needed(painter);
  xrdp_painter_begin_update(painter);

  /* bottom dark gray line */
  painter->fg_color = self->wm->dark_grey;
  xrdp_painter_fill_rect(painter, self, 2, 22, self->width - 4, 1); 
  if (focused)
  {
    /* active title bar */
    painter->fg_color = self->wm->dark_blue;
    xrdp_painter_fill_rect(painter, self, 2, 2, self->width - 4, 20);
    painter->fg_color = self->wm->white;
  }
  else
  {
    /* inactive title bar */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, 2, 2, self->width - 4, 20);
    painter->fg_color = self->wm->black;
  }
  xrdp_painter_draw_text(painter, self, 8, 4, self->caption1);
  xrdp_painter_end_update(painter);
  xrdp_painter_delete(painter);
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_bitmap_get_index(struct xrdp_bitmap* self, int* palette, int color)
{
  int r;
  int g;
  int b;

  r = (color & 0xff0000) >> 16;
  g = (color & 0x00ff00) >> 8;
  b = (color & 0x0000ff) >> 0;
  r = (r >> 5) << 0;
  g = (g >> 5) << 3;
  b = (b >> 6) << 6;
  return (b | g | r);
}

/*****************************************************************************/
/* returns error */
int APP_CC
xrdp_bitmap_resize(struct xrdp_bitmap* self, int width, int height)
{
  int Bpp;
  
  Bpp = 4;
  switch (self->bpp)
  {
    case 8: Bpp = 1; break;
    case 15: Bpp = 2; break;
    case 16: Bpp = 2; break;
  }
 
  if ((width * Bpp == self->line_size) && (height == self->lines))
  {
    return 0;
  }
  if (self->do_not_free_data)
  {
    return 1;
  }
  if (self->type == WND_TYPE_IMAGE)
  {
    self->width = width;
    self->height = height;
  }
  g_free(self->data);
  self->data = (char*)g_malloc(width * height * Bpp, 0);
  self->line_size = width * Bpp;
  self->line_width = width;
  self->lines = height;
  return 0;
}

/*****************************************************************************/
/* load a bmp file */
/* return 0 ok */
/* return 1 error */
int APP_CC
xrdp_bitmap_load(struct xrdp_bitmap* self, const char* filename, int* palette)
{
  int fd;
  int i;
  int j;
  int k;
  int color;
  int size;
  int palette1[256];
  char type1[3];
  char* data;
  struct xrdp_bmp_header header;
  struct stream* s;

  if (!g_file_exist(filename))
  {
    g_writeln("xrdp_bitmap_load: error bitmap file [%s] does not exist",
              filename);
    return 1;
  }
  s = 0;
  fd = g_file_open(filename);
  if (fd != -1)
  {
    /* read file type */
    if (g_file_read(fd, type1, 2) != 2)
    {
      g_file_close(fd);
      return 1;
    }
    if (type1[0] != 'B' || type1[1] != 'M')
    {
      g_file_close(fd);
      return 1;
    }
    /* read file size */
    size = 0;
    g_file_read(fd, (char*)&size, 4);
    /* read bmp header */
    g_file_seek(fd, 14);
    make_stream(s);
    init_stream(s, 8192);
    g_file_read(fd, s->data, 40); /* size better be 40 */
    in_uint32_le(s, header.size);
    in_uint32_le(s, header.image_width);
    in_uint32_le(s, header.image_height);
    in_uint16_le(s, header.planes);
    in_uint16_le(s, header.bit_count);
    in_uint32_le(s, header.compression);
    in_uint32_le(s, header.image_size);
    in_uint32_le(s, header.x_pels_per_meter);
    in_uint32_le(s, header.y_pels_per_meter);
    in_uint32_le(s, header.clr_used);
    in_uint32_le(s, header.clr_important);
    if (header.bit_count != 8 && header.bit_count != 24)
    {
      free_stream(s);
      g_file_close(fd);
      return 1;
    }
    if (header.bit_count == 24) /* 24 bit bitmap */
    {
      g_file_seek(fd, 14 + header.size);
    }
    if (header.bit_count == 8) /* 8 bit bitmap */
    {
      /* read palette */
      g_file_seek(fd, 14 + header.size);
      init_stream(s, 8192);
      g_file_read(fd, s->data, 256 * sizeof(int));
      for (i = 0; i < 256; i++)
      {
        in_uint32_le(s, palette1[i]);
      }
      /* read data */
      xrdp_bitmap_resize(self, header.image_width, header.image_height);
      data = (char*)g_malloc(header.image_width * header.image_height, 1);
      for (i = header.image_height - 1; i >= 0; i--)
      {
        g_file_read(fd, data + i * header.image_width, header.image_width);
      }
      for (i = 0; i < self->lines; i++)
      {
        for (j = 0; j < self->line_width; j++)
        {
          k = (unsigned char)data[i * header.image_width + j];
          color = palette1[k];
          if (self->bpp == 8)
          {
            color = xrdp_bitmap_get_index(self, palette, color);
          }
          else if (self->bpp == 15)
          {
            color = COLOR15((color & 0xff0000) >> 16,
                            (color & 0x00ff00) >> 8,
                            (color & 0x0000ff) >> 0);
          }
          else if (self->bpp == 16)
          {
            color = COLOR16((color & 0xff0000) >> 16,
                            (color & 0x00ff00) >> 8,
                            (color & 0x0000ff) >> 0);
          }
          else if (self->bpp == 24)
          {
            //color = COLOR24((color & 0xff0000) >> 16,
            //                (color & 0x00ff00) >> 8,
            //                (color & 0x0000ff) >> 0);
          }
          xrdp_bitmap_set_pixel(self, j, i, color);
        }
      }
      g_free(data);
    }
    g_file_close(fd);
  }
  free_stream(s);
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_bitmap_get_pixel(struct xrdp_bitmap* self, int x, int y)
{
  if (self == 0)
  {
    return 0;
  }
  if (self->data == 0)
  {
    return 0;
  }
  if (x >= 0 && x < self->line_width && y >= 0 && y < self->lines)
  {
    if (self->bpp == 8)
    {
      return GETPIXEL8(self->data, x, y, self->line_width);
    }
    else if (self->bpp == 15 || self->bpp == 16)
    {
      return GETPIXEL16(self->data, x, y, self->line_width);
    }
    else if (self->bpp == 24)
    {
      return GETPIXEL32(self->data, x, y, self->line_width);
    }
  }
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_bitmap_set_pixel(struct xrdp_bitmap* self, int x, int y, int pixel)
{
  if (self == 0)
  {
    return 0;
  }
  if (self->data == 0)
  {
    return 0;
  }
  if (x >= 0 && x < self->line_width && y >= 0 && y < self->lines)
  {
    if (self->bpp == 8)
    {
      SETPIXEL8(self->data, x, y, self->line_width, pixel);
    }
    else if (self->bpp == 15 || self->bpp == 16)
    {
      SETPIXEL16(self->data, x, y, self->line_width, pixel);
    }
    else if (self->bpp == 24)
    {
      SETPIXEL32(self->data, x, y, self->line_width, pixel);
    }
  }
  return 0;
}

/*****************************************************************************/
/* copy part of self at x, y to 0, 0 in dest */
/* returns error */
int APP_CC
xrdp_bitmap_copy_box(struct xrdp_bitmap* self,
                     struct xrdp_bitmap* dest,
                     int x, int y, int cx, int cy)
{
  int i;
  int j;
  int destx;
  int desty;
  int pixel;

  if (self == 0)
  {
    return 1;
  }
  if (dest == 0)
  {
    return 1;
  }
  if (self->type != WND_TYPE_BITMAP &&
      self->type != WND_TYPE_IMAGE &&
      self->type != WND_TYPE_TILE)
  {
    return 1;
  }
  if (dest->type != WND_TYPE_BITMAP &&
      dest->type != WND_TYPE_IMAGE &&
      dest->type != WND_TYPE_TILE)
  {
    return 1;
  }
  if (self->bpp != dest->bpp)
  {
    return 1;
  }
  destx = 0;
  desty = 0;
  if (!check_bounds(self, &x, &y, &cx, &cy))
  {
    return 1;
  }
  if (!check_bounds(dest, &destx, &desty, &cx, &cy))
  {
    return 1;
  }
  if (self->bpp == 24)
  {
    for (i = 0; i < cy; i++)
    {
      for (j = 0; j < cx; j++)
      {
        pixel = GETPIXEL32(self->data, j + x, i + y, self->line_width);
        SETPIXEL32(dest->data, j + destx, i + desty, dest->line_width, pixel);
      }
    }
  }
  else if (self->bpp == 15 || self->bpp == 16)
  {
    for (i = 0; i < cy; i++)
    {
      for (j = 0; j < cx; j++)
      {
        pixel = GETPIXEL16(self->data, j + x, i + y, self->line_width);
        SETPIXEL16(dest->data, j + destx, i + desty, dest->line_width, pixel);
      }
    }
  }
  else if (self->bpp == 8)
  {
    for (i = 0; i < cy; i++)
    {
      for (j = 0; j < cx; j++)
      {
        pixel = GETPIXEL8(self->data, j + x, i + y, self->line_width);
        SETPIXEL8(dest->data, j + destx, i + desty, dest->line_width, pixel);
      }
    }
  }
  else
  {
    return 1;
  }
  return 0;
}

/*****************************************************************************/
/* copy part of self at x, y to 0, 0 in dest */
/* returns error */
int APP_CC
xrdp_bitmap_copy_box_with_crc(struct xrdp_bitmap* self,
                              struct xrdp_bitmap* dest,
                              int x, int y, int cx, int cy)
{
  int i;
  int j;
  int destx;
  int desty;
  int pixel;
  int crc;
  int incs;
  int incd;
  unsigned char* s8;
  unsigned char* d8;
  unsigned short* s16;
  unsigned short* d16;

  if (self == 0)
  {
    return 1;
  }
  if (dest == 0)
  {
    return 1;
  }
  if (self->type != WND_TYPE_BITMAP &&
      self->type != WND_TYPE_IMAGE &&
      self->type != WND_TYPE_TILE)
  {
    return 1;
  }
  if (dest->type != WND_TYPE_BITMAP &&
      dest->type != WND_TYPE_IMAGE &&
      dest->type != WND_TYPE_TILE)
  {
    return 1;
  }
  if (self->bpp != dest->bpp)
  {
    return 1;
  }
  destx = 0;
  desty = 0;
  if (!check_bounds(self, &x, &y, &cx, &cy))
  {
    return 1;
  }
  if (!check_bounds(dest, &destx, &desty, &cx, &cy))
  {
    return 1;
  }
  crc = dest->crc;
  CRC_START(crc);
  if (self->bpp == 24)
  {
    for (i = 0; i < cy; i++)
    {
      for (j = 0; j < cx; j++)
      {
        pixel = GETPIXEL32(self->data, j + x, i + y, self->line_width);
        CRC_PASS(pixel, crc);
        CRC_PASS(pixel >> 8, crc);
        CRC_PASS(pixel >> 16, crc);
        SETPIXEL32(dest->data, j + destx, i + desty, dest->line_width, pixel);
      }
    }
  }
  else if (self->bpp == 15 || self->bpp == 16)
  {
    s16 = ((unsigned short*)(self->data)) + (self->line_width * y + x);
    d16 = ((unsigned short*)(dest->data)) + (dest->line_width * desty + destx);
    incs = self->line_width - cx;
    incd = dest->line_width - cx;
    for (i = 0; i < cy; i++)
    {
      for (j = 0; j < cx; j++)
      {
        pixel = *s16;
        CRC_PASS(pixel, crc);
        CRC_PASS(pixel >> 8, crc);
        *d16 = pixel;
        s16++;
        d16++;
      }
      s16 += incs;
      d16 += incd;
    }
  }
  else if (self->bpp == 8)
  {
    s8 = ((unsigned char*)(self->data)) + (self->line_width * y + x);
    d8 = ((unsigned char*)(dest->data)) + (dest->line_width * desty + destx);
    incs = self->line_width - cx;
    incd = dest->line_width - cx;
    for (i = 0; i < cy; i++)
    {
      for (j = 0; j < cx; j++)
      {
        pixel = *s8;
        CRC_PASS(pixel, crc);
        *d8 = pixel;
        s8++;
        d8++;
      }
      s8 += incs;
      d8 += incd;
    }
  }
  else
  {
    return 1;
  }
  CRC_END(crc);
  dest->crc = crc;
  return 0;
}

/*****************************************************************************/
/* returns true if they are the same, else returns false */
int APP_CC
xrdp_bitmap_compare(struct xrdp_bitmap* self,
                    struct xrdp_bitmap* b)
{
  if (self == 0)
  {
    return 0;
  }
  if (b == 0)
  {
    return 0;
  }
  if (self->bpp != b->bpp)
  {
    return 0;
  }
  if (self->line_width != b->line_width)
  {
    return 0;
  }
  if (self->lines != b->lines)
  {
    return 0;
  }
  if (g_memcmp(self->data, b->data, b->lines * b->line_size) == 0)
  {
    return 1;
  }
  return 0;
}

/*****************************************************************************/
/* returns true if they are the same, else returns false */
int APP_CC
xrdp_bitmap_compare_with_crc(struct xrdp_bitmap* self,
                             struct xrdp_bitmap* b)
{
  if (self == 0)
  {
    return 0;
  }
  if (b == 0)
  {
    return 0;
  }
  if (self->bpp != b->bpp)
  {
    return 0;
  }
  if (self->line_width != b->line_width)
  {
    return 0;
  }
  if (self->lines != b->lines)
  {
    return 0;
  }
  if (self->crc == b->crc)
  {
    return 1;
  }
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_bitmap_draw_focus_box(struct xrdp_bitmap* self,
                           struct xrdp_painter* painter,
                           int x, int y, int cx, int cy)
{
  painter->rop = 0xf0;
  xrdp_painter_begin_update(painter);
  painter->use_clip = 0;
  painter->mix_mode = 1;
  painter->brush.pattern[0] = 0xaa;
  painter->brush.pattern[1] = 0x55;
  painter->brush.pattern[2] = 0xaa;
  painter->brush.pattern[3] = 0x55;
  painter->brush.pattern[4] = 0xaa;
  painter->brush.pattern[5] = 0x55;
  painter->brush.pattern[6] = 0xaa;
  painter->brush.pattern[7] = 0x55;
  painter->brush.x_orgin = x;
  painter->brush.x_orgin = x;
  painter->brush.style = 3;
  painter->fg_color = self->wm->black;
  painter->bg_color = self->parent->bg_color;
  /* top */
  xrdp_painter_fill_rect(painter, self, x, y, cx, 1);
  /* bottom */
  xrdp_painter_fill_rect(painter, self, x, y + (cy - 1), cx, 1);
  /* left */
  xrdp_painter_fill_rect(painter, self, x, y + 1, 1, cy - 2);
  /* right */
  xrdp_painter_fill_rect(painter, self, x + (cx - 1), y + 1, 1, cy - 2);
  xrdp_painter_end_update(painter);
  painter->rop = 0xcc;
  painter->mix_mode = 0;
  return 0;
}

/*****************************************************************************/
/* x and y are in relation to self for 0, 0 is the top left of the control */
static int APP_CC
xrdp_bitmap_draw_button(struct xrdp_bitmap* self,
                        struct xrdp_painter* painter,
                        int x, int y, int w, int h,
                        int down)
{
  if (down)
  {
    /* medium gray box */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, x, y, w, h);
    /* dark grey top line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, x, y, w, 1);
    /* dark grey left line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, x, y, 1, h);
    /* medium grey top line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, x + 1, y + 1, w - 2, 1);
    /* medium grey left line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, x + 1, y + 1, 1, h - 2);
    /* white bottom line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, x + 1, y + (h - 2), w - 1, 1);
    /* white right line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, x + (w - 2), y + 1, 1, h - 1);
    /* dark grey bottom line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, x, y + (h - 1), w, 1);
    /* dark grey right line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, x + (w - 1), y, 1, h);
  }
  else
  {
    /* gray box */
    painter->fg_color = self->wm->grey;
    xrdp_painter_fill_rect(painter, self, x, y, w, h);
    /* dark grey top line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, x, y, w, 1);
    /* dark grey left line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, x, y, 1, h);
    /* white top line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, x + 1, y + 1, w - 2, 1);
    /* white left line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, x + 1, y + 1, 1, h - 2);
    /* medium grey bottom line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, x + 1, y + (h - 2), w - 1, 1);
    /* medium grey right line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, x + (w - 2), y + 1, 1, h - 1);
    /* dark grey bottom line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, x, y + (h - 1), w, 1);
    /* dark grey right line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, x + (w - 1), y, 1, h);
  }
  return 0;
}

/*****************************************************************************/
/* nil for rect means the whole thing */
/* returns error */
int APP_CC
xrdp_bitmap_invalidate(struct xrdp_bitmap* self, struct xrdp_rect* rect)
{
  int i;
  int w;
  int h;
  int x;
  int y;
  struct xrdp_bitmap* b;
  struct xrdp_rect r1;
  struct xrdp_rect r2;
  struct xrdp_painter* painter;
  twchar wtext[256];
  char text[256];
  char* p;

  if (self == 0) /* if no bitmap */
  {
    return 0;
  }
  if (self->type == WND_TYPE_BITMAP) /* if 0, bitmap, leave */
  {
    return 0;
  }
  painter = xrdp_painter_create(self->wm, self->wm->session);
  xrdp_painter_font_needed(painter);
  painter->rop = 0xcc; /* copy */
  if (rect == 0)
  {
    painter->use_clip = 0;
  }
  else
  {
    if (ISRECTEMPTY(*rect))
    {
      xrdp_painter_delete(painter);
      return 0;
    }
    painter->clip = *rect;
    painter->use_clip = &painter->clip;
  }
  xrdp_painter_begin_update(painter);
  if (self->type == WND_TYPE_WND) /* 1 */
  {
    /* draw grey background */
    painter->fg_color = self->bg_color;
    xrdp_painter_fill_rect(painter, self, 0, 0, self->width, self->height);
    /* top grey line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, 0, 0, self->width, 1);
    /* left grey line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, 0, 0, 1, self->height);

    /* top white line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, 1, 1, self->width - 2, 1);
    /* left white line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, 1, 1, 1, self->height - 2);

    /* bottom medium grey line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, 1, self->height - 2,
                           self->width - 2, 1);
    /* right medium grey line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, self->width - 2, 1, 1,
                           self->height - 2);
    /* bottom dark grey line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, 0, self->height - 1,
                           self->width, 1);
    /* right dark grey line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, self->width - 1, 0,
                           1, self->height);

    /* bottom dark gray line */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, 2, 22, self->width - 4, 1); 
    if (self->wm->focused_window == self)
    {
      /* active title bar */
      painter->fg_color = self->wm->dark_blue;
      xrdp_painter_fill_rect(painter, self, 2, 2, self->width - 4, 20);
      painter->fg_color = self->wm->white;
    }
    else
    {
      /* inactive title bar */
      painter->fg_color = self->wm->dark_grey;
      xrdp_painter_fill_rect(painter, self, 2, 2, self->width - 4, 20);
      painter->fg_color = self->wm->black;
    }
    xrdp_painter_draw_text(painter, self, 8, 4, self->caption1);
  }
  else if (self->type == WND_TYPE_SCREEN) /* 2 */
  {
    if (self->wm->mm->mod != 0)
    {
      if (self->wm->mm->mod->mod_event != 0)
      {
        if (rect != 0)
        {
          x = rect->left;
          y = rect->top;
          w = rect->right - rect->left;
          h = rect->bottom - rect->top;
          if (check_bounds(self->wm->screen, &x, &y, &w, &h))
          {
            self->wm->mm->mod->mod_event(self->wm->mm->mod, WM_INVALIDATE,
                                         MAKELONG(y, x), MAKELONG(h, w),
                                         0, 0);
          }
        }
        else
        {
          x = 0;
          y = 0;
          w = self->wm->screen->width;
          h = self->wm->screen->height;
          self->wm->mm->mod->mod_event(self->wm->mm->mod, WM_INVALIDATE,
                                       MAKELONG(y, x), MAKELONG(h, w),
                                       0, 0);
        }
      }
    }
    else
    {
      painter->fg_color = self->bg_color;
      xrdp_painter_fill_rect(painter, self, 0, 0, self->width, self->height);
    }
  }
  else if (self->type == WND_TYPE_BUTTON) /* 3 */
  {
    if (self->state == BUTTON_STATE_UP) /* 0 */
    {
      xrdp_bitmap_draw_button(self, painter, 0, 0,
                              self->width, self->height, 0);
      w = xrdp_painter_text_width(painter, self->caption1);
      h = xrdp_painter_text_height(painter, self->caption1);
      painter->fg_color = self->wm->black;
      xrdp_painter_draw_text(painter, self, self->width / 2 - w / 2,
                             self->height / 2 - h / 2, self->caption1);
      if (self->parent != 0)
      {
        if (self->wm->focused_window == self->parent)
        {
          if (self->parent->focused_control == self)
          {
            xrdp_bitmap_draw_focus_box(self, painter, 4, 4, self->width - 8,
                                       self->height - 8);
          }
        }
      }
    }
    else if (self->state == BUTTON_STATE_DOWN) /* 1 */
    {
      xrdp_bitmap_draw_button(self, painter, 0, 0,
                              self->width, self->height, 1);
      w = xrdp_painter_text_width(painter, self->caption1);
      h = xrdp_painter_text_height(painter, self->caption1);
      painter->fg_color = self->wm->black;
      xrdp_painter_draw_text(painter, self, (self->width / 2 - w / 2) + 1,
                             (self->height / 2 - h / 2) + 1, self->caption1);
      if (self->parent != 0)
        if (self->wm->focused_window == self->parent)
          if (self->parent->focused_control == self)
            xrdp_bitmap_draw_focus_box(self, painter, 4, 4, self->width - 8,
                                       self->height - 8);
    }
  }
  else if (self->type == WND_TYPE_IMAGE) /* 4 */
  {
    xrdp_painter_copy(painter, self, self, 0, 0, self->width,
                      self->height, 0, 0);
  }
  else if (self->type == WND_TYPE_EDIT) /* 5 */
  {
    /* draw dark gray box */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, 0, 0, self->width, self->height);
    /* main white background */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, 2, 2, self->width - 4,
                           self->height - 4);
    /* medium grey top line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, 1, 1, self->width - 2, 1);
    /* medium grey left line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, 1, 1, 1, self->height - 2);
    /* white bottom line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, 1, self->height- 2, self->width - 2, 1);
    /* white right line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, self->width - 2, 1, 1, self->height - 2);
    /* draw text */
    painter->fg_color = self->wm->black;
    if (self->password_char != 0)
    {
      i = MIN (g_mbstowcs(0, self->caption1, 0), 255);
      g_memset(text, self->password_char, i);
      text[i] = 0;
      xrdp_painter_draw_text(painter, self, 4, 2, text);
    }
    else
    {
      char *cap = self->caption1;
      int  pos;

      i = 2;
      for (;;)
      {
        for (pos = 0; cap[pos] != '\0' && cap[pos] != '\n'; pos++);

        if (cap[pos] == '\0')
        {
          xrdp_painter_draw_text(painter, self, 4, i, cap);
          break;
        }
        cap[pos] = '\0';
        xrdp_painter_draw_text(painter, self, 4, i, cap);
        cap[pos] = '\n';
        cap += (pos + 1);
        i += 15;
      }
    }
    /* draw xor box(cursor) */
    if (self->parent != 0)
    {
      if (self->parent->focused_control == self)
      {
	i = MIN (self->edit_pos, 255);
        if (self->password_char != 0)
        {
          wchar_repeat(wtext, 255, self->password_char, i);
          wtext[i] = 0;
          g_wcstombs(text, wtext, i);
        }
        else
        {
          g_mbstowcs(wtext, self->caption1, 255);
          wtext[i] = 0;
          g_wcstombs(text, wtext, 255);
        }
        w = xrdp_painter_text_width(painter, text);
        painter->fg_color = self->wm->white;
        painter->rop = 0x5a;
        xrdp_painter_fill_rect(painter, self, 4 + w, 3, 2, 14);
      }
    }
    /* reset rop back */
    painter->rop = 0xcc;
  }
  else if (self->type == WND_TYPE_LABEL) /* 6 */
  {
    painter->fg_color = self->wm->black;
    xrdp_painter_draw_text(painter, self, 0, 0, self->caption1);
  }
  else if (self->type == WND_TYPE_COMBO) /* 7 combo box */
  {
    /* draw dark gray box */
    painter->fg_color = self->wm->dark_grey;
    xrdp_painter_fill_rect(painter, self, 0, 0, self->width, self->height);
    /* main white background */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, 2, 2, self->width - 4,
                           self->height - 4);
    /* medium grey top line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, 1, 1, self->width - 2, 1);
    /* medium grey left line */
    painter->fg_color = self->wm->med_grey;
    xrdp_painter_fill_rect(painter, self, 1, 1, 1, self->height - 2);
    /* white bottom line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, 1, self->height- 2, self->width - 2, 1);
    /* white right line */
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, self->width - 2, 1, 1, self->height - 2);

    if (self->parent->focused_control == self)
    {
      painter->fg_color = self->wm->dark_blue;
      xrdp_painter_fill_rect(painter, self, 2, 2, (self->width - 4) - 19,
                             self->height - 4);
    }
    /* draw text */
    if (self->parent->focused_control == self)
    {
      painter->fg_color = self->wm->white;
    }
    else
    {
      painter->fg_color = self->wm->black;
    }
    xrdp_painter_draw_text(painter, self, 4, 2,
            (char*)list_get_item(self->string_list, self->item_index));
    /* draw button on right */
    x = self->width - 20;
    y = 2;
    w = (self->width - x) - 2;
    h = self->height - 4;
    if (self->state == BUTTON_STATE_UP) /* 0 */
    {
      xrdp_bitmap_draw_button(self, painter, x, y, w, h, 0);
    }
    else
    {
      xrdp_bitmap_draw_button(self, painter, x, y, w, h, 1);
    }
    /* black arrow */
    painter->fg_color = self->wm->black;
    xrdp_painter_fill_rect(painter, self, x + 5, y + 6, w - 10, 1);
    xrdp_painter_fill_rect(painter, self, x + 6, y + 7, w - 12, 1);
    xrdp_painter_fill_rect(painter, self, x + 7, y + 8, w - 14, 1);
    xrdp_painter_fill_rect(painter, self, x + 8, y + 9, w - 16, 1);

  }
  else if (self->type == WND_TYPE_SPECIAL) /* 8 special */
  {
    painter->fg_color = self->wm->white;
    xrdp_painter_fill_rect(painter, self, 0, 0, self->width, self->height);
    /* draw the list items */
    if (self->popped_from != 0)
    {
      y = 0;
      for (i = 0; i < self->popped_from->string_list->count; i++)
      {
        p = (char*)list_get_item(self->popped_from->string_list, i);
        h = xrdp_painter_text_height(painter, p);
        self->item_height = h;
        if (i == self->item_index)
        {
          painter->fg_color = self->wm->blue;
          xrdp_painter_fill_rect(painter, self, 0, y, self->width, h);
          painter->fg_color = self->wm->white;
        }
        else
        {
          painter->fg_color = self->wm->black;
        }
        xrdp_painter_draw_text(painter, self, 2, y, p);
        y = y + h;
      }
    }
  }
  else if (self->type == WND_TYPE_TILE) /* 10 tile */
  {
      y = self->top;
      while (y < self->height)
      {
          x = self->left;
	  while (x < self->width)
	  {
	      xrdp_painter_copy(painter, self, self, x, y,
				self->line_width, self->lines, 0, 0);
              x += self->line_width;
	  }
          y += self->lines;
      }
  }

  /* notify */
  if (self->notify != 0)
  {
    self->notify(self, self, WM_PAINT, (long)painter, 0); /* 3 */
  }
  /* draw any child windows in the area */
  for (i = 0; i < self->child_list->count; i++)
  {
    b = (struct xrdp_bitmap*)list_get_item(self->child_list, i);
    if (rect == 0)
    {
      xrdp_bitmap_invalidate(b, 0);
    }
    else
    {
      MAKERECT(r1, b->left, b->top, b->width, b->height);
      if (rect_intersect(rect, &r1, &r2))
      {
        RECTOFFSET(r2, -(b->left), -(b->top));
        xrdp_bitmap_invalidate(b, &r2);
      }
    }
  }
  xrdp_painter_end_update(painter);
  xrdp_painter_delete(painter);
  return 0;
}

/*****************************************************************************/
/* returns error */
int APP_CC
xrdp_bitmap_def_proc(struct xrdp_bitmap* self, int msg,
                     int param1, int param2)
{
  twchar c;
  int n;
  int i;
  int shift;
  int ext;
  int scan_code;
  struct xrdp_bitmap* b;
  struct xrdp_bitmap* focus_out_control;

  if (self == 0)
  {
    return 0;
  }
  if (self->wm == 0)
  {
    return 0;
  }
  if (self->type == WND_TYPE_WND)
  {
    if (msg == WM_KEYDOWN)
    {
      scan_code = param1 % 128;
      if (scan_code == 15) /* tab */
      {
        /* move to next tab stop */
        shift = self->wm->keys[42] || self->wm->keys[54];
        i = -1;
        if (self->child_list != 0)
        {
          i = list_index_of(self->child_list, (long)self->focused_control);
        }
        if (shift)
        {
          i--;
          if (i < 0)
          {
            i = self->child_list->count - 1;
          }
        }
        else
        {
          i++;
          if (i >= self->child_list->count)
          {
            i = 0;
          }
        }
        n = self->child_list->count;
        b = (struct xrdp_bitmap*)list_get_item(self->child_list, i);
        while (b != self->focused_control && b != 0 && n > 0)
        {
          n--;
          if (b->tab_stop)
          {
            focus_out_control = self->focused_control;
            self->focused_control = b;
            xrdp_bitmap_invalidate(focus_out_control, 0);
            xrdp_bitmap_invalidate(b, 0);
            break;
          }
          if (shift)
          {
            i--;
            if (i < 0)
            {
              i = self->child_list->count - 1;
            }
          }
          else
          {
            i++;
            if (i >= self->child_list->count)
            {
              i = 0;
            }
          }
          b = (struct xrdp_bitmap*)list_get_item(self->child_list, i);
        }
      }
      else if (scan_code == 28) /* enter */
      {
        if (self->default_button != 0)
        {
          if (self->notify != 0)
          {
            /* I think this should use def_proc */
            self->notify(self, self->default_button, 1, 0, 0);
            return 0;
          }
        }
      }
      else if (scan_code == 1) /* esc */
      {
        if (self->esc_button != 0)
        {
          if (self->notify != 0)
          {
            /* I think this should use def_proc */
            self->notify(self, self->esc_button, 1, 0, 0);
            return 0;
          }
        }
      }
    }
    if (self->focused_control != 0)
    {
      xrdp_bitmap_def_proc(self->focused_control, msg, param1, param2);
    }
  }
  else if (self->type == WND_TYPE_EDIT)
  {
    if (msg == WM_KEYDOWN)
    {
      scan_code = param1 % 128;
      ext = param2 & 0x0100;
      /* left or up arrow */
      if ((scan_code == 75 || scan_code == 72) &&
          (ext || self->wm->num_lock == 0))
      {
        if (self->edit_pos > 0)
        {
          self->edit_pos--;
          xrdp_bitmap_invalidate(self, 0);
        }
      }
      /* right or down arrow */
      else if ((scan_code == 77 || scan_code == 80) &&
               (ext || self->wm->num_lock == 0))
      {
        if (self->edit_pos < g_mbstowcs(0, self->caption1, 0))
        {
          self->edit_pos++;
          xrdp_bitmap_invalidate(self, 0);
        }
      }
      /* backspace */
      else if (scan_code == 14)
      {
        n = g_mbstowcs(0, self->caption1, 0);
        if (n > 0)
        {
          if (self->edit_pos > 0)
          {
            self->edit_pos--;
            remove_char_at(self->caption1, 255, self->edit_pos);
            xrdp_bitmap_invalidate(self, 0);
          }
        }
      }
      /* delete */
      else if (scan_code == 83  &&
              (ext || self->wm->num_lock == 0))
      {
        n = g_mbstowcs(0, self->caption1, 0);
        if (n > 0)
        {
          if (self->edit_pos < n)
          {
            remove_char_at(self->caption1, 255, self->edit_pos);
            xrdp_bitmap_invalidate(self, 0);
          }
        }
      }
      /* end */
      else if (scan_code == 79  &&
              (ext || self->wm->num_lock == 0))
      {
        n = g_mbstowcs(0, self->caption1, 0);
        if (self->edit_pos < n)
        {
          self->edit_pos = n;
          xrdp_bitmap_invalidate(self, 0);
        }
      }
      /* home */
      else if ((scan_code == 71)  &&
              (ext || (self->wm->num_lock == 0)))
      {
        if (self->edit_pos > 0)
        {
          self->edit_pos = 0;
          xrdp_bitmap_invalidate(self, 0);
        }
      }
      else
      {
        c = get_char_from_scan_code
            (param2, scan_code, self->wm->keys, self->wm->caps_lock,
             self->wm->num_lock, self->wm->scroll_lock,
             &(self->wm->keymap));
        if (c >= 32)
        {
          add_char_at(self->caption1, 255, c, self->edit_pos);
          self->edit_pos++;
          xrdp_bitmap_invalidate(self, 0);
        }
      }
    }
  }
  else if (self->type == WND_TYPE_COMBO)
  {
    if (msg == WM_KEYDOWN)
    {
      scan_code = param1 % 128;
      ext = param2 & 0x0100;
      /* left or up arrow */
      if (((scan_code == 75) || (scan_code == 72)) &&
          (ext || (self->wm->num_lock == 0)))
      {
        if (self->item_index > 0)
        {
          self->item_index--;
          xrdp_bitmap_invalidate(self, 0);
          if (self->parent->notify != 0)
          {
            self->parent->notify(self->parent, self, CB_ITEMCHANGE, 0, 0);
          }
        }
      }
      /* right or down arrow */
      else if ((scan_code == 77 || scan_code == 80) &&
               (ext || self->wm->num_lock == 0))
      {
        if ((self->item_index + 1) < self->string_list->count)
        {
          self->item_index++;
          xrdp_bitmap_invalidate(self, 0);
          if (self->parent->notify != 0)
          {
            self->parent->notify(self->parent, self, CB_ITEMCHANGE, 0, 0);
          }
        }
      }
    }
  }
  else if (self->type == WND_TYPE_SPECIAL)
  {
    if (msg == WM_MOUSEMOVE)
    {
      if (self->item_height > 0 && self->popped_from != 0)
      {
        i = param2;
        i = i / self->item_height;
        if (i != self->item_index &&
            i < self->popped_from->string_list->count)
        {
          self->item_index = i;
          xrdp_bitmap_invalidate(self, 0);
        }
      }
    }
    else if (msg == WM_LBUTTONUP)
    {
      if (self->popped_from != 0)
      {
        self->popped_from->item_index = self->item_index;
        xrdp_bitmap_invalidate(self->popped_from, 0);
        if (self->popped_from->parent->notify != 0)
        {
          self->popped_from->parent->notify(self->popped_from->parent,
                                            self->popped_from,
                                            CB_ITEMCHANGE, 0, 0);
        }
      }
    }
  }
  return 0;
}

/*****************************************************************************/
/* convert the controls coords to screen coords */
int APP_CC
xrdp_bitmap_to_screenx(struct xrdp_bitmap* self, int x)
{
  int i;

  i = x;
  while (self != 0)
  {
    i = i + self->left;
    self = self->parent;
  }
  return i;
}

/*****************************************************************************/
/* convert the controls coords to screen coords */
int APP_CC
xrdp_bitmap_to_screeny(struct xrdp_bitmap* self, int y)
{
  int i;

  i = y;
  while (self != 0)
  {
    i = i + self->top;
    self = self->parent;
  }
  return i;
}

/*****************************************************************************/
/* convert the screen coords to controls coords */
int APP_CC
xrdp_bitmap_from_screenx(struct xrdp_bitmap* self, int x)
{
  int i;

  i = x;
  while (self != 0)
  {
    i = i - self->left;
    self = self->parent;
  }
  return i;
}

/*****************************************************************************/
/* convert the screen coords to controls coords */
int APP_CC
xrdp_bitmap_from_screeny(struct xrdp_bitmap* self, int y)
{
  int i;

  i = y;
  while (self != 0)
  {
    i = i - self->top;
    self = self->parent;
  }
  return i;
}

/*****************************************************************************/
int APP_CC
xrdp_bitmap_get_screen_clip(struct xrdp_bitmap* self,
                            struct xrdp_painter* painter,
                            struct xrdp_rect* rect,
                            int* dx, int* dy)
{
  int ldx;
  int ldy;

  if (painter->use_clip)
  {
    *rect = painter->clip;
  }
  else
  {
    rect->left = 0;
    rect->top = 0;
    rect->right = self->width;
    rect->bottom = self->height;
  }
  ldx = xrdp_bitmap_to_screenx(self, 0);
  ldy = xrdp_bitmap_to_screeny(self, 0);
  rect->left += ldx;
  rect->top += ldy;
  rect->right += ldx;
  rect->bottom += ldy;
  if (dx != 0)
  {
    *dx = ldx;
  }
  if (dy != 0)
  {
    *dy = ldy;
  }
  return 0;
}
