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

   simple window manager

*/

#include "xrdp.h"

/*****************************************************************************/
struct xrdp_wm* APP_CC
xrdp_wm_create(struct xrdp_process* owner,
               struct xrdp_client_info* client_info)
{
  struct xrdp_wm* self;
  char event_name[64];

  self = (struct xrdp_wm*)g_malloc(sizeof(struct xrdp_wm), 1);
  self->client_info = client_info;
  self->screen = xrdp_bitmap_create(client_info->width,
                                    client_info->height,
                                    client_info->bpp,
                                    WND_TYPE_SCREEN, self);
  self->screen->wm = self;
  self->pro_layer = owner;
  self->session = owner->session;
  g_snprintf(event_name, 63, "xrdp_wm_login_mode_event_%8.8x",
             owner->session_id);
  self->login_mode_event = g_create_wait_obj(event_name);
  self->painter = xrdp_painter_create(self, self->session);
  self->cache = xrdp_cache_create(self, self->session, self->client_info);
  self->log = list_create();
  self->log->auto_free = 1;
  self->mm = xrdp_mm_create(self);
  self->default_font = xrdp_font_create(self);
  /* this will use built in keymap or load from file */
  get_keymaps(self->session->client_info->keylayout, &(self->keymap));
  xrdp_wm_set_login_mode(self, 0);
  return self;
}

/*****************************************************************************/
void APP_CC
xrdp_wm_delete(struct xrdp_wm* self)
{
  if (self == 0)
  {
    return;
  }
  xrdp_mm_delete(self->mm);
  xrdp_cache_delete(self->cache);
  xrdp_painter_delete(self->painter);
  xrdp_bitmap_delete(self->screen);
  /* free the log */
  list_delete(self->log);
  /* free default font */
  xrdp_font_delete(self->default_font);
  g_delete_wait_obj(self->login_mode_event);
  /* free self */
  g_free(self);
}

/*****************************************************************************/
int APP_CC
xrdp_wm_send_palette(struct xrdp_wm* self)
{
  return libxrdp_send_palette(self->session, self->palette);
}

/*****************************************************************************/
int APP_CC
xrdp_wm_send_bitmap(struct xrdp_wm* self, struct xrdp_bitmap* bitmap,
                    int x, int y, int cx, int cy)
{
  return libxrdp_send_bitmap(self->session, bitmap->width, bitmap->height,
                             bitmap->bpp, bitmap->data, x, y, cx, cy);
}

/*****************************************************************************/
int APP_CC
xrdp_wm_set_focused(struct xrdp_wm* self, struct xrdp_bitmap* wnd)
{
  struct xrdp_bitmap* focus_out_control;
  struct xrdp_bitmap* focus_in_control;

  if (self == 0)
  {
    return 0;
  }
  if (self->focused_window == wnd)
  {
    return 0;
  }
  focus_out_control = 0;
  focus_in_control = 0;
  if (self->focused_window != 0)
  {
    xrdp_bitmap_set_focus(self->focused_window, 0);
    focus_out_control = self->focused_window->focused_control;
  }
  self->focused_window = wnd;
  if (self->focused_window != 0)
  {
    xrdp_bitmap_set_focus(self->focused_window, 1);
    focus_in_control = self->focused_window->focused_control;
  }
  xrdp_bitmap_invalidate(focus_out_control, 0);
  xrdp_bitmap_invalidate(focus_in_control, 0);
  return 0;
}

/******************************************************************************/
static int APP_CC
xrdp_wm_get_pixel(char* data, int x, int y, int width, int bpp)
{
  int start;
  int shift;

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
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_pointer(struct xrdp_wm* self, char* data, char* mask, int x, int y)
{
  struct xrdp_pointer_item pointer_item;

  g_memset(&pointer_item, 0, sizeof(struct xrdp_pointer_item));
  pointer_item.x = x;
  pointer_item.y = y;
  g_memcpy(pointer_item.data, data, 32 * 32 * 3);
  g_memcpy(pointer_item.mask, mask, 32 * 32 / 8);
  self->screen->pointer = xrdp_cache_add_pointer(self->cache, &pointer_item);
  return 0;
}

/*****************************************************************************/
/* returns error */
int APP_CC
xrdp_wm_load_pointer(struct xrdp_wm* self, char* file_name, char* data,
                     char* mask, int* x, int* y)
{
  int fd;
  int bpp;
  int w;
  int h;
  int i;
  int j;
  int pixel;
  int palette[16];
  struct stream* fs;

  if (!g_file_exist(file_name))
  {
    g_writeln("xrdp_wm_load_pointer: error pointer file [%s] does not exist",
              file_name);
    return 1;
  }
  make_stream(fs);
  init_stream(fs, 8192);
  fd = g_file_open(file_name);
  g_file_read(fd, fs->data, 8192);
  g_file_close(fd);
  in_uint8s(fs, 6);
  in_uint8(fs, w);
  in_uint8(fs, h);
  in_uint8s(fs, 2);
  in_uint16_le(fs, *x);
  in_uint16_le(fs, *y);
  in_uint8s(fs, 22);
  in_uint8(fs, bpp);
  in_uint8s(fs, 25);
  if (w == 32 && h == 32)
  {
    if (bpp == 1)
    {
      in_uint8a(fs, palette, 8);
      for (i = 0; i < 32; i++)
      {
        for (j = 0; j < 32; j++)
        {
          pixel = palette[xrdp_wm_get_pixel(fs->p, j, i, 32, 1)];
          *data = pixel;
          data++;
          *data = pixel >> 8;
          data++;
          *data = pixel >> 16;
          data++;
        }
      }
      in_uint8s(fs, 128);
    }
    else if (bpp == 4)
    {
      in_uint8a(fs, palette, 64);
      for (i = 0; i < 32; i++)
      {
        for (j = 0; j < 32; j++)
        {
          pixel = palette[xrdp_wm_get_pixel(fs->p, j, i, 32, 1)];
          *data = pixel;
          data++;
          *data = pixel >> 8;
          data++;
          *data = pixel >> 16;
          data++;
        }
      }
      in_uint8s(fs, 512);
    }
    g_memcpy(mask, fs->p, 128); /* mask */
  }
  free_stream(fs);
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_send_pointer(struct xrdp_wm* self, int cache_idx,
                     char* data, char* mask, int x, int y)
{
  return libxrdp_send_pointer(self->session, cache_idx, data, mask, x, y);
}

/*****************************************************************************/
int APP_CC
xrdp_wm_set_pointer(struct xrdp_wm* self, int cache_idx)
{
  return libxrdp_set_pointer(self->session, cache_idx);
}

/*****************************************************************************/
int APP_CC
xrdp_wm_load_static_colors(struct xrdp_wm* self)
{
  int bindex;
  int gindex;
  int rindex;

  if (self->screen->bpp == 8)
  {
    /* rgb332 */
    for (bindex = 0; bindex < 4; bindex++)
    {
      for (gindex = 0; gindex < 8; gindex++)
      {
        for (rindex = 0; rindex < 8; rindex++)
        {
          self->palette[(bindex << 6) | (gindex << 3) | rindex] =
                (((rindex << 5) | (rindex << 2) | (rindex >> 1)) << 16) |
                (((gindex << 5) | (gindex << 2) | (gindex >> 1)) << 8) |
                ((bindex << 6) | (bindex << 4) | (bindex << 2) | (bindex));
        }
      }
    }
    self->black     = COLOR8(0, 0, 0);
    self->grey      = COLOR8(0xfb, 0xfb, 0xfb);
    self->med_grey  = COLOR8(0xed, 0xed, 0xed);
    self->dark_grey = COLOR8(0xb0, 0xb0, 0xb0);
    self->blue      = COLOR8(0x7e, 0xa4, 0xd4);
    self->dark_blue = COLOR8(0x4e, 0x76, 0xa8);
    self->white     = COLOR8(0xff, 0xff, 0xff);
    self->red       = COLOR8(0xff, 0x00, 0x00);
    self->green     = COLOR8(0x00, 0xff, 0x00);
    xrdp_wm_send_palette(self);
  }
  else if (self->screen->bpp == 15)
  {
    self->black     = COLOR15(0, 0, 0);
    self->grey      = COLOR15(0xfb, 0xfb, 0xfb);
    self->med_grey  = COLOR15(0xed, 0xed, 0xed);
    self->dark_grey = COLOR15(0xb0, 0xb0, 0xb0);
    self->blue      = COLOR15(0x7e, 0xa4, 0xd4);
    self->dark_blue = COLOR15(0x4e, 0x76, 0xa8);
    self->white     = COLOR15(0xff, 0xff, 0xff);
    self->red       = COLOR15(0xff, 0x00, 0x00);
    self->green     = COLOR15(0x00, 0xff, 0x00);
  }
  else if (self->screen->bpp == 16)
  {
    self->black     = COLOR16(0, 0, 0);
    self->grey      = COLOR16(0xfb, 0xfb, 0xfb);
    self->med_grey  = COLOR16(0xed, 0xed, 0xed);
    self->dark_grey = COLOR16(0xb0, 0xb0, 0xb0);
    self->blue      = COLOR16(0x7e, 0xa4, 0xd4);
    self->dark_blue = COLOR16(0x4e, 0x76, 0xa8);
    self->white     = COLOR16(0xff, 0xff, 0xff);
    self->red       = COLOR16(0xff, 0x00, 0x00);
    self->green     = COLOR16(0x00, 0xff, 0x00);
  }
  else if (self->screen->bpp == 24)
  {
    self->black     = COLOR24BGR(0, 0, 0);
    self->grey      = COLOR24BGR(0xfb, 0xfb, 0xfb);
    self->med_grey  = COLOR24BGR(0xed, 0xed, 0xed);
    self->dark_grey = COLOR24BGR(0xb0, 0xb0, 0xb0);
    self->blue      = COLOR24BGR(0x7e, 0xa4, 0xd4);
    self->dark_blue = COLOR24BGR(0x4e, 0x76, 0xa8);
    self->white     = COLOR24BGR(0xff, 0xff, 0xff);
    self->red       = COLOR24BGR(0xff, 0x00, 0x00);
    self->green     = COLOR24BGR(0x00, 0xff, 0x00);
  }
  return 0;
}

/*****************************************************************************/
/* returns error */
int APP_CC
xrdp_wm_load_static_pointers(struct xrdp_wm* self)
{
  struct xrdp_pointer_item pointer_item;
  char file_path[256];

  DEBUG(("sending cursor"));
  g_snprintf(file_path, 255, "%s/cursor1.cur", XRDP_SHARE_PATH);
  g_memset(&pointer_item, 0, sizeof(pointer_item));
  xrdp_wm_load_pointer(self, file_path, pointer_item.data,
                       pointer_item.mask, &pointer_item.x, &pointer_item.y);
  xrdp_cache_add_pointer_static(self->cache, &pointer_item, 1);
  DEBUG(("sending cursor"));
  g_snprintf(file_path, 255, "%s/cursor0.cur", XRDP_SHARE_PATH);
  g_memset(&pointer_item, 0, sizeof(pointer_item));
  xrdp_wm_load_pointer(self, file_path, pointer_item.data,
                       pointer_item.mask, &pointer_item.x, &pointer_item.y);
  xrdp_cache_add_pointer_static(self->cache, &pointer_item, 0);
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_load_sections(struct xrdp_wm* self,
		      struct list* string_list,
		      struct list* data_list)
{
  struct list* sections;
  struct list* section_names;
  struct list* section_values;
  int fd;
  int i;
  int j;
  char* p;
  char* q;
  char* r;
  char name[256];
  struct xrdp_mod_data* mod_data;

  sections = list_create();
  sections->auto_free = 1;
  section_names = list_create();
  section_names->auto_free = 1;
  section_values = list_create();
  section_values->auto_free = 1;
  fd = g_file_open(XRDP_CFG_FILE); /* xrdp.ini */
  file_read_sections(fd, sections);
  for (i = 0; i < sections->count; i++)
  {
    p = (char*)list_get_item(sections, i);
    file_read_section(fd, p, section_names, section_values);
    if (g_strncmp(p, "globals", 255) == 0)
    {
    }
    else if (g_strncmp(p, "xsessions", 255) == 0)
    {
      unsigned int dir;
      char         path[256];

      g_strncpy(path, ".", 255);
      for (j = 0; j < section_names->count; j++)
      {
        q = (char*)list_get_item(section_names, j);
        r = (char*)list_get_item(section_values, j);
	if (g_strncmp("path", q, 255) == 0)
        {
	  g_strncpy(path, r, 255);
	  break;
        }
      }

      if (g_directory_exist (path) && (dir = g_dir_open (path)))
      {
	const char*  file;
	struct list* entry_names;
	struct list* entry_values;

	struct stream* s;
	char stext[512];
	char sname[512];
	char svalue[512];
	int wm_fd, len;
	char *default_wm;

	entry_names = list_create();
	entry_names->auto_free = 1;
	entry_values = list_create();
	entry_values->auto_free = 1;

	default_wm = g_strdup("twm");
	g_memset(stext, 0, 512);
	make_stream(s);
	init_stream(s, 32 * 1024);
	wm_fd = g_file_open("/etc/sysconfig/windowmanager");
	len = g_file_read(wm_fd, s->data, 32 * 1024);
	if (len > 0)
	{
	  s->end = s->p + len;
	  while (file_read_line(s, stext) == 0)
	  {
	    if (g_strlen(stext) > 0)
	    {
	      file_split_name_value(stext, sname, svalue);
	      if (g_strcmp (sname, "DEFAULT_WM") == 0)
	      {
		default_wm = g_strdup(svalue);
		break;
	      }
	    }
	  }
	}
	g_file_close(wm_fd);
	free_stream(s);

	while ((file = g_dir_read_name (dir)))
	{
	  int de_fd;
	  int prepend = 0;

	  if (g_pos ((char *) file, ".desktop") == -1)
	    continue;

	  g_strncpy(name, file, 255);
	  mod_data = (struct xrdp_mod_data*)
	      g_malloc(sizeof(struct xrdp_mod_data), 1);
	  mod_data->names = list_create();
	  mod_data->names->auto_free = 1;
	  mod_data->values = list_create();
	  mod_data->values->auto_free = 1;

	  g_snprintf(name, 255, "%s/%s", path, file);
	  de_fd = g_file_open(name);

	  g_strncpy(name, file, 255);
	  file_read_section(de_fd, "Desktop Entry", entry_names, entry_values);
	  for (j = 0; j < entry_names->count; j++)
	  {
	    q = (char*)list_get_item(entry_names, j);
	    r = (char*)list_get_item(entry_values, j);
	    if (g_strncmp("Name", q, 255) == 0)
	    {
	      g_strncpy(name, r, 255);
	    }
	    else if (g_strncmp("Exec", q, 255) == 0)
	    {
	      list_add_item(mod_data->names, (long)g_strdup("exec"));
	      list_add_item(mod_data->values, (long)g_strdup(r));

	      if (default_wm && g_pos (default_wm, r) != -1)
		prepend = 1;
	    }
	  }

	  for (j = 0; j < section_names->count; j++)
	  {
	    q = (char*)list_get_item(section_names, j);
	    r = (char*)list_get_item(section_values, j);
	    list_add_item(mod_data->names, (long)g_strdup(q));
	    list_add_item(mod_data->values, (long)g_strdup(r));
	  }

	  if (prepend)
	  {
	    list_insert_item(string_list, 0, (long)g_strdup(name));
	    list_insert_item(data_list, 0, (long)mod_data);
	  }
	  else
	  {
	    list_add_item(string_list, (long)g_strdup(name));
	    list_add_item(data_list, (long)mod_data);
	  }
	  
	  g_file_close(de_fd);
	}

	list_delete(entry_names);
	list_delete(entry_values);

	if (default_wm)
	  g_free (default_wm);

	g_dir_close (dir);
      }
    }
    else
    {
      g_strncpy(name, p, 255);
      mod_data = (struct xrdp_mod_data*)
                     g_malloc(sizeof(struct xrdp_mod_data), 1);
      mod_data->names = list_create();
      mod_data->names->auto_free = 1;
      mod_data->values = list_create();
      mod_data->values->auto_free = 1;
      for (j = 0; j < section_names->count; j++)
      {
        q = (char*)list_get_item(section_names, j);
        r = (char*)list_get_item(section_values, j);
        if (g_strncmp("name", q, 255) == 0)
        {
          g_strncpy(name, r, 255);
        }
        list_add_item(mod_data->names, (long)g_strdup(q));
        list_add_item(mod_data->values, (long)g_strdup(r));
      }
      list_add_item(string_list, (long)g_strdup(name));
      list_add_item(data_list, (long)mod_data);
    }
  }
  g_file_close(fd);
  list_delete(sections);
  list_delete(section_names);
  list_delete(section_values);
  return 0;
}

/******************************************************************************/
static void APP_CC
xrdp_wm_background_create(struct xrdp_wm* self)
{
  struct xrdp_bitmap* b;
  char file_path[256];

  /* image */
  b = xrdp_bitmap_create(4, 4, self->screen->bpp, WND_TYPE_IMAGE, self);
  g_snprintf(file_path, 255, "%s/opensuse256.bmp", XRDP_SHARE_PATH);
  xrdp_bitmap_load(b, file_path, self->palette);
  b->parent = self->screen;
  b->owner = self->screen;
  b->left = 0;
  b->top = 0;
  list_add_item(self->screen->child_list, (long)b);

  /* tile */
  b = xrdp_bitmap_create(4, 4, self->screen->bpp, WND_TYPE_TILE, self);
  g_snprintf(file_path, 255, "%s/tile256.bmp", XRDP_SHARE_PATH);
  xrdp_bitmap_load(b, file_path, self->palette);
  b->parent = self->screen;
  b->owner = self->screen;
  b->left = 0;
  b->top = 0;
  b->width = self->screen->width;
  b->height = self->screen->height;
  list_add_item(self->screen->child_list, (long)b);
}

/*****************************************************************************/
int APP_CC
xrdp_wm_init(struct xrdp_wm* self)
{
  struct xrdp_mod_data* mod_data;
  int index;
  struct list* string_list;
  struct list* data_list;
  char* q;
  char* r;
  char section_name[256];

  xrdp_wm_load_static_colors(self);
  xrdp_wm_load_static_pointers(self);
  self->screen->bg_color = self->black;
  if (self->session->client_info->rdp_autologin)
  {
    string_list = list_create();
    string_list->auto_free = 1;
    data_list = list_create();
    data_list->auto_free = 1;
    xrdp_wm_load_sections (self, string_list, data_list);
    g_strncpy(section_name, self->session->client_info->program, 255);
    index = 0;
    if (section_name[0] != 0)
    {
      int i;

      for (i = 0; i < string_list->count; i++)
      {
        q = (char*)list_get_item(string_list, i);
	if (g_strcasecmp(section_name, q) == 0)
	{
	  index = i;
          break;
	}
      }
    }
    mod_data = (struct xrdp_mod_data*) list_get_item(data_list, index);
    if (mod_data != 0)
    {
      for (index = 0; index < mod_data->names->count; index++)
      {
        q = (char*)list_get_item(mod_data->names, index);
	r = (char*)list_get_item(mod_data->values, index);
	if (g_strncmp("password", q, 255) == 0)
        {
          list_add_item(self->mm->login_names, (long)g_strdup("password"));
	  list_add_item(self->mm->login_values,
			(long)g_strdup(self->session->client_info->password));
	}
	else if (g_strncmp("username", q, 255) == 0)
	{
          list_add_item(self->mm->login_names, (long)g_strdup("username"));
	  list_add_item(self->mm->login_values,
			(long)g_strdup(self->session->client_info->username));
	}
	else
	{
          list_add_item(self->mm->login_names, (long)g_strdup(q));
	  list_add_item(self->mm->login_values, (long)g_strdup(r));
	}
      }
    }

    xrdp_wm_set_login_mode(self, 2);

    for (index = 0; index < data_list->count; index++)
    {
      mod_data = (struct xrdp_mod_data*)list_get_item(data_list, index);
      if (mod_data != 0)
      {
        list_delete(mod_data->names);
	list_delete(mod_data->values);
      }
    }
    list_delete(string_list);
    list_delete(data_list);
  }
  else
  {
    xrdp_wm_background_create(self);
    xrdp_login_wnd_create(self);
    /* clear screen */
    xrdp_bitmap_invalidate(self->screen, 0);
    xrdp_wm_set_focused(self, self->login_window);
    xrdp_wm_set_login_mode(self, 1);
  }
  return 0;
}

/*****************************************************************************/
/* returns the number for rects visible for an area relative to a drawable */
/* putting the rects in region */
int APP_CC
xrdp_wm_get_vis_region(struct xrdp_wm* self, struct xrdp_bitmap* bitmap,
                       int x, int y, int cx, int cy,
                       struct xrdp_region* region, int clip_children)
{
  int i;
  struct xrdp_bitmap* p;
  struct xrdp_rect a;
  struct xrdp_rect b;

  /* area we are drawing */
  MAKERECT(a, bitmap->left + x, bitmap->top + y, cx, cy);
  p = bitmap->parent;
  while (p != 0)
  {
    RECTOFFSET(a, p->left, p->top);
    p = p->parent;
  }
  a.left = MAX(self->screen->left, a.left);
  a.top = MAX(self->screen->top, a.top);
  a.right = MIN(self->screen->left + self->screen->width, a.right);
  a.bottom = MIN(self->screen->top + self->screen->height, a.bottom);
  xrdp_region_add_rect(region, &a);
  if (clip_children)
  {
    /* loop through all windows in z order */
    for (i = 0; i < self->screen->child_list->count; i++)
    {
      p = (struct xrdp_bitmap*)list_get_item(self->screen->child_list, i);
      if (p == bitmap || p == bitmap->parent)
      {
        return 0;
      }
      MAKERECT(b, p->left, p->top, p->width, p->height);
      xrdp_region_subtract_rect(region, &b);
    }
  }
  return 0;
}

/*****************************************************************************/
/* return the window at x, y on the screen */
static struct xrdp_bitmap* APP_CC
xrdp_wm_at_pos(struct xrdp_bitmap* wnd, int x, int y,
               struct xrdp_bitmap** wnd1)
{
  int i;
  struct xrdp_bitmap* p;
  struct xrdp_bitmap* q;

  /* loop through all windows in z order */
  for (i = 0; i < wnd->child_list->count; i++)
  {
    p = (struct xrdp_bitmap*)list_get_item(wnd->child_list, i);
    if (x >= p->left && y >= p->top && x < p->left + p->width &&
        y < p->top + p->height)
    {
      if (wnd1 != 0)
      {
        *wnd1 = p;
      }
      q = xrdp_wm_at_pos(p, x - p->left, y - p->top, 0);
      if (q == 0)
      {
        return p;
      }
      else
      {
        return q;
      }
    }
  }
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_xor_pat(struct xrdp_wm* self, int x, int y, int cx, int cy)
{
  self->painter->clip_children = 0;
  self->painter->rop = 0x5a;
  xrdp_painter_begin_update(self->painter);
  self->painter->use_clip = 0;
  self->painter->mix_mode = 1;
  self->painter->brush.pattern[0] = 0xaa;
  self->painter->brush.pattern[1] = 0x55;
  self->painter->brush.pattern[2] = 0xaa;
  self->painter->brush.pattern[3] = 0x55;
  self->painter->brush.pattern[4] = 0xaa;
  self->painter->brush.pattern[5] = 0x55;
  self->painter->brush.pattern[6] = 0xaa;
  self->painter->brush.pattern[7] = 0x55;
  self->painter->brush.x_orgin = 0;
  self->painter->brush.x_orgin = 0;
  self->painter->brush.style = 3;
  self->painter->bg_color = self->black;
  self->painter->fg_color = self->white;
  /* top */
  xrdp_painter_fill_rect(self->painter, self->screen, x, y, cx, 5);
  /* bottom */
  xrdp_painter_fill_rect(self->painter, self->screen, x, y + (cy - 5), cx, 5);
  /* left */
  xrdp_painter_fill_rect(self->painter, self->screen, x, y + 5, 5, cy - 10);
  /* right */
  xrdp_painter_fill_rect(self->painter, self->screen, x + (cx - 5), y + 5, 5,
                          cy - 10);
  xrdp_painter_end_update(self->painter);
  self->painter->rop = 0xcc;
  self->painter->clip_children = 1;
  self->painter->mix_mode = 0;
  return 0;
}

/*****************************************************************************/
/* this don't are about nothing, just copy the bits */
/* no clipping rects, no windows in the way, nothing */
static int APP_CC
xrdp_wm_bitblt(struct xrdp_wm* self,
               struct xrdp_bitmap* dst, int dx, int dy,
               struct xrdp_bitmap* src, int sx, int sy,
               int sw, int sh, int rop)
{
//  int i;
//  int line_size;
//  int Bpp;
//  char* s;
//  char* d;

//  if (sw <= 0 || sh <= 0)
//    return 0;
  if (self->screen == dst && self->screen == src)
  { /* send a screen blt */
//    Bpp = (dst->bpp + 7) / 8;
//    line_size = sw * Bpp;
//    s = src->data + (sy * src->width + sx) * Bpp;
//    d = dst->data + (dy * dst->width + dx) * Bpp;
//    for (i = 0; i < sh; i++)
//    {
//      //g_memcpy(d, s, line_size);
//      s += src->width * Bpp;
//      d += dst->width * Bpp;
//    }
    libxrdp_orders_init(self->session);
    libxrdp_orders_screen_blt(self->session, dx, dy, sw, sh, sx, sy, rop, 0);
    libxrdp_orders_send(self->session);
  }
  return 0;
}

/*****************************************************************************/
/* return true is rect is totaly exposed going in reverse z order */
/* from wnd up */
static int APP_CC
xrdp_wm_is_rect_vis(struct xrdp_wm* self, struct xrdp_bitmap* wnd,
                    struct xrdp_rect* rect)
{
  struct xrdp_rect wnd_rect;
  struct xrdp_bitmap* b;
  int i;;

  /* if rect is part off screen */
  if (rect->left < 0)
  {
    return 0;
  }
  if (rect->top < 0)
  {
    return 0;
  }
  if (rect->right >= self->screen->width)
  {
    return 0;
  }
  if (rect->bottom >= self->screen->height)
  {
    return 0;
  }

  i = list_index_of(self->screen->child_list, (long)wnd);
  i--;
  while (i >= 0)
  {
    b = (struct xrdp_bitmap*)list_get_item(self->screen->child_list, i);
    MAKERECT(wnd_rect, b->left, b->top, b->width, b->height);
    if (rect_intersect(rect, &wnd_rect, 0))
    {
      return 0;
    }
    i--;
  }
  return 1;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_move_window(struct xrdp_wm* self, struct xrdp_bitmap* wnd,
                    int dx, int dy)
{
  struct xrdp_rect rect1;
  struct xrdp_rect rect2;
  struct xrdp_region* r;
  int i;

  MAKERECT(rect1, wnd->left, wnd->top, wnd->width, wnd->height);
  if (xrdp_wm_is_rect_vis(self, wnd, &rect1))
  {
    rect2 = rect1;
    RECTOFFSET(rect2, dx, dy);
    if (xrdp_wm_is_rect_vis(self, wnd, &rect2))
    { /* if both src and dst are unobscured, we can do a bitblt move */
      xrdp_wm_bitblt(self, self->screen, wnd->left + dx, wnd->top + dy,
                     self->screen, wnd->left, wnd->top,
                     wnd->width, wnd->height, 0xcc);
      wnd->left += dx;
      wnd->top += dy;
      r = xrdp_region_create(self);
      xrdp_region_add_rect(r, &rect1);
      xrdp_region_subtract_rect(r, &rect2);
      i = 0;
      while (xrdp_region_get_rect(r, i, &rect1) == 0)
      {
        xrdp_bitmap_invalidate(self->screen, &rect1);
        i++;
      }
      xrdp_region_delete(r);
      return 0;
    }
  }
  wnd->left += dx;
  wnd->top += dy;
  xrdp_bitmap_invalidate(self->screen, &rect1);
  xrdp_bitmap_invalidate(wnd, 0);
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_undraw_dragging_box(struct xrdp_wm* self, int do_begin_end)
{
  int boxx;
  int boxy;

  if (self == 0)
  {
    return 0;
  }
  if (self->dragging)
  {
    if (self->draggingxorstate)
    {
      if (do_begin_end)
      {
        xrdp_painter_begin_update(self->painter);
      }
      boxx = self->draggingx - self->draggingdx;
      boxy = self->draggingy - self->draggingdy;
      xrdp_wm_xor_pat(self, boxx, boxy, self->draggingcx, self->draggingcy);
      self->draggingxorstate = 0;
      if (do_begin_end)
      {
        xrdp_painter_end_update(self->painter);
      }
    }
  }
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_draw_dragging_box(struct xrdp_wm* self, int do_begin_end)
{
  int boxx;
  int boxy;

  if (self == 0)
  {
    return 0;
  }
  if (self->dragging)
  {
    if (!self->draggingxorstate)
    {
      if (do_begin_end)
      {
        xrdp_painter_begin_update(self->painter);
      }
      boxx = self->draggingx - self->draggingdx;
      boxy = self->draggingy - self->draggingdy;
      xrdp_wm_xor_pat(self, boxx, boxy, self->draggingcx, self->draggingcy);
      self->draggingxorstate = 1;
      if (do_begin_end)
      {
        xrdp_painter_end_update(self->painter);
      }
    }
  }
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_mouse_move(struct xrdp_wm* self, int x, int y)
{
  struct xrdp_bitmap* b;

  if (self == 0)
  {
    return 0;
  }
  if (x < 0)
  {
    x = 0;
  }
  if (y < 0)
  {
    y = 0;
  }
  if (x >= self->screen->width)
  {
    x = self->screen->width;
  }
  if (y >= self->screen->height)
  {
    y = self->screen->height;
  }
  self->mouse_x = x;
  self->mouse_y = y;
  if (self->dragging)
  {
    xrdp_painter_begin_update(self->painter);
    xrdp_wm_undraw_dragging_box(self, 0);
    self->draggingx = x;
    self->draggingy = y;
    xrdp_wm_draw_dragging_box(self, 0);
    xrdp_painter_end_update(self->painter);
    return 0;
  }
  b = xrdp_wm_at_pos(self->screen, x, y, 0);
  if (b == 0) /* if b is null, the movment must be over the screen */
  {
    if (self->screen->pointer != self->current_pointer)
    {
      xrdp_wm_set_pointer(self, self->screen->pointer);
      self->current_pointer = self->screen->pointer;
    }
    if (self->mm->mod != 0) /* if screen is mod controled */
    {
      if (self->mm->mod->mod_event != 0)
      {
        self->mm->mod->mod_event(self->mm->mod, WM_MOUSEMOVE, x, y, 0, 0);
      }
    }
  }
  if (self->button_down != 0)
  {
    if (b == self->button_down && self->button_down->state == 0)
    {
      self->button_down->state = 1;
      xrdp_bitmap_invalidate(self->button_down, 0);
    }
    else if (b != self->button_down)
    {
      self->button_down->state = 0;
      xrdp_bitmap_invalidate(self->button_down, 0);
    }
  }
  if (b != 0)
  {
    if (!self->dragging)
    {
      if (b->pointer != self->current_pointer)
      {
        xrdp_wm_set_pointer(self, b->pointer);
        self->current_pointer = b->pointer;
      }
      xrdp_bitmap_def_proc(b, WM_MOUSEMOVE,
                           xrdp_bitmap_from_screenx(b, x),
                           xrdp_bitmap_from_screeny(b, y));
      if (self->button_down == 0)
      {
        if (b->notify != 0)
        {
          b->notify(b->owner, b, 2, x, y);
        }
      }
    }
  }
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_clear_popup(struct xrdp_wm* self)
{
  int i;
  struct xrdp_rect rect;
  //struct xrdp_bitmap* b;

  //b = 0;
  if (self->popup_wnd != 0)
  {
    //b = self->popup_wnd->popped_from;
    i = list_index_of(self->screen->child_list, (long)self->popup_wnd);
    list_remove_item(self->screen->child_list, i);
    MAKERECT(rect, self->popup_wnd->left, self->popup_wnd->top,
             self->popup_wnd->width, self->popup_wnd->height);
    xrdp_bitmap_invalidate(self->screen, &rect);
    xrdp_bitmap_delete(self->popup_wnd);
  }
  //xrdp_wm_set_focused(self, b->parent);
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_mouse_click(struct xrdp_wm* self, int x, int y, int but, int down)
{
  struct xrdp_bitmap* control;
  struct xrdp_bitmap* focus_out_control;
  struct xrdp_bitmap* wnd;
  int newx;
  int newy;
  int oldx;
  int oldy;

  if (self == 0)
  {
    return 0;
  }
  if (x < 0)
  {
    x = 0;
  }
  if (y < 0)
  {
    y = 0;
  }
  if (x >= self->screen->width)
  {
    x = self->screen->width;
  }
  if (y >= self->screen->height)
  {
    y = self->screen->height;
  }
  if (self->dragging && but == 1 && !down && self->dragging_window != 0)
  { /* if done dragging */
    self->draggingx = x;
    self->draggingy = y;
    newx = self->draggingx - self->draggingdx;
    newy = self->draggingy - self->draggingdy;
    oldx = self->dragging_window->left;
    oldy = self->dragging_window->top;
    /* draw xor box one more time */
    if (self->draggingxorstate)
    {
      xrdp_wm_xor_pat(self, newx, newy, self->draggingcx, self->draggingcy);
    }
    self->draggingxorstate = 0;
    /* move screen to new location */
    xrdp_wm_move_window(self, self->dragging_window, newx - oldx, newy - oldy);
    self->dragging_window = 0;
    self->dragging = 0;
  }
  wnd = 0;
  control = xrdp_wm_at_pos(self->screen, x, y, &wnd);
  if (control == 0)
  {
    if (self->mm->mod != 0) /* if screen is mod controled */
    {
      if (self->mm->mod->mod_event != 0)
      {
        if (but == 1 && down)
        {
          self->mm->mod->mod_event(self->mm->mod, WM_LBUTTONDOWN, x, y, 0, 0);
        }
        else if (but == 1 && !down)
        {
          self->mm->mod->mod_event(self->mm->mod, WM_LBUTTONUP, x, y, 0, 0);
        }
        if (but == 2 && down)
        {
          self->mm->mod->mod_event(self->mm->mod, WM_RBUTTONDOWN, x, y, 0, 0);
        }
        else if (but == 2 && !down)
        {
          self->mm->mod->mod_event(self->mm->mod, WM_RBUTTONUP, x, y, 0, 0);
        }
        if (but == 3 && down)
        {
          self->mm->mod->mod_event(self->mm->mod, WM_BUTTON3DOWN, x, y, 0, 0);
        }
        else if (but == 3 && !down)
        {
          self->mm->mod->mod_event(self->mm->mod, WM_BUTTON3UP, x, y, 0, 0);
        }
        if (but == 4)
        {
          self->mm->mod->mod_event(self->mm->mod, WM_BUTTON4DOWN,
                                   self->mouse_x, self->mouse_y, 0, 0);
          self->mm->mod->mod_event(self->mm->mod, WM_BUTTON4UP,
                                   self->mouse_x, self->mouse_y, 0, 0);
        }
        if (but == 5)
        {
          self->mm->mod->mod_event(self->mm->mod, WM_BUTTON5DOWN,
                                   self->mouse_x, self->mouse_y, 0, 0);
          self->mm->mod->mod_event(self->mm->mod, WM_BUTTON5UP,
                                   self->mouse_x, self->mouse_y, 0, 0);
        }
      }
    }
  }
  if (self->popup_wnd != 0)
  {
    if (self->popup_wnd == control && !down)
    {
      xrdp_bitmap_def_proc(self->popup_wnd, WM_LBUTTONUP, x, y);
      xrdp_wm_clear_popup(self);
      self->button_down = 0;
      return 0;
    }
    else if (self->popup_wnd != control && down)
    {
      xrdp_wm_clear_popup(self);
      self->button_down = 0;
      return 0;
    }
  }
  if (control != 0)
  {
    if (wnd != 0)
    {
      if (wnd->modal_dialog != 0) /* if window has a modal dialog */
      {
        return 0;
      }
      if (control == wnd)
      {
      }
      else if (control->tab_stop)
      {
        focus_out_control = wnd->focused_control;
        wnd->focused_control = control;
        xrdp_bitmap_invalidate(focus_out_control, 0);
        xrdp_bitmap_invalidate(control, 0);
      }
    }
    if ((control->type == WND_TYPE_BUTTON ||
         control->type == WND_TYPE_COMBO) &&
        but == 1 && !down && self->button_down == control)
    { /* if clicking up on a button that was clicked down */
      self->button_down = 0;
      control->state = 0;
      xrdp_bitmap_invalidate(control, 0);
      if (control->parent != 0)
      {
        if (control->parent->notify != 0)
        {
          /* control can be invalid after this */
          control->parent->notify(control->owner, control, 1, x, y);
        }
      }
    }
    else if ((control->type == WND_TYPE_BUTTON ||
              control->type == WND_TYPE_COMBO) &&
             but == 1 && down)
    { /* if clicking down on a button or combo */
      self->button_down = control;
      control->state = 1;
      xrdp_bitmap_invalidate(control, 0);
      if (control->type == WND_TYPE_COMBO)
      {
        xrdp_wm_pu(self, control);
      }
    }
    else if (but == 1 && down)
    {
      if (self->popup_wnd == 0)
      {
        xrdp_wm_set_focused(self, wnd);
        if (control->type == WND_TYPE_WND && y < (control->top + 21))
        { /* if dragging */
          if (self->dragging) /* rarely happens */
          {
            newx = self->draggingx - self->draggingdx;
            newy = self->draggingy - self->draggingdy;
            if (self->draggingxorstate)
            {
              xrdp_wm_xor_pat(self, newx, newy,
                              self->draggingcx, self->draggingcy);
            }
            self->draggingxorstate = 0;
          }
          self->dragging = 1;
          self->dragging_window = control;
          self->draggingorgx = control->left;
          self->draggingorgy = control->top;
          self->draggingx = x;
          self->draggingy = y;
          self->draggingdx = x - control->left;
          self->draggingdy = y - control->top;
          self->draggingcx = control->width;
          self->draggingcy = control->height;
        }
      }
    }
  }
  else
  {
    xrdp_wm_set_focused(self, 0);
  }
  /* no matter what, mouse is up, reset button_down */
  if (but == 1 && !down && self->button_down != 0)
  {
    self->button_down = 0;
  }
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_key(struct xrdp_wm* self, int device_flags, int scan_code)
{
  int msg;
  int c;
  static int last_key_status = -1;

  /*g_printf("count %d\n", self->key_down_list->count);*/
  scan_code = scan_code % 128;
  if (self->popup_wnd != 0)
  {
    xrdp_wm_clear_popup(self);
    return 0;
  }
  if (device_flags & KBD_FLAG_UP) /* 0x8000 */
  {
    self->keys[scan_code] = 0;
    msg = WM_KEYUP;
  }
  else /* key down */
  {
    self->keys[scan_code] = 1;
    msg = WM_KEYDOWN;
    switch (scan_code)
    {
      case 58:
        self->caps_lock = !self->caps_lock;
        break; /* caps lock */
      case 69:
        self->num_lock = !self->num_lock;
        break; /* num lock */
      case 70:
        self->scroll_lock = !self->scroll_lock;
        break; /* scroll lock */
    }
  }
  if (self->mm->mod != 0)
  {
    if (self->mm->mod->mod_event != 0)
    {
      c = get_char_from_scan_code
          (device_flags, scan_code, self->keys, self->caps_lock,
           self->num_lock, self->scroll_lock,
           &(self->keymap));
      if (c != 0)
      {
        self->mm->mod->mod_event(self->mm->mod, msg, c,
                                 0xffff, scan_code, device_flags);
      }
      else
      {
        if ((last_key_status != WM_KEYDOWN) && (scan_code == 15) && (device_flags == KBD_FLAG_UP))
        {
          g_writeln("Don't track Tab keys from Windows when Max/Min or Move the rdp client window.\n");
        }
        else
          self->mm->mod->mod_event(self->mm->mod, msg, scan_code,
                                 device_flags, scan_code, device_flags);
      }
    }
  }
  else if (self->focused_window != 0)
  {
    xrdp_bitmap_def_proc(self->focused_window,
                         msg, scan_code, device_flags);
  }
  last_key_status = msg;
  return 0;
}

/*****************************************************************************/
/* happens when client gets focus and sends key modifier info */
int APP_CC
xrdp_wm_key_sync(struct xrdp_wm* self, int device_flags, int key_flags)
{
  self->num_lock = 0;
  self->scroll_lock = 0;
  self->caps_lock = 0;
  if (key_flags & 1)
  {
    self->scroll_lock = 1;
  }
  if (key_flags & 2)
  {
    self->num_lock = 1;
  }
  if (key_flags & 4)
  {
    self->caps_lock = 1;
  }
  if (self->mm->mod != 0)
  {
    if (self->mm->mod->mod_event != 0)
    {
      self->mm->mod->mod_event(self->mm->mod, 17, key_flags, device_flags,
                               key_flags, device_flags);
    }
  }
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_pu(struct xrdp_wm* self, struct xrdp_bitmap* control)
{
  int x;
  int y;

  if (self == 0)
  {
    return 0;
  }
  if (control == 0)
  {
    return 0;
  }
  self->popup_wnd = xrdp_bitmap_create(control->width, 100,
                                       self->screen->bpp,
                                       WND_TYPE_SPECIAL, self);
  self->popup_wnd->popped_from = control;
  self->popup_wnd->parent = self->screen;
  self->popup_wnd->owner = self->screen;
  x = xrdp_bitmap_to_screenx(control, 0);
  y = xrdp_bitmap_to_screeny(control, 0);
  self->popup_wnd->left = x;
  self->popup_wnd->top = y + control->height;
  self->popup_wnd->item_index = control->item_index;
  list_insert_item(self->screen->child_list, 0, (long)self->popup_wnd);
  xrdp_bitmap_invalidate(self->popup_wnd, 0);
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_process_input_mouse(struct xrdp_wm* self, int device_flags,
                            int x, int y)
{
  DEBUG(("mouse event flags %4.4x x %d y %d", device_flags, x, y));
  if (device_flags & MOUSE_FLAG_MOVE) /* 0x0800 */
  {
    xrdp_wm_mouse_move(self, x, y);
  }
  if (device_flags & MOUSE_FLAG_BUTTON1) /* 0x1000 */
  {
    if (device_flags & MOUSE_FLAG_DOWN) /* 0x8000 */
    {
      xrdp_wm_mouse_click(self, x, y, 1, 1);
    }
    else
    {
      xrdp_wm_mouse_click(self, x, y, 1, 0);
    }
  }
  if (device_flags & MOUSE_FLAG_BUTTON2) /* 0x2000 */
  {
    if (device_flags & MOUSE_FLAG_DOWN) /* 0x8000 */
    {
      xrdp_wm_mouse_click(self, x, y, 2, 1);
    }
    else
    {
      xrdp_wm_mouse_click(self, x, y, 2, 0);
    }
  }
  if (device_flags & MOUSE_FLAG_BUTTON3) /* 0x4000 */
  {
    if (device_flags & MOUSE_FLAG_DOWN) /* 0x8000 */
    {
      xrdp_wm_mouse_click(self, x, y, 3, 1);
    }
    else
    {
      xrdp_wm_mouse_click(self, x, y, 3, 0);
    }
  }
  if (device_flags == MOUSE_FLAG_BUTTON4 || /* 0x0280 */
      device_flags == 0x0278)
  {
    xrdp_wm_mouse_click(self, 0, 0, 4, 0);
  }
  if (device_flags == MOUSE_FLAG_BUTTON5 || /* 0x0380 */
      device_flags == 0x0388)
  {
    xrdp_wm_mouse_click(self, 0, 0, 5, 0);
  }
  return 0;
}

/******************************************************************************/
static int APP_CC
xrdp_wm_process_channel_data(struct xrdp_wm* self, int channel_id,
                             char* data, int data_len)
{
 if (self->mm->mod != 0)
  {
    if (self->mm->mod->mod_event != 0)
    {
      return self->mm->mod->mod_event(self->mm->mod, 0x5555, channel_id,
				      (long)data, data_len, 0);
    }
  }
  return 0;
}

/******************************************************************************/
/* this is the callbacks comming from libxrdp.so */
int DEFAULT_CC
callback(long id, int msg, long param1, long param2, long param3, long param4)
{
  int rv;
  struct xrdp_wm* wm;
  struct xrdp_rect rect;

  if (id == 0) /* "id" should be "struct xrdp_process*" as long */
  {
    return 0;
  }
  wm = ((struct xrdp_process*)id)->wm;
  if (wm == 0)
  {
    return 0;
  }
  rv = 0;
  switch (msg)
  {
    case 0: /* RDP_INPUT_SYNCHRONIZE */
      rv = xrdp_wm_key_sync(wm, param3, param1);
      break;
    case 4: /* RDP_INPUT_SCANCODE */
      rv = xrdp_wm_key(wm, param3, param1);
      break;
    case 0x8001: /* RDP_INPUT_MOUSE */
      rv = xrdp_wm_process_input_mouse(wm, param3, param1, param2);
      break;
    case 0x4444: /* invalidate, this is not from RDP_DATA_PDU_INPUT */
                 /* like the rest, its from RDP_PDU_DATA with code 33 */
                 /* its the rdp client asking for a screen update */
      MAKERECT(rect, param1, param2, param3, param4);
      rv = xrdp_bitmap_invalidate(wm->screen, &rect);
      break;
    case 0x5555: /* called from xrdp_channel.c, channel data has come in,
                    pass it to module if there is one */
      rv = xrdp_wm_process_channel_data(wm, param1, (char*)param2, param3);
      break;
  }
  return rv;
}

/******************************************************************************/
/* returns error */
/* this gets called when there is nothing on any socket */
static int APP_CC
xrdp_wm_login_mode_changed(struct xrdp_wm* self)
{
  if (self == 0)
  {
    return 0;
  }
  if (self->login_mode == 0)
  {
    /* this is the inital state of the login window */
    xrdp_wm_set_login_mode(self, 1); /* put the wm in login mode */
    list_clear(self->log);
    xrdp_wm_delete_all_childs(self);
    self->dragging = 0;
    xrdp_wm_init(self);
  }
  else if (self->login_mode == 2)
  {
    xrdp_wm_set_login_mode(self, 3); /* put the wm in connected mode */
    xrdp_wm_delete_all_childs(self);
    xrdp_wm_background_create(self);
    xrdp_bitmap_invalidate(self->screen, 0);
    self->dragging = 0;
    xrdp_mm_connect(self->mm);
  }
  else if (self->login_mode == 4)
  {
    /* intermediate state used by dmx module */
    xrdp_wm_set_login_mode(self, 5);
  }
  else if (self->login_mode == 10)
  {
    xrdp_wm_delete_all_childs(self);
    xrdp_bitmap_invalidate(self->screen, 0);
    self->dragging = 0;
    xrdp_wm_set_login_mode(self, 11);
  }
  else if (self->login_mode == 20)
  {
    return 1; /* end session */
  }
  return 0;
}

/*****************************************************************************/
/* this is the log windows nofity function */
static int DEFAULT_CC
xrdp_wm_log_wnd_notify(struct xrdp_bitmap* wnd,
                       struct xrdp_bitmap* sender,
                       int msg, long param1, long param2)
{
  struct xrdp_painter* painter;
  struct xrdp_wm* wm;
  struct xrdp_rect rect;
  int index;
  char* text;

  if (wnd == 0)
  {
    return 0;
  }
  if (sender == 0)
  {
    return 0;
  }
  if (wnd->owner == 0)
  {
    return 0;
  }
  wm = wnd->wm;
  if (msg == 1) /* click */
  {
    if (sender->id == 1) /* ok button */
    {
      xrdp_wm_set_login_mode(wm, 20); /* end session */
    }
  }
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_log_msg(struct xrdp_wm* self, char* msg)
{
  struct xrdp_bitmap* but;

  list_add_item(self->log, (long)g_strdup(msg));
  if (self->log_wnd == 0)
  {
    /* log window */
    self->log_wnd = xrdp_bitmap_create(620, 430, self->screen->bpp,
                                       WND_TYPE_WND, self);
    list_insert_item(self->screen->child_list, 0, (long)self->log_wnd);
    self->log_wnd->parent = self->screen;
    self->log_wnd->owner = self->screen;
    self->log_wnd->bg_color = self->grey;
    self->log_wnd->left = 10;
    self->log_wnd->top = 40;
    set_string(&(self->log_wnd->caption1), "Connection Log");

    /* edit */
    self->log_edit = xrdp_bitmap_create(self->log_wnd->width - 18,
					self->log_wnd->height - 72,
					self->screen->bpp,
					WND_TYPE_EDIT, self);
    list_insert_item(self->log_wnd->child_list, 0, (long)self->log_edit);
    self->log_edit->parent = self->log_wnd;
    self->log_edit->owner = self->log_wnd;
    self->log_edit->left = 9;
    self->log_edit->top = 30;
    self->log_edit->id = 2;
    self->log_edit->pointer = 0;
    self->log_edit->tab_stop = 0;
    self->log_edit->edit_pos = 0;
    set_string(&(self->log_edit->caption1), msg);

    /* ok button */
    but = xrdp_bitmap_create(60, 25, self->screen->bpp, WND_TYPE_BUTTON, self);
    list_insert_item(self->log_wnd->child_list, 0, (long)but);
    but->parent = self->log_wnd;
    but->owner = self->log_wnd;
    but->left = (self->log_wnd->width - 60) - 10;
    but->top = (self->log_wnd->height - 25) - 10;
    but->id = 1;
    but->tab_stop = 1;
    set_string(&but->caption1, "OK");
    self->log_wnd->focused_control = but;
    /* set notify function */
    self->log_wnd->notify = xrdp_wm_log_wnd_notify;
  }
  else if (self->log_edit->caption1)
  {
    char buf[8192];
    int  pos;
    int  len;
    int  index;

    msg = (char *)list_get_item(self->log, 0);
    len = g_strlen(msg);
    g_sprintf(buf, "%s", msg);
    pos = len;
    for (index = 1; index < self->log->count; index++)
    {
      msg = (char *)list_get_item(self->log, index);
      len = g_strlen(msg) + 1;
      if (pos + len + 1 < sizeof(buf))
	g_sprintf(buf + pos, "\n%s", msg);
      pos += len;
    }
    set_string(&self->log_edit->caption1, buf);
  }
  xrdp_wm_set_focused(self, self->log_wnd);
  xrdp_bitmap_invalidate(self->log_wnd, 0);
  g_sleep(100);
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_mod_get_wait_objs(struct xrdp_wm* self,
                          tbus* read_objs, int* rcount,
                          tbus* write_objs, int* wcount, int* timeout)
{
  if (self->mm != 0)
  {
    if (self->mm->mod != 0)
    {
      if (self->mm->mod->mod_get_wait_objs != 0)
      {
        return self->mm->mod->mod_get_wait_objs
               (self->mm->mod, read_objs, rcount,
                write_objs, wcount, timeout);
      }
    }
  }
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_mod_check_wait_objs(struct xrdp_wm* self)
{
  if (self->mm != 0)
  {
    if (self->mm->mod != 0)
    {
      if (self->mm->mod->mod_check_wait_objs != 0)
      {
        return self->mm->mod->mod_check_wait_objs(self->mm->mod);
      }
    }
  }
  return 0;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_get_wait_objs(struct xrdp_wm* self, tbus* robjs, int* rc,
                      tbus* wobjs, int* wc, int* timeout)
{
  int i;

  if (self == 0)
  {
    return 0;
  }
  i = *rc;
  robjs[i++] = self->login_mode_event;
  if (self->mm != 0)
  {
    if (self->mm->sck_obj != 0)
    {
      robjs[i++] = self->mm->sck_obj;
    }
  }
  *rc = i;
  return xrdp_wm_mod_get_wait_objs(self, robjs, rc, wobjs, wc, timeout);
}

/******************************************************************************/
int APP_CC
xrdp_wm_check_wait_objs(struct xrdp_wm* self)
{
  int rv;

  if (self == 0)
  {
    return 0;
  }
  rv = 0;
  if (g_is_wait_obj_set(self->login_mode_event))
  {
    g_reset_wait_obj(self->login_mode_event);
    rv = xrdp_wm_login_mode_changed(self);
  }
  if (rv == 0)
  {
    if (self->mm != 0)
    {
      if (self->mm->sck_obj != 0)
      {
        if (g_is_wait_obj_set(self->mm->sck_obj))
        {
          rv = xrdp_mm_signal(self->mm); 
        }
      }
    }
  }
  if (rv == 0)
  {
    rv = xrdp_wm_mod_check_wait_objs(self);
  }
  return rv;
}

/*****************************************************************************/
int APP_CC
xrdp_wm_set_login_mode(struct xrdp_wm* self, int login_mode)
{
  self->login_mode = login_mode;
  g_set_wait_obj(self->login_mode_event);
  return 0;
}
