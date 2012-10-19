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

   main login window and login help window

*/

#include "xrdp.h"

/*****************************************************************************/
/* all login help screen events go here */
static int DEFAULT_CC
xrdp_wm_login_help_notify(struct xrdp_bitmap* wnd,
                          struct xrdp_bitmap* sender,
                          int msg, long param1, long param2)
{
  struct xrdp_painter* p;

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
  if (msg == 1) /* click */
  {
    if (sender->id == 1) /* ok button */
    {
      if (sender->owner->notify != 0)
      {
        wnd->owner->notify(wnd->owner, wnd, 100, 1, 0); /* ok */
      }
    }
  }
  else if (msg == WM_PAINT) /* 3 */
  {
    p = (struct xrdp_painter*)param1;
    if (p != 0)
    {
      p->fg_color = wnd->wm->black;
      xrdp_painter_draw_text(p, wnd, 10, 30, "You must be authenticated \
before using this");
      xrdp_painter_draw_text(p, wnd, 10, 46, "session.");
      xrdp_painter_draw_text(p, wnd, 10, 78, "Enter a valid username in \
the username edit box.");
      xrdp_painter_draw_text(p, wnd, 10, 94, "Enter the password in \
the password edit box.");
      xrdp_painter_draw_text(p, wnd, 10, 110, "Both the username and \
password are case");
      xrdp_painter_draw_text(p, wnd, 10, 126, "sensitive.");
      xrdp_painter_draw_text(p, wnd, 10, 158, "Contact your system \
administrator if you are");
      xrdp_painter_draw_text(p, wnd, 10, 174, "having problems \
logging on.");
    }
  }
  return 0;
}

#if 0
/*****************************************************************************/
static int DEFAULT_CC
xrdp_wm_popup_notify(struct xrdp_bitmap* wnd,
                     struct xrdp_bitmap* sender,
                     int msg, int param1, int param2)
{
  return 0;
}
#endif

/*****************************************************************************/
int APP_CC
xrdp_wm_delete_all_childs(struct xrdp_wm* self)
{
  int index;
  struct xrdp_bitmap* b;
  struct xrdp_rect rect;

  for (index = self->screen->child_list->count - 1; index >= 0; index--)
  {
    b = (struct xrdp_bitmap*)list_get_item(self->screen->child_list, index);
    MAKERECT(rect, b->left, b->top, b->width, b->height);
    xrdp_bitmap_delete(b);
    xrdp_bitmap_invalidate(self->screen, &rect);
  }
  return 0;
}

/*****************************************************************************/
static int APP_CC
set_mod_data_item(struct xrdp_mod_data* mod, char* name, char* value)
{
  int index;

  for (index = 0; index < mod->names->count; index++)
  {
    if (g_strncmp(name, (char*)list_get_item(mod->names, index), 255) == 0)
    {
      list_remove_item(mod->values, index);
      list_insert_item(mod->values, index, (long)g_strdup(value));
    }
  }
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_help_clicked(struct xrdp_bitmap* wnd)
{
  struct xrdp_bitmap* help;
  struct xrdp_bitmap* but;

  /* create help screen */
  help = xrdp_bitmap_create(340, 300, wnd->wm->screen->bpp,
                            WND_TYPE_WND, wnd->wm);
  list_insert_item(wnd->wm->screen->child_list, 0, (long)help);
  help->parent = wnd->wm->screen;
  help->owner = wnd;
  wnd->modal_dialog = help;
  help->bg_color = wnd->wm->grey;
  help->left = wnd->wm->screen->width / 2 - help->width / 2;
  help->top = wnd->wm->screen->height / 2 - help->height / 2;
  help->notify = xrdp_wm_login_help_notify;
  set_string(&help->caption1, "Login help");
  /* ok button */
  but = xrdp_bitmap_create(60, 25, wnd->wm->screen->bpp,
                           WND_TYPE_BUTTON, wnd->wm);
  list_insert_item(help->child_list, 0, (long)but);
  but->parent = help;
  but->owner = help;
  but->left = 140;
  but->top = 260;
  but->id = 1;
  but->tab_stop = 1;
  set_string(&but->caption1, "OK");
  /* draw it */
  help->focused_control = but;
  help->default_button = but;
  help->esc_button = but;
  xrdp_bitmap_invalidate(help, 0);
  xrdp_wm_set_focused(wnd->wm, help);
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_cancel_clicked(struct xrdp_bitmap* wnd)
{
  if (wnd != 0)
  {
    if (wnd->wm != 0)
    {
      if (wnd->wm->pro_layer != 0)
      {
        g_set_wait_obj(wnd->wm->pro_layer->self_term_event);
      }
    }
  }
  return 0;
}

/*****************************************************************************/
static int APP_CC
xrdp_wm_ok_clicked(struct xrdp_bitmap* wnd)
{
  struct xrdp_bitmap* combo;
  struct xrdp_bitmap* label;
  struct xrdp_bitmap* edit;
  struct xrdp_wm* wm;
  struct xrdp_mod_data* mod_data;
  int i;

  wm = wnd->wm;
  combo = xrdp_bitmap_get_child_by_id(wnd, 6);
  if (combo != 0)
  {
    mod_data = (struct xrdp_mod_data*)
             list_get_item(combo->data_list, combo->item_index);
    if (mod_data != 0)
    {
      /* get the user typed values */
      i = 100;
      label = xrdp_bitmap_get_child_by_id(wnd, i);
      edit = xrdp_bitmap_get_child_by_id(wnd, i + 1);
      while (label != 0 && edit != 0)
      {
	if (g_strcmp (label->caption1, "User name:") == 0)
          set_mod_data_item(mod_data, "username", edit->caption1);
	else if (g_strcmp (label->caption1, "Password:") == 0)
          set_mod_data_item(mod_data, "password", edit->caption1);
	else
          set_mod_data_item(mod_data, label->caption1, edit->caption1);
        i += 2;
        label = xrdp_bitmap_get_child_by_id(wnd, i);
        edit = xrdp_bitmap_get_child_by_id(wnd, i + 1);
      }
      list_delete(wm->mm->login_names);
      list_delete(wm->mm->login_values);
      wm->mm->login_names = list_create();
      wm->mm->login_names->auto_free = 1;
      wm->mm->login_values = list_create();
      wm->mm->login_values->auto_free = 1;
      /* gota copy these cause dialog gets freed */
      list_append_list_strdup(mod_data->names, wm->mm->login_names, 0);
      list_append_list_strdup(mod_data->values, wm->mm->login_values, 0);
      xrdp_wm_set_login_mode(wm, 2);
    }
  }
  return 0;
}

/******************************************************************************/
static int APP_CC
xrdp_wm_show_edits(struct xrdp_wm* self, struct xrdp_bitmap* combo)
{
  int count;
  int index;
  int insert_index;
  int username_set;
  char* name;
  char* value;
  struct xrdp_mod_data* mod;
  struct xrdp_bitmap* b;

  username_set = 0;
  /* free labels and edits, cause we gota create them */
  /* creation or combo changed */
  for (index = 100; index < 200; index++)
  {
    b = xrdp_bitmap_get_child_by_id(combo->parent, index);
    xrdp_bitmap_delete(b);
  }

  insert_index = list_index_of(self->login_window->child_list,
                                    (long)combo);
  insert_index++;
  mod = (struct xrdp_mod_data*)
           list_get_item(combo->data_list, combo->item_index);
  if (mod != 0)
  {
    count = 0;
    for (index = 0; index < mod->names->count; index++)
    {
      value = (char*)list_get_item(mod->values, index);
      if (g_strncmp("ask", value, 3) == 0)
      {
        /* label */
        b = xrdp_bitmap_create(70, 20, self->screen->bpp,
                               WND_TYPE_LABEL, self);
        list_insert_item(self->login_window->child_list, insert_index,
                              (long)b);
        insert_index++;
        b->parent = self->login_window;
        b->owner = self->login_window;
        b->left = 16;
        b->top = 159 + 25 * count;
        b->id = 100 + 2 * count;
        name = (char*)list_get_item(mod->names, index);
        if (g_strcmp (name, "username") == 0)
          set_string(&b->caption1, "User name:");
        else
          set_string(&b->caption1, "Password:");
        /* edit */
        b = xrdp_bitmap_create(self->login_window->width - 200, 20, self->screen->bpp,
                               WND_TYPE_EDIT, self);
        list_insert_item(self->login_window->child_list, insert_index,
                              (long)b);
        insert_index++;
        b->parent = self->login_window;
        b->owner = self->login_window;
        b->left = 100;
        b->top = 159 + 25 * count;
        b->id = 100 + 2 * count + 1;
        b->pointer = 1;
        b->tab_stop = 1;
        b->caption1 = (char*)g_malloc(256, 1);
        g_strncpy(b->caption1, value + 3, 255);
        b->edit_pos = g_mbstowcs(0, b->caption1, 0);
        if (self->login_window->focused_control == 0)
        {
          self->login_window->focused_control = b;
        }
        if (g_strncmp(name, "username", 255) == 0)
        {
          g_strncpy(b->caption1, self->session->client_info->username, 255);
          b->edit_pos = g_mbstowcs(0, b->caption1, 0);
          if (b->edit_pos > 0)
          {
            username_set = 1;
          }
        }
        if (g_strncmp(name, "password", 255) == 0)
        {
          b->password_char = '*';
          if (username_set)
          {
            if (b->parent != 0)
            {
              b->parent->focused_control = b;
            }
          }
        }
        count++;
      }
    }
  }
  return 0;
}

/*****************************************************************************/
/* all login screen events go here */
static int DEFAULT_CC
xrdp_wm_login_notify(struct xrdp_bitmap* wnd,
                     struct xrdp_bitmap* sender,
                     int msg, long param1, long param2)
{
  struct xrdp_bitmap* b;
  struct xrdp_rect rect;
  int i;

  if (wnd->modal_dialog != 0 && msg != 100)
  {
    return 0;
  }
  if (msg == 1) /* click */
  {
    if (sender->id == 1) /* help button */
    {
      xrdp_wm_help_clicked(wnd);
    }
    else if (sender->id == 2) /* cancel button */
    {
      xrdp_wm_cancel_clicked(wnd);
    }
    else if (sender->id == 3) /* ok button */
    {
      xrdp_wm_ok_clicked(wnd);
    }
  }
  else if (msg == 2) /* mouse move */
  {
  }
  else if (msg == 100) /* modal result is done */
  {
    i = list_index_of(wnd->wm->screen->child_list, (long)sender);
    if (i >= 0)
    {
      b = (struct xrdp_bitmap*)
              list_get_item(wnd->wm->screen->child_list, i);
      list_remove_item(sender->wm->screen->child_list, i);
      MAKERECT(rect, b->left, b->top, b->width, b->height);
      xrdp_bitmap_invalidate(wnd->wm->screen, &rect);
      xrdp_bitmap_delete(sender);
      wnd->modal_dialog = 0;
      xrdp_wm_set_focused(wnd->wm, wnd);
    }
  }
  else if (msg == CB_ITEMCHANGE) /* combo box change */
  {
    xrdp_bitmap_invalidate(wnd, 0); /* invalidate the whole dialog for now */
  }
  return 0;
}

/******************************************************************************/
static int APP_CC
xrdp_wm_login_fill_in_combo(struct xrdp_wm* self, struct xrdp_bitmap* b)
{
  return xrdp_wm_load_sections(self, b->string_list, b->data_list);
}

/******************************************************************************/
int APP_CC
xrdp_login_wnd_create(struct xrdp_wm* self)
{
  struct xrdp_bitmap* but;
  struct xrdp_bitmap* combo;
  char file_path[256];
  char hostname[256];
  char title[288];
  int i;

  g_strncpy(hostname, "xrdp", 255);
  g_gethostname(hostname, 255);
  hostname[255] = '\0';
  g_snprintf(title, 287, "Log On to %s", hostname);

  /* draw login window */
  self->login_window = xrdp_bitmap_create(404, 278, self->screen->bpp,
                                          WND_TYPE_WND, self);
  list_insert_item(self->screen->child_list, 0, (long)self->login_window);
  self->login_window->parent = self->screen;
  self->login_window->owner = self->screen;
  self->login_window->bg_color = self->grey;
  self->login_window->left = self->screen->width / 2 -
                             self->login_window->width / 2;
  self->login_window->top = self->screen->height / 2 -
                            self->login_window->height / 2;
  self->login_window->notify = xrdp_wm_login_notify;
  set_string(&self->login_window->caption1, title);

  /* image */
  but = xrdp_bitmap_create(4, 4, self->screen->bpp, WND_TYPE_IMAGE, self);
  g_snprintf(file_path, 255, "%s/rdc256.bmp", XRDP_SHARE_PATH);
  xrdp_bitmap_load(but, file_path, self->palette);
  but->parent = self->login_window;
  but->owner = self->login_window;
  but->left = 2;
  but->top = 23;
  list_add_item(self->login_window->child_list, (long)but);

  /* label */
  but = xrdp_bitmap_create(60, 20, self->screen->bpp, WND_TYPE_LABEL, self);
  list_add_item(self->login_window->child_list, (long)but);
  but->parent = self->login_window;
  but->owner = self->login_window;
  but->left = 16;
  but->top = 209;
  set_string(&but->caption1, "Session:");

  /* combo */
  combo = xrdp_bitmap_create(self->login_window->width - 200, 20, self->screen->bpp, WND_TYPE_COMBO, self);
  list_add_item(self->login_window->child_list, (long)combo);
  combo->parent = self->login_window;
  combo->owner = self->login_window;
  combo->left = 100;
  combo->top = 209;
  combo->id = 6;
  combo->tab_stop = 1;
  xrdp_wm_login_fill_in_combo(self, combo);
  for (i = 0; i < combo->string_list->count; i++)
  {
    char *p;
    p = (char*)list_get_item(combo->string_list, i);
    if (g_strncmp(p, self->client_info->program, 255) == 0)
    {
      combo->item_index = i;
      break;
    }
  }

  /* button */
  but = xrdp_bitmap_create(60, 25, self->screen->bpp, WND_TYPE_BUTTON, self);
  list_add_item(self->login_window->child_list, (long)but);
  but->parent = self->login_window;
  but->owner = self->login_window;
  but->left = self->login_window->width - 75;
  but->top = self->login_window->height - 38;
  but->id = 3;
  set_string(&but->caption1, "OK");
  but->tab_stop = 1;
  self->login_window->default_button = but;

  /* button */
  but = xrdp_bitmap_create(60, 25, self->screen->bpp, WND_TYPE_BUTTON, self);
  list_add_item(self->login_window->child_list, (long)but);
  but->parent = self->login_window;
  but->owner = self->login_window;
  but->left = self->login_window->width - 145;
  but->top = self->login_window->height - 38;
  but->id = 2;
  set_string(&but->caption1, "Cancel");
  but->tab_stop = 1;
  self->login_window->esc_button = but;

  /* button
  but = xrdp_bitmap_create(60, 25, self->screen->bpp, WND_TYPE_BUTTON, self);
  list_add_item(self->login_window->child_list, (long)but);
  but->parent = self->login_window;
  but->owner = self->login_window;
  but->left = 320;
  but->top = 160;
  but->id = 1;
  set_string(&but->caption1, "Help");
  but->tab_stop = 1; */

  /* labels and edits */
  xrdp_wm_show_edits(self, combo);

  return 0;
}
