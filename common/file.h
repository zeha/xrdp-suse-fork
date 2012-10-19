/*
   Copyright (c) 2004-2008 Jay Sorg

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.

   read a config file
*/

#if !defined(FILE_H)
#define FILE_H

#include "arch.h"
#include "parse.h"

int APP_CC
file_read_line(struct stream* s, char* text);
int APP_CC
file_split_name_value(char* text, char* name, char* value);
int APP_CC
file_read_sections(int fd, struct list* names);
int APP_CC
file_by_name_read_sections(const char* file_name, struct list* names);
int APP_CC
file_read_section(int fd, const char* section,
                  struct list* names, struct list* values);
int APP_CC
file_by_name_read_section(const char* file_name, const char* section,
                          struct list* names, struct list* values);

#endif
