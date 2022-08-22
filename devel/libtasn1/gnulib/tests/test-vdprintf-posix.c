/* Test of POSIX compatible vdprintf() function.
   Copyright (C) 2007-2021 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* Written by Bruno Haible <bruno@clisp.org>, 2009.  */

#include <config.h>

#include <stdio.h>

#include "signature.h"
SIGNATURE_CHECK (vdprintf, int, (int, char const *, va_list));

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "macros.h"

#include "test-fprintf-posix.h"

static int
my_fprintf (FILE *fp, const char *format, ...)
{
  va_list args;
  int ret;

  va_start (args, format);
  ret = vdprintf (fileno (fp), format, args);
  va_end (args);
  return ret;
}

int
main (int argc, char *argv[])
{
  test_function (my_fprintf);
  return 0;
}
