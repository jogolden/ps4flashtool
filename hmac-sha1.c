/* hmac-sha1.c -- hashed message authentication codes
   Copyright (C) 2005, 2006 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Written by Simon Josefsson.  */

/* #include <config.h> */

#include "hmac-sha1.h"
#include "sha1.h"

#include <string.h>

#define IPAD 0x36
#define OPAD 0x5c

void *
memxor (void */*restrict*/ dest, const void */*restrict*/ src, size_t n)
{
  char const *s = (char const*)src;
  char *d = (char*)dest;

  for (; n > 0; n--)
    *d++ ^= *s++;

  return dest;
}

/*!
 * @fn int hmac_sha1 (const void *key, size_t keylen, const void *in, size_t inlen, void *resbuf)
 *
 * @brief Compute Hashed Message Authentication Code with SHA-1
 *
 * @details Compute Hashed Message Authentication Code with SHA-1, over IN
 *          data of INLEN bytes using the KEY of KEYLEN bytes, writing the
 *          output to pre-allocated 20 byte minimum RESBUF buffer.  Return 0 on
 *          success
 *
 * @param[in]  key     key used to create the HMAC
 * @param[in]  keylen  length of key
 * @param[in]  in      input data to be hashed
 * @param[in]  inlen   length of input data
 * @param[out] resbuf  buffer used to store resulting HMAC
 * @return 0 on success
 */

int
hmac_sha1 (const void *key, size_t keylen,
	   const void *in, size_t inlen, void *resbuf)
{
  struct sha1_ctx inner;
  struct sha1_ctx outer;
  char optkeybuf[20];
  char block[64];
  char innerhash[20];

  /* Reduce the key's size, so that it becomes <= 64 bytes large.  */

  if (keylen > 64)
    {
      struct sha1_ctx keyhash;

      sha1_init_ctx (&keyhash);
      sha1_process_bytes (key, keylen, &keyhash);
      sha1_finish_ctx (&keyhash, optkeybuf);

      key = optkeybuf;
      keylen = 20;
    }

  /* Compute INNERHASH from KEY and IN.  */

  sha1_init_ctx (&inner);

  memset (block, IPAD, sizeof (block));
  memxor (block, key, keylen);

  sha1_process_block (block, 64, &inner);
  sha1_process_bytes (in, inlen, &inner);

  sha1_finish_ctx (&inner, innerhash);

  /* Compute result from KEY and INNERHASH.  */

  sha1_init_ctx (&outer);

  memset (block, OPAD, sizeof (block));
  memxor (block, key, keylen);

  sha1_process_block (block, 64, &outer);
  sha1_process_bytes (innerhash, 20, &outer);

  sha1_finish_ctx (&outer, resbuf);

  return 0;
}
