/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_blake2b.cl"
#endif

KERNEL_FQ void m90001_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS].salt_buf[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    blake2b_ctx_vector_t ctx;

    blake2b_init_vector (&ctx);

    blake2b_update_vector (&ctx, w, pw_len);

    blake2b_update_vector (&ctx, s, salt_len);

    blake2b_final_vector  (&ctx);

    const u32x r0 = h32_from_64 (ctx.h[0]);
    const u32x r1 = l32_from_64 (ctx.h[0]);
    const u32x r2 = h32_from_64 (ctx.h[1]);
    const u32x r3 = l32_from_64 (ctx.h[1]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m90001_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS].salt_buf[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    blake2b_ctx_vector_t ctx;

    blake2b_init_vector (&ctx);

    blake2b_update_vector (&ctx, w, pw_len);

    blake2b_update_vector (&ctx, s, salt_len);

    blake2b_final_vector  (&ctx);

    const u32x r0 = h32_from_64 (ctx.h[0]);
    const u32x r1 = l32_from_64 (ctx.h[0]);
    const u32x r2 = h32_from_64 (ctx.h[1]);
    const u32x r3 = l32_from_64 (ctx.h[1]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
