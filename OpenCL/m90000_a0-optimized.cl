/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#endif

#define BLAKE2B_G_VECTOR_64(k0,k1,a,b,c,d) \
{                                          \
  a = a + b + hl32_to_64(m[2*k0 + 1], m[2*k0]);  \
  d = hc_rotr64 (d ^ a, 32);               \
  c = c + d;                               \
  b = hc_rotr64 (b ^ c, 24);               \
  a = a + b + hl32_to_64(m[2*k1 + 1], m[2*k1]);  \
  d = hc_rotr64 (d ^ a, 16);               \
  c = c + d;                               \
  b = hc_rotr64 (b ^ c, 63);               \
}

#define BLAKE2B_ROUND_VECTOR_64(c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf) \
{                                                                                \
  BLAKE2B_G_VECTOR_64 (c0, c1, v[0], v[4], v[ 8], v[12]);                        \
  BLAKE2B_G_VECTOR_64 (c2, c3, v[1], v[5], v[ 9], v[13]);                        \
  BLAKE2B_G_VECTOR_64 (c4, c5, v[2], v[6], v[10], v[14]);                        \
  BLAKE2B_G_VECTOR_64 (c6, c7, v[3], v[7], v[11], v[15]);                        \
  BLAKE2B_G_VECTOR_64 (c8, c9, v[0], v[5], v[10], v[15]);                        \
  BLAKE2B_G_VECTOR_64 (ca, cb, v[1], v[6], v[11], v[12]);                        \
  BLAKE2B_G_VECTOR_64 (cc, cd, v[2], v[7], v[ 8], v[13]);                        \
  BLAKE2B_G_VECTOR_64 (ce, cf, v[3], v[4], v[ 9], v[14]);                        \
}

void blake2b_compute (u64x* h, u32x* m, u32x len) {
  const u64x t0 = hl32_to_64 (0, len);

  u64x v[16];

  v[ 0] = BLAKE2B_IV_00 ^ 0x01010040;
  v[ 1] = BLAKE2B_IV_01;
  v[ 2] = BLAKE2B_IV_02;
  v[ 3] = BLAKE2B_IV_03;
  v[ 4] = BLAKE2B_IV_04;
  v[ 5] = BLAKE2B_IV_05;
  v[ 6] = BLAKE2B_IV_06;
  v[ 7] = BLAKE2B_IV_07;
  v[ 8] = BLAKE2B_IV_00;
  v[ 9] = BLAKE2B_IV_01;
  v[10] = BLAKE2B_IV_02;
  v[11] = BLAKE2B_IV_03;
  v[12] = BLAKE2B_IV_04 ^ t0;
  v[13] = BLAKE2B_IV_05; // ^ t1;
  v[14] = BLAKE2B_IV_06 ^ 0xffffffffffffffff;
  v[15] = BLAKE2B_IV_07; // ^ f1;

  BLAKE2B_ROUND_VECTOR_64 ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15);
  BLAKE2B_ROUND_VECTOR_64 (14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3);
  BLAKE2B_ROUND_VECTOR_64 (11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4);
  BLAKE2B_ROUND_VECTOR_64 ( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8);
  BLAKE2B_ROUND_VECTOR_64 ( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13);
  BLAKE2B_ROUND_VECTOR_64 ( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9);
  BLAKE2B_ROUND_VECTOR_64 (12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11);
  BLAKE2B_ROUND_VECTOR_64 (13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10);
  BLAKE2B_ROUND_VECTOR_64 ( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5);
  BLAKE2B_ROUND_VECTOR_64 (10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0);
  BLAKE2B_ROUND_VECTOR_64 ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15);
  BLAKE2B_ROUND_VECTOR_64 (14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3);

  h[0] = BLAKE2B_IV_00 ^ 0x01010040 ^ v[0] ^ v[ 8];
  h[1] = BLAKE2B_IV_01 ^ v[1] ^ v[ 9];
  h[2] = BLAKE2B_IV_02 ^ v[2] ^ v[10];
  h[3] = BLAKE2B_IV_03 ^ v[3] ^ v[11];
  h[4] = BLAKE2B_IV_04 ^ v[4] ^ v[12];
  h[5] = BLAKE2B_IV_05 ^ v[5] ^ v[13];
  h[6] = BLAKE2B_IV_06 ^ v[6] ^ v[14];
  h[7] = BLAKE2B_IV_07 ^ v[7] ^ v[15];
}

KERNEL_FQ void m90000_m04 (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];
  u32 salt_buf4[4];
  u32 salt_buf5[4];
  u32 salt_buf6[4];
  u32 salt_buf7[4];

  salt_buf0[0] = salt_bufs[SALT_POS].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[SALT_POS].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[SALT_POS].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[SALT_POS].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[SALT_POS].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[SALT_POS].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[SALT_POS].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[SALT_POS].salt_buf[ 7];
  salt_buf2[0] = salt_bufs[SALT_POS].salt_buf[ 8];
  salt_buf2[1] = salt_bufs[SALT_POS].salt_buf[ 9];
  salt_buf2[2] = salt_bufs[SALT_POS].salt_buf[10];
  salt_buf2[3] = salt_bufs[SALT_POS].salt_buf[11];
  salt_buf3[0] = salt_bufs[SALT_POS].salt_buf[12];
  salt_buf3[1] = salt_bufs[SALT_POS].salt_buf[13];
  salt_buf3[2] = salt_bufs[SALT_POS].salt_buf[14];
  salt_buf3[3] = salt_bufs[SALT_POS].salt_buf[15];
  salt_buf4[0] = salt_bufs[SALT_POS].salt_buf[16];
  salt_buf4[1] = salt_bufs[SALT_POS].salt_buf[17];
  salt_buf4[2] = salt_bufs[SALT_POS].salt_buf[18];
  salt_buf4[3] = salt_bufs[SALT_POS].salt_buf[19];
  salt_buf5[0] = salt_bufs[SALT_POS].salt_buf[20];
  salt_buf5[1] = salt_bufs[SALT_POS].salt_buf[21];
  salt_buf5[2] = salt_bufs[SALT_POS].salt_buf[22];
  salt_buf5[3] = salt_bufs[SALT_POS].salt_buf[23];
  salt_buf6[0] = salt_bufs[SALT_POS].salt_buf[24];
  salt_buf6[1] = salt_bufs[SALT_POS].salt_buf[25];
  salt_buf6[2] = salt_bufs[SALT_POS].salt_buf[26];
  salt_buf6[3] = salt_bufs[SALT_POS].salt_buf[27];
  salt_buf7[0] = salt_bufs[SALT_POS].salt_buf[28];
  salt_buf7[1] = salt_bufs[SALT_POS].salt_buf[29];
  salt_buf7[2] = salt_bufs[SALT_POS].salt_buf[30];
  salt_buf7[3] = salt_bufs[SALT_POS].salt_buf[31];

  const u32 salt_len = salt_bufs[SALT_POS].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x m[32];

    m[ 0] = 0;
    m[ 1] = 0;
    m[ 2] = 0;
    m[ 3] = 0;
    m[ 4] = 0;
    m[ 5] = 0;
    m[ 6] = 0;
    m[ 7] = 0;
    m[ 8] = 0;
    m[ 9] = 0;
    m[10] = 0;
    m[11] = 0;
    m[12] = 0;
    m[13] = 0;
    m[14] = 0;
    m[15] = 0;
    m[16] = 0;
    m[17] = 0;
    m[18] = 0;
    m[19] = 0;
    m[20] = 0;
    m[21] = 0;
    m[22] = 0;
    m[23] = 0;
    m[24] = 0;
    m[25] = 0;
    m[26] = 0;
    m[27] = 0;
    m[28] = 0;
    m[29] = 0;
    m[30] = 0;
    m[31] = 0;

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, &m[0], &m[4]);

    /**
     * prepend salt
     */

    const u32x out_salt_len = out_len + salt_len;
    // printf("pass : %08x%08x%08x%08x%08x%08x\n", hc_swap32(m[0]), hc_swap32(m[1]), hc_swap32(m[2]), hc_swap32(m[3]), hc_swap32(m[4]), hc_swap32(m[5]));

    switch_buffer_by_offset_8x4_le (&m[0], &m[4], &m[8], &m[12], &m[16], &m[20], &m[24], &m[28], salt_len);

    // printf("pass shifted : %08x%08x%08x%08x%08x%08x\n", hc_swap32(m[0]), hc_swap32(m[1]), hc_swap32(m[2]), hc_swap32(m[3]), hc_swap32(m[4]), hc_swap32(m[5]));

    m[ 0] |= salt_buf0[0];
    m[ 1] |= salt_buf0[1];
    m[ 2] |= salt_buf0[2];
    m[ 3] |= salt_buf0[3];
    m[ 4] |= salt_buf1[0];
    m[ 5] |= salt_buf1[1];
    m[ 6] |= salt_buf1[2];
    m[ 7] |= salt_buf1[3];
    m[ 8] |= salt_buf2[0];
    m[ 9] |= salt_buf2[1];
    m[10] |= salt_buf2[2];
    m[11] |= salt_buf2[3];
    m[12] |= salt_buf3[0];
    m[13] |= salt_buf3[1];
    m[14] |= salt_buf3[2];
    m[15] |= salt_buf3[3];
    m[16] |= salt_buf4[0];
    m[17] |= salt_buf4[1];
    m[18] |= salt_buf4[2];
    m[19] |= salt_buf4[3];
    m[20] |= salt_buf5[0];
    m[21] |= salt_buf5[1];
    m[22] |= salt_buf5[2];
    m[23] |= salt_buf5[3];
    m[24] |= salt_buf6[0];
    m[25] |= salt_buf6[1];
    m[26] |= salt_buf6[2];
    m[27] |= salt_buf6[3];
    m[28] |= salt_buf7[0];
    m[29] |= salt_buf7[1];
    m[30] |= salt_buf7[2];
    m[31] |= salt_buf7[3];

    u64x h[8];

    // printf("pass + salt : %08x%08x%08x%08x%08x%08x\n", hc_swap32(m[0]), hc_swap32(m[1]), hc_swap32(m[2]), hc_swap32(m[3]), hc_swap32(m[4]), hc_swap32(m[5]));
    // printf("message + salt length : %d\n", out_salt_len);

    blake2b_compute (h, m, out_salt_len);

    const u32x r0 = h32_from_64 (h[0]);
    const u32x r1 = l32_from_64 (h[0]);
    const u32x r2 = h32_from_64 (h[1]);
    const u32x r3 = l32_from_64 (h[1]);

    // printf("hash : %08x%08x%08x%08x\n", hc_swap32(r1), hc_swap32(r0), hc_swap32(r3), hc_swap32(r2));

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m90000_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m90000_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m90000_s04 (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];
  u32 salt_buf4[4];
  u32 salt_buf5[4];
  u32 salt_buf6[4];
  u32 salt_buf7[4];

  salt_buf0[0] = salt_bufs[SALT_POS].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[SALT_POS].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[SALT_POS].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[SALT_POS].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[SALT_POS].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[SALT_POS].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[SALT_POS].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[SALT_POS].salt_buf[ 7];
  salt_buf2[0] = salt_bufs[SALT_POS].salt_buf[ 8];
  salt_buf2[1] = salt_bufs[SALT_POS].salt_buf[ 9];
  salt_buf2[2] = salt_bufs[SALT_POS].salt_buf[10];
  salt_buf2[3] = salt_bufs[SALT_POS].salt_buf[11];
  salt_buf3[0] = salt_bufs[SALT_POS].salt_buf[12];
  salt_buf3[1] = salt_bufs[SALT_POS].salt_buf[13];
  salt_buf3[2] = salt_bufs[SALT_POS].salt_buf[14];
  salt_buf3[3] = salt_bufs[SALT_POS].salt_buf[15];
  salt_buf4[0] = salt_bufs[SALT_POS].salt_buf[16];
  salt_buf4[1] = salt_bufs[SALT_POS].salt_buf[17];
  salt_buf4[2] = salt_bufs[SALT_POS].salt_buf[18];
  salt_buf4[3] = salt_bufs[SALT_POS].salt_buf[19];
  salt_buf5[0] = salt_bufs[SALT_POS].salt_buf[20];
  salt_buf5[1] = salt_bufs[SALT_POS].salt_buf[21];
  salt_buf5[2] = salt_bufs[SALT_POS].salt_buf[22];
  salt_buf5[3] = salt_bufs[SALT_POS].salt_buf[23];
  salt_buf6[0] = salt_bufs[SALT_POS].salt_buf[24];
  salt_buf6[1] = salt_bufs[SALT_POS].salt_buf[25];
  salt_buf6[2] = salt_bufs[SALT_POS].salt_buf[26];
  salt_buf6[3] = salt_bufs[SALT_POS].salt_buf[27];
  salt_buf7[0] = salt_bufs[SALT_POS].salt_buf[28];
  salt_buf7[1] = salt_bufs[SALT_POS].salt_buf[29];
  salt_buf7[2] = salt_bufs[SALT_POS].salt_buf[30];
  salt_buf7[3] = salt_bufs[SALT_POS].salt_buf[31];

  const u32 salt_len = salt_bufs[SALT_POS].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x m[32];

    m[ 0] = 0;
    m[ 1] = 0;
    m[ 2] = 0;
    m[ 3] = 0;
    m[ 4] = 0;
    m[ 5] = 0;
    m[ 6] = 0;
    m[ 7] = 0;
    m[ 8] = 0;
    m[ 9] = 0;
    m[10] = 0;
    m[11] = 0;
    m[12] = 0;
    m[13] = 0;
    m[14] = 0;
    m[15] = 0;
    m[16] = 0;
    m[17] = 0;
    m[18] = 0;
    m[19] = 0;
    m[20] = 0;
    m[21] = 0;
    m[22] = 0;
    m[23] = 0;
    m[24] = 0;
    m[25] = 0;
    m[26] = 0;
    m[27] = 0;
    m[28] = 0;
    m[29] = 0;
    m[30] = 0;
    m[31] = 0;

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, &m[0], &m[4]);

    /**
     * prepend salt
     */

    const u32x out_salt_len = out_len + salt_len;
    // printf("pass : %08x%08x%08x%08x%08x%08x\n", hc_swap32(m[0]), hc_swap32(m[1]), hc_swap32(m[2]), hc_swap32(m[3]), hc_swap32(m[4]), hc_swap32(m[5]));

    switch_buffer_by_offset_8x4_le (&m[0], &m[4], &m[8], &m[12], &m[16], &m[20], &m[24], &m[28], salt_len);

    // printf("pass shifted : %08x%08x%08x%08x%08x%08x\n", hc_swap32(m[0]), hc_swap32(m[1]), hc_swap32(m[2]), hc_swap32(m[3]), hc_swap32(m[4]), hc_swap32(m[5]));

    m[ 0] |= salt_buf0[0];
    m[ 1] |= salt_buf0[1];
    m[ 2] |= salt_buf0[2];
    m[ 3] |= salt_buf0[3];
    m[ 4] |= salt_buf1[0];
    m[ 5] |= salt_buf1[1];
    m[ 6] |= salt_buf1[2];
    m[ 7] |= salt_buf1[3];
    m[ 8] |= salt_buf2[0];
    m[ 9] |= salt_buf2[1];
    m[10] |= salt_buf2[2];
    m[11] |= salt_buf2[3];
    m[12] |= salt_buf3[0];
    m[13] |= salt_buf3[1];
    m[14] |= salt_buf3[2];
    m[15] |= salt_buf3[3];
    m[16] |= salt_buf4[0];
    m[17] |= salt_buf4[1];
    m[18] |= salt_buf4[2];
    m[19] |= salt_buf4[3];
    m[20] |= salt_buf5[0];
    m[21] |= salt_buf5[1];
    m[22] |= salt_buf5[2];
    m[23] |= salt_buf5[3];
    m[24] |= salt_buf6[0];
    m[25] |= salt_buf6[1];
    m[26] |= salt_buf6[2];
    m[27] |= salt_buf6[3];
    m[28] |= salt_buf7[0];
    m[29] |= salt_buf7[1];
    m[30] |= salt_buf7[2];
    m[31] |= salt_buf7[3];

    u64x h[8];

    // printf("pass + salt : %08x%08x%08x%08x%08x%08x\n", hc_swap32(m[0]), hc_swap32(m[1]), hc_swap32(m[2]), hc_swap32(m[3]), hc_swap32(m[4]), hc_swap32(m[5]));
    // printf("message + salt length : %d\n", out_salt_len);

    blake2b_compute (h, m, out_salt_len);

    const u32x r0 = h32_from_64 (h[0]);
    const u32x r1 = l32_from_64 (h[0]);
    const u32x r2 = h32_from_64 (h[1]);
    const u32x r3 = l32_from_64 (h[1]);

    // printf("hash : %08x%08x%08x%08x\n", hc_swap32(r1), hc_swap32(r0), hc_swap32(r3), hc_swap32(r2));

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m90000_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m90000_s16 (KERN_ATTR_RULES ())
{
}
