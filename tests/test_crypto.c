/* SPDX-License-Identifier: MPL-2.0 */
#include "wapi.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    const uint8_t plain[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    const uint8_t cipher[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
    uint8_t zero[64] = {0}, out[65], inplace[64], mic[16], padded[16] = {0};
    assert(wapi_sm_wpi_encrypt(NULL,NULL,0,NULL,NULL) == 1);
    assert(wapi_sm_wpi_decrypt(NULL,NULL,0,NULL,NULL) == 1);
    assert(wapi_sm_wpi_calc_mic(NULL,NULL,0,NULL,NULL) == 1);
    assert(wapi_sm_wpi_encrypt(plain,zero,16,plain,out) == 0);
    assert(memcmp(out,cipher,16) == 0);
    assert(wapi_sm_wpi_decrypt(cipher,zero,16,plain,out) == 0);
    assert(memcmp(out,plain,16) == 0);
    for (unsigned n = 1; n <= 64; ++n) {
        memset(out,0xa5,sizeof out);
        memset(inplace,0,sizeof inplace);
        assert(wapi_sm_wpi_encrypt(plain,zero,n,plain,out) == 0);
        assert(out[n] == 0xa5);
        assert(wapi_sm_wpi_encrypt(plain,inplace,n,plain,inplace) == 0);
        assert(memcmp(inplace,out,n) == 0);
        assert(wapi_sm_wpi_decrypt(plain,zero,n,plain,out) == 0);
        memset(inplace,0,sizeof inplace);
        assert(wapi_sm_wpi_decrypt(plain,inplace,n,plain,inplace) == 0);
        assert(memcmp(inplace,out,n) == 0);
    }
    for (unsigned n = 1; n < 16; ++n) {
        memset(padded,0,sizeof padded);
        memcpy(padded,plain,n);
        wapi_sm_wpi_calc_mic(plain,plain,n,plain,mic);
        wapi_sm_wpi_calc_mic(plain,padded,16,plain,out);
        assert(memcmp(mic,out,16) == 0);
    }
    puts("crypto known vector, zero-length, alias, boundary and MIC padding checks passed");
    return 0;
}
