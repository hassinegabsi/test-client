#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <stdint.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define assert(a) if( !( a ) )                                      \
{                                                                   \
    mbedtls_fprintf( stderr, "Assertion Failed at %s:%d - %s\n",   \
                             __FILE__, __LINE__, #a );              \
    mbedtls_exit( 1 );                                             \
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

static int unhexify( unsigned char *obuf, const char *ibuf )
{
    unsigned char c, c2;
    int len = strlen( ibuf ) / 2;
    assert( strlen( ibuf ) % 2 == 0 ); // must be even number of bytes

    while( *ibuf != 0 )
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify( unsigned char *obuf, const unsigned char *ibuf, int len )
{
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * Allocate and zeroize a buffer.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *zero_alloc( size_t len )
{
    void *p;
    size_t actual_len = ( len != 0 ) ? len : 1;

    p = mbedtls_calloc( 1, actual_len );
    assert( p != NULL );

    memset( p, 0x00, actual_len );

    return( p );
}

/**
 * Allocate and fill a buffer from hex data.
 *
 * The buffer is sized exactly as needed. This allows to detect buffer
 * overruns (including overreads) when running the test suite under valgrind.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *unhexify_alloc( const char *ibuf, size_t *olen )
{
    unsigned char *obuf;

    *olen = strlen( ibuf ) / 2;

    if( *olen == 0 )
        return( zero_alloc( *olen ) );

    obuf = mbedtls_calloc( 1, *olen );
    assert( obuf != NULL );

    (void) unhexify( obuf, ibuf );

    return( obuf );
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 * 
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += ( ( ( info->v1 << 4 ) ^ ( info->v1 >> 5 ) )
                            + info->v1 ) ^ ( sum + k[sum & 3] );
            sum += delta;
            info->v1 += ( ( ( info->v0 << 4 ) ^ ( info->v0 >> 5 ) )
                            + info->v0 ) ^ ( sum + k[( sum>>11 ) & 3] );
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}


#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_BIGNUM_C)
#if defined(MBEDTLS_GENPRIME)

#include "mbedtls/rsa.h"
#include "mbedtls/md2.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#endif /* defined(MBEDTLS_RSA_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */
#endif /* defined(MBEDTLS_GENPRIME) */


#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_exit       exit
#define mbedtls_free       free
#define mbedtls_calloc     calloc
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

static int test_errors = 0;

#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_BIGNUM_C)
#if defined(MBEDTLS_GENPRIME)

#define TEST_SUITE_ACTIVE

static void test_fail( const char *test )
{
    test_errors++;
    if( test_errors == 1 )
        mbedtls_printf( "FAILED\n" );
    mbedtls_printf( "  %s\n", test );
}

#define TEST_ASSERT( TEST )                         \
    do {                                            \
        if( ! (TEST) )                              \
        {                                           \
            test_fail( #TEST );                     \
            goto exit;                              \
        }                                           \
    } while( 0 )

int verify_string( char **str )
{
    if( (*str)[0] != '"' ||
        (*str)[strlen( *str ) - 1] != '"' )
    {
        mbedtls_printf( "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    (*str)++;
    (*str)[strlen( *str ) - 1] = '\0';

    return( 0 );
}

int verify_int( char *str, int *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && str[i] == 'x' )
        {
            hex = 1;
            continue;
        }

        if( ! ( ( str[i] >= '0' && str[i] <= '9' ) ||
                ( hex && ( ( str[i] >= 'a' && str[i] <= 'f' ) ||
                           ( str[i] >= 'A' && str[i] <= 'F' ) ) ) ) )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

    if( strcmp( str, "MBEDTLS_ERR_RSA_KEY_CHECK_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_INVALID_PADDING" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_INVALID_PADDING );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_VERIFY_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_VERIFY_FAILED );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_MD_MD4" ) == 0 )
    {
        *value = ( MBEDTLS_MD_MD4 );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA224" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA224 );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_PUBLIC_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_PUBLIC_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA384" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA384 );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_MD_MD2" ) == 0 )
    {
        *value = ( MBEDTLS_MD_MD2 );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_RNG_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_RNG_FAILED );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_PRIVATE_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_PRIVATE_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_MD_MD5" ) == 0 )
    {
        *value = ( MBEDTLS_MD_MD5 );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA256" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA256 );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_RSA_PKCS_V15" ) == 0 )
    {
        *value = ( MBEDTLS_RSA_PKCS_V15 );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA1" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA1 );
        return( 0 );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA512" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA512 );
        return( 0 );
    }


    mbedtls_printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

void test_suite_mbedtls_rsa_pkcs1_sign( char *message_hex_string, int padding_mode, int digest,
                     int mod, int radix_P, char *input_P, int radix_Q,
                     char *input_Q, int radix_N, char *input_N, int radix_E,
                     char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    mbedtls_mpi P1, Q1, H, G;
    int msg_len;
    rnd_pseudo_info rnd_info;

    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 ); mbedtls_mpi_init( &H ); mbedtls_mpi_init( &G );
    mbedtls_rsa_init( &ctx, padding_mode, 0 );

    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    ctx.len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_gcd( &G, &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );

    if( mbedtls_md_info_from_type( digest ) != NULL )
        TEST_ASSERT( mbedtls_md( mbedtls_md_info_from_type( digest ), message_str, msg_len, hash_result ) == 0 );

    TEST_ASSERT( mbedtls_rsa_pkcs1_sign( &ctx, &rnd_pseudo_rand, &rnd_info, MBEDTLS_RSA_PRIVATE, digest, 0, hash_result, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

exit:
    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &H ); mbedtls_mpi_free( &G );
    mbedtls_rsa_free( &ctx );
}

void test_suite_mbedtls_rsa_pkcs1_verify( char *message_hex_string, int padding_mode, int digest,
                       int mod, int radix_N, char *input_N, int radix_E,
                       char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char result_str[1000];
    mbedtls_rsa_context ctx;
    int msg_len;

    mbedtls_rsa_init( &ctx, padding_mode, 0 );
    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( result_str, 0x00, 1000 );

    ctx.len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );
    unhexify( result_str, result_hex_str );

    if( mbedtls_md_info_from_type( digest ) != NULL )
        TEST_ASSERT( mbedtls_md( mbedtls_md_info_from_type( digest ), message_str, msg_len, hash_result ) == 0 );

    TEST_ASSERT( mbedtls_rsa_pkcs1_verify( &ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC, digest, 0, hash_result, result_str ) == result );

exit:
    mbedtls_rsa_free( &ctx );
}

void test_suite_rsa_pkcs1_sign_raw( char *message_hex_string, char *hash_result_string,
                         int padding_mode, int mod, int radix_P, char *input_P,
                         int radix_Q, char *input_Q, int radix_N,
                         char *input_N, int radix_E, char *input_E,
                         char *result_hex_str )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    mbedtls_mpi P1, Q1, H, G;
    int hash_len;
    rnd_pseudo_info rnd_info;

    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 ); mbedtls_mpi_init( &H ); mbedtls_mpi_init( &G );
    mbedtls_rsa_init( &ctx, padding_mode, 0 );

    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    ctx.len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_gcd( &G, &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );
    hash_len = unhexify( hash_result, hash_result_string );

    TEST_ASSERT( mbedtls_rsa_pkcs1_sign( &ctx, &rnd_pseudo_rand, &rnd_info, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_NONE, hash_len, hash_result, output ) == 0 );

    hexify( output_str, output, ctx.len );

    TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );

    /* For PKCS#1 v1.5, there is an alternative way to generate signatures */
    if( padding_mode == MBEDTLS_RSA_PKCS_V15 )
    {
        memset( output, 0x00, 1000 );
        memset( output_str, 0x00, 1000 );

        TEST_ASSERT( mbedtls_rsa_rsaes_pkcs1_v15_encrypt( &ctx,
                    &rnd_pseudo_rand, &rnd_info, MBEDTLS_RSA_PRIVATE,
                    hash_len, hash_result, output ) == 0 );

        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

exit:
    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &H ); mbedtls_mpi_free( &G );
    mbedtls_rsa_free( &ctx );
}

void test_suite_rsa_pkcs1_verify_raw( char *message_hex_string, char *hash_result_string,
                           int padding_mode, int mod, int radix_N,
                           char *input_N, int radix_E, char *input_E,
                           char *result_hex_str, int correct )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char result_str[1000];
    unsigned char output[1000];
    mbedtls_rsa_context ctx;
    size_t hash_len, olen;

    mbedtls_rsa_init( &ctx, padding_mode, 0 );
    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( result_str, 0x00, 1000 );
    memset( output, 0x00, sizeof( output ) );

    ctx.len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );
    hash_len = unhexify( hash_result, hash_result_string );
    unhexify( result_str, result_hex_str );

    TEST_ASSERT( mbedtls_rsa_pkcs1_verify( &ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE, hash_len, hash_result, result_str ) == correct );

    /* For PKCS#1 v1.5, there is an alternative way to verify signatures */
    if( padding_mode == MBEDTLS_RSA_PKCS_V15 )
    {
        int ok;

        TEST_ASSERT( mbedtls_rsa_rsaes_pkcs1_v15_decrypt( &ctx,
                    NULL, NULL, MBEDTLS_RSA_PUBLIC,
                    &olen, result_str, output, sizeof( output ) ) == 0 );

        ok = olen == hash_len && memcmp( output, hash_result, olen ) == 0;
        if( correct == 0 )
            TEST_ASSERT( ok == 1 );
        else
            TEST_ASSERT( ok == 0 );
    }

exit:
    mbedtls_rsa_free( &ctx );
}

void test_suite_mbedtls_rsa_pkcs1_encrypt( char *message_hex_string, int padding_mode, int mod,
                        int radix_N, char *input_N, int radix_E, char *input_E,
                        char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    size_t msg_len;
    rnd_pseudo_info rnd_info;

    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    mbedtls_rsa_init( &ctx, padding_mode, 0 );
    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );

    ctx.len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );

    TEST_ASSERT( mbedtls_rsa_pkcs1_encrypt( &ctx, &rnd_pseudo_rand, &rnd_info, MBEDTLS_RSA_PUBLIC, msg_len, message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

exit:
    mbedtls_rsa_free( &ctx );
}

void test_suite_rsa_pkcs1_encrypt_bad_rng( char *message_hex_string, int padding_mode,
                                int mod, int radix_N, char *input_N,
                                int radix_E, char *input_E,
                                char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    size_t msg_len;

    mbedtls_rsa_init( &ctx, padding_mode, 0 );
    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );

    ctx.len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );

    TEST_ASSERT( mbedtls_rsa_pkcs1_encrypt( &ctx, &rnd_zero_rand, NULL, MBEDTLS_RSA_PUBLIC, msg_len, message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

exit:
    mbedtls_rsa_free( &ctx );
}

void test_suite_mbedtls_rsa_pkcs1_decrypt( char *message_hex_string, int padding_mode, int mod,
                        int radix_P, char *input_P, int radix_Q, char *input_Q,
                        int radix_N, char *input_N, int radix_E, char *input_E,
                        int max_output, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    mbedtls_mpi P1, Q1, H, G;
    size_t output_len;
    rnd_pseudo_info rnd_info;

    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 ); mbedtls_mpi_init( &H ); mbedtls_mpi_init( &G );
    mbedtls_rsa_init( &ctx, padding_mode, 0 );

    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    ctx.len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_gcd( &G, &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );
    output_len = 0;

    TEST_ASSERT( mbedtls_rsa_pkcs1_decrypt( &ctx, rnd_pseudo_rand, &rnd_info, MBEDTLS_RSA_PRIVATE, &output_len, message_str, output, max_output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strncasecmp( (char *) output_str, result_hex_str, strlen( result_hex_str ) ) == 0 );
    }

exit:
    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &H ); mbedtls_mpi_free( &G );
    mbedtls_rsa_free( &ctx );
}

void test_suite_mbedtls_rsa_public( char *message_hex_string, int mod, int radix_N, char *input_N,
                 int radix_E, char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx, ctx2; /* Also test mbedtls_rsa_copy() while at it */

    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_rsa_init( &ctx2, MBEDTLS_RSA_PKCS_V15, 0 );
    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );

    ctx.len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );

    TEST_ASSERT( mbedtls_rsa_public( &ctx, message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

    /* And now with the copy */
    TEST_ASSERT( mbedtls_rsa_copy( &ctx2, &ctx ) == 0 );
    /* clear the original to be sure */
    mbedtls_rsa_free( &ctx );

    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx2 ) == 0 );

    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    TEST_ASSERT( mbedtls_rsa_public( &ctx2, message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx2.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

exit:
    mbedtls_rsa_free( &ctx );
    mbedtls_rsa_free( &ctx2 );
}

void test_suite_mbedtls_rsa_private( char *message_hex_string, int mod, int radix_P, char *input_P,
                  int radix_Q, char *input_Q, int radix_N, char *input_N,
                  int radix_E, char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx, ctx2; /* Also test mbedtls_rsa_copy() while at it */
    mbedtls_mpi P1, Q1, H, G;
    rnd_pseudo_info rnd_info;
    int i;

    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 ); mbedtls_mpi_init( &H ); mbedtls_mpi_init( &G );
    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_rsa_init( &ctx2, MBEDTLS_RSA_PKCS_V15, 0 );

    memset( message_str, 0x00, 1000 );
    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    ctx.len = mod / 8;
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_gcd( &G, &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
    TEST_ASSERT( mbedtls_mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );

    /* repeat three times to test updating of blinding values */
    for( i = 0; i < 3; i++ )
    {
        memset( output, 0x00, 1000 );
        memset( output_str, 0x00, 1000 );
        TEST_ASSERT( mbedtls_rsa_private( &ctx, rnd_pseudo_rand, &rnd_info,
                                  message_str, output ) == result );
        if( result == 0 )
        {
            hexify( output_str, output, ctx.len );

            TEST_ASSERT( strcasecmp( (char *) output_str,
                                              result_hex_str ) == 0 );
        }
    }

    /* And now one more time with the copy */
    TEST_ASSERT( mbedtls_rsa_copy( &ctx2, &ctx ) == 0 );
    /* clear the original to be sure */
    mbedtls_rsa_free( &ctx );

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx2 ) == 0 );

    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    TEST_ASSERT( mbedtls_rsa_private( &ctx2, rnd_pseudo_rand, &rnd_info,
                              message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx2.len );

        TEST_ASSERT( strcasecmp( (char *) output_str,
                                          result_hex_str ) == 0 );
    }

exit:
    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &H ); mbedtls_mpi_free( &G );
    mbedtls_rsa_free( &ctx ); mbedtls_rsa_free( &ctx2 );
}

void test_suite_rsa_check_privkey_null()
{
    mbedtls_rsa_context ctx;
    memset( &ctx, 0x00, sizeof( mbedtls_rsa_context ) );

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

exit:
    return;
}

void test_suite_mbedtls_rsa_check_pubkey( int radix_N, char *input_N, int radix_E, char *input_E,
                       int result )
{
    mbedtls_rsa_context ctx;

    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );

    if( strlen( input_N ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    }
    if( strlen( input_E ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );
    }

    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == result );

exit:
    mbedtls_rsa_free( &ctx );
}

void test_suite_mbedtls_rsa_check_privkey( int mod, int radix_P, char *input_P, int radix_Q,
                        char *input_Q, int radix_N, char *input_N,
                        int radix_E, char *input_E, int radix_D, char *input_D,
                        int radix_DP, char *input_DP, int radix_DQ,
                        char *input_DQ, int radix_QP, char *input_QP,
                        int result )
{
    mbedtls_rsa_context ctx;

    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );

    ctx.len = mod / 8;
    if( strlen( input_P ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.P, radix_P, input_P ) == 0 );
    }
    if( strlen( input_Q ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.Q, radix_Q, input_Q ) == 0 );
    }
    if( strlen( input_N ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    }
    if( strlen( input_E ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );
    }
    if( strlen( input_D ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.D, radix_D, input_D ) == 0 );
    }
    if( strlen( input_DP ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.DP, radix_DP, input_DP ) == 0 );
    }
    if( strlen( input_DQ ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.DQ, radix_DQ, input_DQ ) == 0 );
    }
    if( strlen( input_QP ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.QP, radix_QP, input_QP ) == 0 );
    }

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == result );

exit:
    mbedtls_rsa_free( &ctx );
}

void test_suite_rsa_check_pubpriv( int mod, int radix_Npub, char *input_Npub,
                        int radix_Epub, char *input_Epub,
                        int radix_P, char *input_P, int radix_Q,
                        char *input_Q, int radix_N, char *input_N,
                        int radix_E, char *input_E, int radix_D, char *input_D,
                        int radix_DP, char *input_DP, int radix_DQ,
                        char *input_DQ, int radix_QP, char *input_QP,
                        int result )
{
    mbedtls_rsa_context pub, prv;

    mbedtls_rsa_init( &pub, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_rsa_init( &prv, MBEDTLS_RSA_PKCS_V15, 0 );

    pub.len = mod / 8;
    prv.len = mod / 8;

    if( strlen( input_Npub ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &pub.N, radix_Npub, input_Npub ) == 0 );
    }
    if( strlen( input_Epub ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &pub.E, radix_Epub, input_Epub ) == 0 );
    }

    if( strlen( input_P ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.P, radix_P, input_P ) == 0 );
    }
    if( strlen( input_Q ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.Q, radix_Q, input_Q ) == 0 );
    }
    if( strlen( input_N ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.N, radix_N, input_N ) == 0 );
    }
    if( strlen( input_E ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.E, radix_E, input_E ) == 0 );
    }
    if( strlen( input_D ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.D, radix_D, input_D ) == 0 );
    }
    if( strlen( input_DP ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.DP, radix_DP, input_DP ) == 0 );
    }
    if( strlen( input_DQ ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.DQ, radix_DQ, input_DQ ) == 0 );
    }
    if( strlen( input_QP ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.QP, radix_QP, input_QP ) == 0 );
    }

    TEST_ASSERT( mbedtls_rsa_check_pub_priv( &pub, &prv ) == result );

exit:
    mbedtls_rsa_free( &pub );
    mbedtls_rsa_free( &prv );
}

#ifdef MBEDTLS_CTR_DRBG_C
#ifdef MBEDTLS_ENTROPY_C
void test_suite_mbedtls_rsa_gen_key( int nrbits, int exponent, int result)
{
    mbedtls_rsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "test_suite_rsa";

    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );
    TEST_ASSERT( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) pers, strlen( pers ) ) == 0 );

    mbedtls_rsa_init( &ctx, 0, 0 );

    TEST_ASSERT( mbedtls_rsa_gen_key( &ctx, mbedtls_ctr_drbg_random, &ctr_drbg, nrbits, exponent ) == result );
    if( result == 0 )
    {
        TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );
    }

exit:
    mbedtls_rsa_free( &ctx );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
}
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */

#ifdef MBEDTLS_SELF_TEST
void test_suite_rsa_selftest()
{
    TEST_ASSERT( mbedtls_rsa_self_test( 0 ) == 0 );

exit:
    return;
}
#endif /* MBEDTLS_SELF_TEST */


#endif /* defined(MBEDTLS_RSA_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */
#endif /* defined(MBEDTLS_GENPRIME) */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "MBEDTLS_MD5_C" ) == 0 )
    {
#if defined(MBEDTLS_MD5_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_MD4_C" ) == 0 )
    {
#if defined(MBEDTLS_MD4_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_SELF_TEST" ) == 0 )
    {
#if defined(MBEDTLS_SELF_TEST)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_SHA1_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA1_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_PKCS1_V15" ) == 0 )
    {
#if defined(MBEDTLS_PKCS1_V15)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_MD2_C" ) == 0 )
    {
#if defined(MBEDTLS_MD2_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_SHA512_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA512_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_SHA256_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA256_C)
        return( 0 );
#else
        return( 1 );
#endif
    }


    return( 1 );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    if( strcmp( params[0], "mbedtls_rsa_pkcs1_sign" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;
        char *param12 = params[12];
        char *param13 = params[13];
        int param14;

        if( cnt != 15 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 15 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );
        if( verify_string( &param10 ) != 0 ) return( 2 );
        if( verify_int( params[11], &param11 ) != 0 ) return( 2 );
        if( verify_string( &param12 ) != 0 ) return( 2 );
        if( verify_string( &param13 ) != 0 ) return( 2 );
        if( verify_int( params[14], &param14 ) != 0 ) return( 2 );

        test_suite_mbedtls_rsa_pkcs1_sign( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_pkcs1_verify" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        char *param9 = params[9];
        int param10;

        if( cnt != 11 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 11 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );

        test_suite_mbedtls_rsa_pkcs1_verify( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "rsa_pkcs1_sign_raw" ) == 0 )
    {

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;
        char *param12 = params[12];
        char *param13 = params[13];

        if( cnt != 14 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 14 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );
        if( verify_string( &param10 ) != 0 ) return( 2 );
        if( verify_int( params[11], &param11 ) != 0 ) return( 2 );
        if( verify_string( &param12 ) != 0 ) return( 2 );
        if( verify_string( &param13 ) != 0 ) return( 2 );

        test_suite_rsa_pkcs1_sign_raw( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "rsa_pkcs1_verify_raw" ) == 0 )
    {

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        char *param9 = params[9];
        int param10;

        if( cnt != 11 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 11 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );

        test_suite_rsa_pkcs1_verify_raw( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_pkcs1_encrypt" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;

        if( cnt != 10 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );

        test_suite_mbedtls_rsa_pkcs1_encrypt( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "rsa_pkcs1_encrypt_bad_rng" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;

        if( cnt != 10 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );

        test_suite_rsa_pkcs1_encrypt_bad_rng( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_pkcs1_decrypt" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;
        char *param9 = params[9];
        int param10;
        char *param11 = params[11];
        int param12;
        char *param13 = params[13];
        int param14;

        if( cnt != 15 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 15 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );
        if( verify_string( &param11 ) != 0 ) return( 2 );
        if( verify_int( params[12], &param12 ) != 0 ) return( 2 );
        if( verify_string( &param13 ) != 0 ) return( 2 );
        if( verify_int( params[14], &param14 ) != 0 ) return( 2 );

        test_suite_mbedtls_rsa_pkcs1_decrypt( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_public" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        char *param7 = params[7];
        int param8;

        if( cnt != 9 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 9 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );

        test_suite_mbedtls_rsa_public( param1, param2, param3, param4, param5, param6, param7, param8 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_private" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        char *param11 = params[11];
        int param12;

        if( cnt != 13 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 13 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );
        if( verify_string( &param10 ) != 0 ) return( 2 );
        if( verify_string( &param11 ) != 0 ) return( 2 );
        if( verify_int( params[12], &param12 ) != 0 ) return( 2 );

        test_suite_mbedtls_rsa_private( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "rsa_check_privkey_null" ) == 0 )
    {


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_rsa_check_privkey_null(  );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_check_pubkey" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );

        test_suite_mbedtls_rsa_check_pubkey( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_check_privkey" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;
        char *param9 = params[9];
        int param10;
        char *param11 = params[11];
        int param12;
        char *param13 = params[13];
        int param14;
        char *param15 = params[15];
        int param16;
        char *param17 = params[17];
        int param18;

        if( cnt != 19 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 19 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );
        if( verify_string( &param11 ) != 0 ) return( 2 );
        if( verify_int( params[12], &param12 ) != 0 ) return( 2 );
        if( verify_string( &param13 ) != 0 ) return( 2 );
        if( verify_int( params[14], &param14 ) != 0 ) return( 2 );
        if( verify_string( &param15 ) != 0 ) return( 2 );
        if( verify_int( params[16], &param16 ) != 0 ) return( 2 );
        if( verify_string( &param17 ) != 0 ) return( 2 );
        if( verify_int( params[18], &param18 ) != 0 ) return( 2 );

        test_suite_mbedtls_rsa_check_privkey( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14, param15, param16, param17, param18 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "rsa_check_pubpriv" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;
        char *param9 = params[9];
        int param10;
        char *param11 = params[11];
        int param12;
        char *param13 = params[13];
        int param14;
        char *param15 = params[15];
        int param16;
        char *param17 = params[17];
        int param18;
        char *param19 = params[19];
        int param20;
        char *param21 = params[21];
        int param22;

        if( cnt != 23 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 23 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );
        if( verify_string( &param11 ) != 0 ) return( 2 );
        if( verify_int( params[12], &param12 ) != 0 ) return( 2 );
        if( verify_string( &param13 ) != 0 ) return( 2 );
        if( verify_int( params[14], &param14 ) != 0 ) return( 2 );
        if( verify_string( &param15 ) != 0 ) return( 2 );
        if( verify_int( params[16], &param16 ) != 0 ) return( 2 );
        if( verify_string( &param17 ) != 0 ) return( 2 );
        if( verify_int( params[18], &param18 ) != 0 ) return( 2 );
        if( verify_string( &param19 ) != 0 ) return( 2 );
        if( verify_int( params[20], &param20 ) != 0 ) return( 2 );
        if( verify_string( &param21 ) != 0 ) return( 2 );
        if( verify_int( params[22], &param22 ) != 0 ) return( 2 );

        test_suite_rsa_check_pubpriv( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14, param15, param16, param17, param18, param19, param20, param21, param22 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_gen_key" ) == 0 )
    {
    #ifdef MBEDTLS_CTR_DRBG_C
    #ifdef MBEDTLS_ENTROPY_C

        int param1;
        int param2;
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_mbedtls_rsa_gen_key( param1, param2, param3 );
        return ( 0 );
    #endif /* MBEDTLS_CTR_DRBG_C */
    #endif /* MBEDTLS_ENTROPY_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "rsa_selftest" ) == 0 )
    {
    #ifdef MBEDTLS_SELF_TEST


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_rsa_selftest(  );
        return ( 0 );
    #endif /* MBEDTLS_SELF_TEST */

        return ( 3 );
    }
    else

    {
        mbedtls_fprintf( stdout, "FAILED\nSkipping unknown test function '%s'\n", params[0] );
        fflush( stdout );
        return( 1 );
    }
#else
    return( 3 );
#endif
    return( ret );
}

int get_line( FILE *f, char *buf, size_t len )
{
    char *ret;

    ret = fgets( buf, len, f );
    if( ret == NULL )
        return( -1 );

    if( strlen( buf ) && buf[strlen(buf) - 1] == '\n' )
        buf[strlen(buf) - 1] = '\0';
    if( strlen( buf ) && buf[strlen(buf) - 1] == '\r' )
        buf[strlen(buf) - 1] = '\0';

    return( 0 );
}

int parse_arguments( char *buf, size_t len, char *params[50] )
{
    int cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < buf + len )
    {
        if( *p == '\\' )
        {
            p++;
            p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    // Replace newlines, question marks and colons in strings
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *(p + 1) == 'n' )
            {
                p += 2;
                *(q++) = '\n';
            }
            else if( *p == '\\' && *(p + 1) == ':' )
            {
                p += 2;
                *(q++) = ':';
            }
            else if( *p == '\\' && *(p + 1) == '?' )
            {
                p += 2;
                *(q++) = '?';
            }
            else
                *(q++) = *(p++);
        }
        *q = '\0';
    }

    return( cnt );
}

static int test_snprintf( size_t n, const char ref_buf[10], int ref_ret )
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    ret = mbedtls_snprintf( buf, n, "%s", "123" );
    if( ret < 0 || (size_t) ret >= n )
        ret = -1;

    if( strncmp( ref_buf, buf, sizeof( buf ) ) != 0 ||
        ref_ret != ret ||
        memcmp( buf + n, ref + n, sizeof( buf ) - n ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

static int run_test_snprintf( void )
{
    return( test_snprintf( 0, "xxxxxxxxx",  -1 ) != 0 ||
            test_snprintf( 1, "",           -1 ) != 0 ||
            test_snprintf( 2, "1",          -1 ) != 0 ||
            test_snprintf( 3, "12",         -1 ) != 0 ||
            test_snprintf( 4, "123",         3 ) != 0 ||
            test_snprintf( 5, "123",         3 ) != 0 );
}

int main()
{
    int ret, i, cnt, total_errors = 0, total_tests = 0, total_skipped = 0;
    const char *filename = "suites/test_suite_rsa.data";
    FILE *file;
    char buf[5000];
    char *params[50];
    void *pointer;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_fprintf( stderr, "all-bits-zero is not a NULL pointer\n" );
        return( 1 );
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if( run_test_snprintf() != 0 )
    {
        mbedtls_fprintf( stderr, "the snprintf implementation is broken\n" );
        return( 0 );
    }

    file = fopen( filename, "r" );
    if( file == NULL )
    {
        mbedtls_fprintf( stderr, "Failed to open\n" );
        return( 1 );
    }

    while( !feof( file ) )
    {
        int skip = 0;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        mbedtls_fprintf( stdout, "%s%.66s", test_errors ? "\n" : "", buf );
        mbedtls_fprintf( stdout, " " );
        for( i = strlen( buf ) + 1; i < 67; i++ )
            mbedtls_fprintf( stdout, "." );
        mbedtls_fprintf( stdout, " " );
        fflush( stdout );

        total_tests++;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        cnt = parse_arguments( buf, strlen(buf), params );

        if( strcmp( params[0], "depends_on" ) == 0 )
        {
            for( i = 1; i < cnt; i++ )
                if( dep_check( params[i] ) != 0 )
                    skip = 1;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen(buf), params );
        }

        if( skip == 0 )
        {
            test_errors = 0;
            ret = dispatch_test( cnt, params );
        }

        if( skip == 1 || ret == 3 )
        {
            total_skipped++;
            mbedtls_fprintf( stdout, "----\n" );
            fflush( stdout );
        }
        else if( ret == 0 && test_errors == 0 )
        {
            mbedtls_fprintf( stdout, "PASS\n" );
            fflush( stdout );
        }
        else if( ret == 2 )
        {
            mbedtls_fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
            fclose(file);
            mbedtls_exit( 2 );
        }
        else
            total_errors++;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        if( strlen(buf) != 0 )
        {
            mbedtls_fprintf( stderr, "Should be empty %d\n", (int) strlen(buf) );
            return( 1 );
        }
    }
    fclose(file);

    mbedtls_fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        mbedtls_fprintf( stdout, "PASSED" );
    else
        mbedtls_fprintf( stdout, "FAILED" );

    mbedtls_fprintf( stdout, " (%d / %d tests (%d skipped))\n",
             total_tests - total_errors, total_tests, total_skipped );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

    return( total_errors != 0 );
}


