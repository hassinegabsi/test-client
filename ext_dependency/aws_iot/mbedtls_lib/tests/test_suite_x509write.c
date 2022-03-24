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


#if defined(MBEDTLS_BIGNUM_C)
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_PK_PARSE_C)

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/pem.h"
#include "mbedtls/oid.h"
#endif /* defined(MBEDTLS_BIGNUM_C) */
#endif /* defined(MBEDTLS_FS_IO) */
#endif /* defined(MBEDTLS_PK_PARSE_C) */


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

#if defined(MBEDTLS_BIGNUM_C)
#if defined(MBEDTLS_FS_IO)
#if defined(MBEDTLS_PK_PARSE_C)

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

#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_MD_MD5" ) == 0 )
    {
        *value = ( MBEDTLS_MD_MD5 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_KEY_ENCIPHERMENT" ) == 0 )
    {
        *value = ( MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_KEY_ENCIPHERMENT );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CRT_WRITE_C
#ifdef MBEDTLS_SHA1_C
    if( strcmp( str, "MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_KEY_ENCIPHERMENT" ) == 0 )
    {
        *value = ( MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_KEY_ENCIPHERMENT );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CRT_WRITE_C
#endif // MBEDTLS_SHA1_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CRT_WRITE_C
#ifdef MBEDTLS_SHA1_C
    if( strcmp( str, "MBEDTLS_X509_CRT_VERSION_1" ) == 0 )
    {
        *value = ( MBEDTLS_X509_CRT_VERSION_1 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CRT_WRITE_C
#endif // MBEDTLS_SHA1_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CRT_WRITE_C
#ifdef MBEDTLS_SHA1_C
    if( strcmp( str, "MBEDTLS_MD_SHA1" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA1 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CRT_WRITE_C
#endif // MBEDTLS_SHA1_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_MD_SHA1" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA1 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CRT_WRITE_C
#ifdef MBEDTLS_SHA1_C
    if( strcmp( str, "MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER" ) == 0 )
    {
        *value = ( MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CRT_WRITE_C
#endif // MBEDTLS_SHA1_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER" ) == 0 )
    {
        *value = ( MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_MD_SHA384" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA384 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_MD_SHA224" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA224 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CRT_WRITE_C
#ifdef MBEDTLS_SHA1_C
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CRT_WRITE_C
#endif // MBEDTLS_SHA1_C
#ifdef MBEDTLS_X509_CREATE_C
#ifdef MBEDTLS_X509_USE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_UNKNOWN_OID" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_UNKNOWN_OID );
        return( 0 );
    }
#endif // MBEDTLS_X509_CREATE_C
#endif // MBEDTLS_X509_USE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_MD_MD4" ) == 0 )
    {
        *value = ( MBEDTLS_MD_MD4 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_MD_SHA256" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA256 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_NON_REPUDIATION" ) == 0 )
    {
        *value = ( MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_NON_REPUDIATION );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
    if( strcmp( str, "MBEDTLS_MD_SHA512" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA512 );
        return( 0 );
    }
#endif // MBEDTLS_PEM_WRITE_C
#endif // MBEDTLS_X509_CSR_WRITE_C
#ifdef MBEDTLS_X509_CREATE_C
#ifdef MBEDTLS_X509_USE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_NAME" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_NAME );
        return( 0 );
    }
#endif // MBEDTLS_X509_CREATE_C
#endif // MBEDTLS_X509_USE_C


    mbedtls_printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CSR_WRITE_C
void test_suite_x509_csr_check( char *key_file, char *cert_req_check_file,
                     int md_type, int key_usage, int cert_type )
{
    mbedtls_pk_context key;
    mbedtls_x509write_csr req;
    unsigned char buf[4000];
    unsigned char check_buf[4000];
    int ret;
    size_t olen = 0, pem_len = 0;
    FILE *f;
    const char *subject_name = "C=NL,O=PolarSSL,CN=PolarSSL Server 1";
    rnd_pseudo_info rnd_info;

    memset( &rnd_info, 0x2a, sizeof( rnd_pseudo_info ) );

    mbedtls_pk_init( &key );
    TEST_ASSERT( mbedtls_pk_parse_keyfile( &key, key_file, NULL ) == 0 );

    mbedtls_x509write_csr_init( &req );
    mbedtls_x509write_csr_set_md_alg( &req, md_type );
    mbedtls_x509write_csr_set_key( &req, &key );
    TEST_ASSERT( mbedtls_x509write_csr_set_subject_name( &req, subject_name ) == 0 );
    if( key_usage != 0 )
        TEST_ASSERT( mbedtls_x509write_csr_set_key_usage( &req, key_usage ) == 0 );
    if( cert_type != 0 )
        TEST_ASSERT( mbedtls_x509write_csr_set_ns_cert_type( &req, cert_type ) == 0 );

    ret = mbedtls_x509write_csr_pem( &req, buf, sizeof(buf),
                             rnd_pseudo_rand, &rnd_info );
    TEST_ASSERT( ret == 0 );

    pem_len = strlen( (char *) buf );

    f = fopen( cert_req_check_file, "r" );
    TEST_ASSERT( f != NULL );
    olen = fread( check_buf, 1, sizeof( check_buf ), f );
    fclose( f );

    TEST_ASSERT( olen >= pem_len - 1 );
    TEST_ASSERT( memcmp( buf, check_buf, pem_len - 1 ) == 0 );

exit:
    mbedtls_x509write_csr_free( &req );
    mbedtls_pk_free( &key );
}
#endif /* MBEDTLS_PEM_WRITE_C */
#endif /* MBEDTLS_X509_CSR_WRITE_C */

#ifdef MBEDTLS_PEM_WRITE_C
#ifdef MBEDTLS_X509_CRT_WRITE_C
#ifdef MBEDTLS_SHA1_C
void test_suite_x509_crt_check( char *subject_key_file, char *subject_pwd,
                     char *subject_name, char *issuer_key_file,
                     char *issuer_pwd, char *issuer_name,
                     char *serial_str, char *not_before, char *not_after,
                     int md_type, int key_usage, int cert_type, int ver,
                     char *cert_check_file )
{
    mbedtls_pk_context subject_key, issuer_key;
    mbedtls_x509write_cert crt;
    unsigned char buf[4000];
    unsigned char check_buf[5000];
    mbedtls_mpi serial;
    int ret;
    size_t olen = 0, pem_len = 0;
    FILE *f;
    rnd_pseudo_info rnd_info;

    memset( &rnd_info, 0x2a, sizeof( rnd_pseudo_info ) );
    mbedtls_mpi_init( &serial );
    mbedtls_pk_init( &subject_key );
    mbedtls_pk_init( &issuer_key );

    TEST_ASSERT( mbedtls_pk_parse_keyfile( &subject_key, subject_key_file,
                                         subject_pwd ) == 0 );
    TEST_ASSERT( mbedtls_pk_parse_keyfile( &issuer_key, issuer_key_file,
                                         issuer_pwd ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &serial, 10, serial_str ) == 0 );

    mbedtls_x509write_crt_init( &crt );
    if( ver != -1 )
        mbedtls_x509write_crt_set_version( &crt, ver );
    TEST_ASSERT( mbedtls_x509write_crt_set_serial( &crt, &serial ) == 0 );
    TEST_ASSERT( mbedtls_x509write_crt_set_validity( &crt, not_before,
                                                   not_after ) == 0 );
    mbedtls_x509write_crt_set_md_alg( &crt, md_type );
    TEST_ASSERT( mbedtls_x509write_crt_set_issuer_name( &crt, issuer_name ) == 0 );
    TEST_ASSERT( mbedtls_x509write_crt_set_subject_name( &crt, subject_name ) == 0 );
    mbedtls_x509write_crt_set_subject_key( &crt, &subject_key );
    mbedtls_x509write_crt_set_issuer_key( &crt, &issuer_key );

    if( crt.version >= MBEDTLS_X509_CRT_VERSION_3 )
    {
        TEST_ASSERT( mbedtls_x509write_crt_set_basic_constraints( &crt, 0, 0 ) == 0 );
        TEST_ASSERT( mbedtls_x509write_crt_set_subject_key_identifier( &crt ) == 0 );
        TEST_ASSERT( mbedtls_x509write_crt_set_authority_key_identifier( &crt ) == 0 );
        if( key_usage != 0 )
            TEST_ASSERT( mbedtls_x509write_crt_set_key_usage( &crt, key_usage ) == 0 );
        if( cert_type != 0 )
            TEST_ASSERT( mbedtls_x509write_crt_set_ns_cert_type( &crt, cert_type ) == 0 );
    }

    ret = mbedtls_x509write_crt_pem( &crt, buf, sizeof(buf),
                             rnd_pseudo_rand, &rnd_info );
    TEST_ASSERT( ret == 0 );

    pem_len = strlen( (char *) buf );

    f = fopen( cert_check_file, "r" );
    TEST_ASSERT( f != NULL );
    olen = fread( check_buf, 1, sizeof(check_buf), f );
    fclose( f );
    TEST_ASSERT( olen < sizeof(check_buf) );

    TEST_ASSERT( olen >= pem_len - 1 );
    TEST_ASSERT( memcmp( buf, check_buf, pem_len - 1 ) == 0 );

exit:
    mbedtls_x509write_crt_free( &crt );
    mbedtls_pk_free( &issuer_key );
    mbedtls_pk_free( &subject_key );
    mbedtls_mpi_free( &serial );
}
#endif /* MBEDTLS_PEM_WRITE_C */
#endif /* MBEDTLS_X509_CRT_WRITE_C */
#endif /* MBEDTLS_SHA1_C */

#ifdef MBEDTLS_X509_CREATE_C
#ifdef MBEDTLS_X509_USE_C
void test_suite_mbedtls_x509_string_to_names( char *name, char *parsed_name, int result )
{
    int ret;
    size_t len = 0;
    mbedtls_asn1_named_data *names = NULL;
    mbedtls_x509_name parsed, *parsed_cur, *parsed_prv;
    unsigned char buf[1024], out[1024], *c;

    memset( &parsed, 0, sizeof( parsed ) );
    memset( out, 0, sizeof( out ) );
    memset( buf, 0, sizeof( buf ) );
    c = buf + sizeof( buf );

    ret = mbedtls_x509_string_to_names( &names, name );
    TEST_ASSERT( ret == result );

    if( ret != 0 )
        goto exit;

    ret = mbedtls_x509_write_names( &c, buf, names );
    TEST_ASSERT( ret > 0 );

    TEST_ASSERT( mbedtls_asn1_get_tag( &c, buf + sizeof( buf ), &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) == 0 );
    TEST_ASSERT( mbedtls_x509_get_name( &c, buf + sizeof( buf ), &parsed ) == 0 );

    ret = mbedtls_x509_dn_gets( (char *) out, sizeof( out ), &parsed );
    TEST_ASSERT( ret > 0 );

    TEST_ASSERT( strcmp( (char *) out, parsed_name ) == 0 );

exit:
    mbedtls_asn1_free_named_data_list( &names );

    parsed_cur = parsed.next;
    while( parsed_cur != 0 )
    {
        parsed_prv = parsed_cur;
        parsed_cur = parsed_cur->next;
        mbedtls_free( parsed_prv );
    }
}
#endif /* MBEDTLS_X509_CREATE_C */
#endif /* MBEDTLS_X509_USE_C */


#endif /* defined(MBEDTLS_BIGNUM_C) */
#endif /* defined(MBEDTLS_FS_IO) */
#endif /* defined(MBEDTLS_PK_PARSE_C) */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "MBEDTLS_SHA512_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA512_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_DES_C" ) == 0 )
    {
#if defined(MBEDTLS_DES_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_CIPHER_MODE_CBC" ) == 0 )
    {
#if defined(MBEDTLS_CIPHER_MODE_CBC)
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
    if( strcmp( str, "MBEDTLS_SHA1_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA1_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_ECDSA_C" ) == 0 )
    {
#if defined(MBEDTLS_ECDSA_C)
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
    if( strcmp( str, "MBEDTLS_ECP_DP_SECP256R1_ENABLED" ) == 0 )
    {
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
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
    if( strcmp( str, "MBEDTLS_MD5_C" ) == 0 )
    {
#if defined(MBEDTLS_MD5_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_RSA_C" ) == 0 )
    {
#if defined(MBEDTLS_RSA_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "MBEDTLS_ECDSA_DETERMINISTIC" ) == 0 )
    {
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
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
    if( strcmp( params[0], "x509_csr_check" ) == 0 )
    {
    #ifdef MBEDTLS_PEM_WRITE_C
    #ifdef MBEDTLS_X509_CSR_WRITE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );

        test_suite_x509_csr_check( param1, param2, param3, param4, param5 );
        return ( 0 );
    #endif /* MBEDTLS_PEM_WRITE_C */
    #endif /* MBEDTLS_X509_CSR_WRITE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_crt_check" ) == 0 )
    {
    #ifdef MBEDTLS_PEM_WRITE_C
    #ifdef MBEDTLS_X509_CRT_WRITE_C
    #ifdef MBEDTLS_SHA1_C

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];
        char *param7 = params[7];
        char *param8 = params[8];
        char *param9 = params[9];
        int param10;
        int param11;
        int param12;
        int param13;
        char *param14 = params[14];

        if( cnt != 15 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 15 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );
        if( verify_int( params[11], &param11 ) != 0 ) return( 2 );
        if( verify_int( params[12], &param12 ) != 0 ) return( 2 );
        if( verify_int( params[13], &param13 ) != 0 ) return( 2 );
        if( verify_string( &param14 ) != 0 ) return( 2 );

        test_suite_x509_crt_check( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14 );
        return ( 0 );
    #endif /* MBEDTLS_PEM_WRITE_C */
    #endif /* MBEDTLS_X509_CRT_WRITE_C */
    #endif /* MBEDTLS_SHA1_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_string_to_names" ) == 0 )
    {
    #ifdef MBEDTLS_X509_CREATE_C
    #ifdef MBEDTLS_X509_USE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_mbedtls_x509_string_to_names( param1, param2, param3 );
        return ( 0 );
    #endif /* MBEDTLS_X509_CREATE_C */
    #endif /* MBEDTLS_X509_USE_C */

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
    const char *filename = "suites/test_suite_x509write.data";
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


