#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/basic_functions.h"
#include "skein.h"
#include "php_skein.h"

#define SKEIN_DEFAULT_BITS_LENGTH 512

zend_function_entry skein_functions[] = {
	PHP_FE(skein_hash, NULL)
	PHP_FE(skein_hash_hex, NULL)    
#ifdef PHP_FE_END
	PHP_FE_END
#else
	{ NULL, NULL, NULL }
#endif
};

zend_module_entry skein_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"skein",
	skein_functions,
	PHP_MINIT(skein),
	PHP_MSHUTDOWN(skein),
	NULL,
	NULL,
	PHP_MINFO(skein),
#if ZEND_MODULE_API_NO >= 20010901
	"1.1",
#endif
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SKEIN
ZEND_GET_MODULE(skein)
#endif

PHP_MINIT_FUNCTION(skein)
{
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(skein)
{
	return SUCCESS;
}

PHP_MINFO_FUNCTION(skein)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "skein hash support", "enabled");
	php_info_print_table_end();
}

static int skein256_hash_buffer(unsigned char hash[32],
                                const size_t sizeof_hash,
                                const unsigned char *buf,
                                const size_t buf_size,
                                const size_t hash_bitlen)
{
    Skein_256_Ctxt_t ctx;
    
    if (sizeof_hash < 32U) {
        return -1;
    }
    memset(hash, 0, 32U);
    Skein_256_Init(&ctx, hash_bitlen);
    Skein_256_Update(&ctx, (const u08b_t *) buf, buf_size);
    Skein_256_Final(&ctx, hash);
    
    return 0;
}

static int skein512_hash_buffer(unsigned char hash[64],
                                const size_t sizeof_hash,
                                const unsigned char *buf,
                                const size_t buf_size,
                                const size_t hash_bitlen)
{
    Skein_512_Ctxt_t ctx;
    
    if (sizeof_hash < 64U) {
        return -1;
    }
    memset(hash, 0, 64U);
    Skein_512_Init(&ctx, hash_bitlen);
    Skein_512_Update(&ctx, (const u08b_t *) buf, buf_size);
    Skein_512_Final(&ctx, hash);
    
    return 0;
}

static int skein1024_hash_buffer(unsigned char hash[128],
                                 const size_t sizeof_hash,
                                 const unsigned char *buf,
                                 const size_t buf_size,
                                 const size_t hash_bitlen)
{
    Skein1024_Ctxt_t ctx;
    
    if (sizeof_hash < 128U) {
        return -1;
    }
    memset(hash, 0, 128U);
    Skein1024_Init(&ctx, hash_bitlen);
    Skein1024_Update(&ctx, (const u08b_t *) buf, buf_size);
    Skein1024_Final(&ctx, hash);

    return 0;
}

static int skein_hash_buffer(unsigned char * const hash,
                             const size_t sizeof_hash,
                             const unsigned char *buf,
                             const size_t buf_size,
                             const size_t hash_bitlen)
{
    if (hash_bitlen <= 256) {
        return skein256_hash_buffer(hash, sizeof_hash, buf, buf_size,
                                    hash_bitlen);
    } else if (hash_bitlen <= 512) {
        return skein512_hash_buffer(hash, sizeof_hash, buf, buf_size,
                                    hash_bitlen);
    }
    return skein1024_hash_buffer(hash, sizeof_hash,
                                 buf, buf_size, hash_bitlen);
}

PHP_FUNCTION(skein_hash)
{
    char hash[128];
	char *buf = NULL;
	int buf_size;
	long hash_bitlen = SKEIN_DEFAULT_BITS_LENGTH;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
                              &buf, &buf_size, &hash_bitlen) == FAILURE) {
		return;
	}
    if (hash_bitlen < 1 || hash_bitlen > 1024) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Bad bit length");
        RETURN_FALSE;        
    }
    if (skein_hash_buffer(hash, sizeof hash, buf, buf_size,
                          (size_t) hash_bitlen) != 0) {
        RETURN_FALSE;
    }    
    RETURN_STRINGL(hash, ceil(hash_bitlen / 8), 1);
}

PHP_FUNCTION(skein_hash_hex)
{
	static const char hexits[] = "0123456789abcdef";
    char hash[128];    
	char res[256];
	char *resptr = res;
	char *buf = NULL;
	int buf_size;
    size_t j = 0U;
    size_t real_hash_size;
	long hash_bitlen = SKEIN_DEFAULT_BITS_LENGTH;
    
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
                              &buf, &buf_size, &hash_bitlen) == FAILURE) {
		return;
	}
    if (hash_bitlen < 1 || hash_bitlen > 1024) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Bad bit length");
        RETURN_FALSE;        
    }
    if (skein_hash_buffer(hash, sizeof hash, buf, buf_size,
                          (size_t) hash_bitlen) != 0) {
        RETURN_FALSE;
    }
    real_hash_size = ceil(hash_bitlen / 8);
    if (real_hash_size > sizeof hash) {
        abort();
    }
    do {
        *resptr++ = hexits[(hash[j] & 0xf0) >> 4];
        *resptr++ = hexits[hash[j] & 0x0f];
    } while (++j < real_hash_size);
    *resptr = 0;

	RETURN_STRINGL(res, (size_t) (resptr - res), 1);
}
