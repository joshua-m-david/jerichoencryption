#ifndef PHP_SKEIN_H
# define PHP_SKEIN_H

extern zend_module_entry skein_module_entry;
# define phpext_skein_ptr &skein_module_entry

# ifdef PHP_WIN32
#  define PHP_SKEIN_API __declspec(dllexport)
# else
#  define PHP_SKEIN_API
# endif

# ifdef ZTS
#  include "TSRM.h"
# endif

PHP_MINIT_FUNCTION(skein);
PHP_MSHUTDOWN_FUNCTION(skein);
PHP_RINIT_FUNCTION(skein);
PHP_RSHUTDOWN_FUNCTION(skein);
PHP_MINFO_FUNCTION(skein);

PHP_FUNCTION(skein_hash);
PHP_FUNCTION(skein_hash_hex);

# ifdef ZTS
#  define SKEIN_G(v) TSRMG(skein_globals_id, zend_skein_globals *, v)
# else
#  define SKEIN_G(v) (skein_globals.v)
# endif

#endif
