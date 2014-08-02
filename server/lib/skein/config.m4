PHP_ARG_ENABLE(skein, whether to enable skein support,
[  --enable-skein          Enable skein support])

if test "$PHP_SKEIN" != "no"; then
  PHP_NEW_EXTENSION(skein, php_skein.c skein.c skein_block.c, $ext_shared)
fi
