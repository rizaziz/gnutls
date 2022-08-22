#!/bin/sh

# Test in the POSIX locale.
LC_ALL=C     ${CHECKER} ./test-c32islower${EXEEXT} 0 || exit 1
LC_ALL=POSIX ${CHECKER} ./test-c32islower${EXEEXT} 0 || exit 1

# Test in an ISO-8859-1 or ISO-8859-15 locale.
: ${LOCALE_FR=fr_FR}
if test $LOCALE_FR != none; then
  LC_ALL=$LOCALE_FR \
  ${CHECKER} ./test-c32islower${EXEEXT} 1 \
  || exit 1
fi

# Test whether a specific EUC-JP locale is installed.
: ${LOCALE_JA=ja_JP}
if test $LOCALE_JA != none; then
  LC_ALL=$LOCALE_JA \
  ${CHECKER} ./test-c32islower${EXEEXT} 2 \
  || exit 1
fi

# Test whether a specific UTF-8 locale is installed.
: ${LOCALE_FR_UTF8=fr_FR.UTF-8}
if test $LOCALE_FR_UTF8 != none; then
  LC_ALL=$LOCALE_FR_UTF8 \
  ${CHECKER} ./test-c32islower${EXEEXT} 3 \
  || exit 1
fi

# Test whether a specific GB18030 locale is installed.
: ${LOCALE_ZH_CN=zh_CN.GB18030}
if test $LOCALE_ZH_CN != none; then
  LC_ALL=$LOCALE_ZH_CN \
  ${CHECKER} ./test-c32islower${EXEEXT} 4 \
  || exit 1
fi

exit 0
