lcsam
=====

lcsam (LiveConfig SpamAssassin Milter) is a milter (Sendmail filter) service to check incoming e-mails with SpamAssassin and optionally tag or reject them.

## Why another SpamAssassin Milter?

We've searched a while for a tool to filter incoming mails through SpamAssassin which meets the following conditions:
* works with [Postfix](http://www.postfix.org/)
* allows per-user thresholds and actions
* works *without* a MySQL database
* allows [rejection at SMTP time](http://www.postfix.org/MILTER_README.html) (to avoid [backscatter](http://en.wikipedia.org/wiki/Backscatter_%28email%29))
* no script language please (no additional runtime requirements)

There are [numerous tools](http://wiki.apache.org/spamassassin/IntegratedInMta) available - however, none of these matched our requirements. Either they are written in Perl, they store their user configuration in MySQL, ot they don't even allow per-user thresholds.

## What's cool about *lcsam*?

*lcsam* is based on the program flow and some ideas of Daniel Hartmeiers excellent [milter-spamd](http://www.benzedrine.cx/milter-spamd.html), but is completely rewritten from scratch.
We've focussed on **security** and **reliability** since the very first line of code. We do
* **static code analysis** with [PC-lint](http://www.gimpel.com/html/pcl.htm) (the propably most sophisticated tool ever!) and [clang](http://clang-analyzer.llvm.org/)
* **runtime analysis** with [Valgrind](http://valgrind.org) (amongst others)
* **unit tests** with [Check](http://check.sourceforge.net/)
* **publish the source** as *lcsam* is also available under an open-source license (GPLv2)

## Copyright

Copyright (c) 2014 Keppler IT GmbH. All rights reserved.

See LICENSE file for detailed license informations.
