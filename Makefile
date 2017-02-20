#  _    _          ___           __ _     (R)
# | |  (_)_ _____ / __|___ _ _  / _(_)__ _
# | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
# |____|_|\_/\___|\___\___/_||_|_| |_\__, |
#                                    |___/
# lcsam - LiveConfig SpamAssassin Milter

# Include common Makefile settings if existing...
ifeq (../Makefile.common,$(wildcard ../Makefile.common))
include ../Makefile.common
CPPFLAGS += -DBDB_H=\"$(BDB_H)\"
else
CHECKLIB = -lcheck
endif

CFLAGS	= -g -Wall -Werror -O3
LIBS	= -pthread
LDFLAGS	= -L/usr/lib/libmilter
OBJECTS	= args.o lcsam.o log.o lookup.o pid.o safety.o

# Berkeley DB
ifdef LIB_BDB
LIBS   += $(LIB_BDB)
else
LIBS   += -ldb
endif

# Milter
ifdef LIB_MILTER
LIBS   += $(LIB_MILTER)
else
LIBS   += -lmilter
endif

all: lcsam

# Dependencies
args.o: args.c args.h
lcsam.o: lcsam.c args.h log.h lookup.h pid.h safety.h
log.o: log.c lcsam.h args.h log.h
lookup.o: lookup.c lcsam.h args.h log.h lookup.h
pid.o: pid.c lcsam.h log.h pid.h
safety.o: safety.c lcsam.h args.h log.h safety.h

.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -o $@ $<

%.1: %.1.pod
	pod2man --section=1 --center="LiveConfig Utilities" $< >$@

lcsam: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f $(OBJECTS) lcsam test_lcsam

distclean: clean
	chmod a-x *.c *.h lcsam.1 lcsam.1.pod Makefile README.md

tests: test_lcsam

test_lcsam: test_lcsam.c args.o lookup.o log.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS) $(LIBS) $(CHECKLIB) -lm -lrt

lint:
	gcclint $(OBJECTS:%.o=%.c)

valgrind: lcsam
	valgrind --tool=memcheck --track-fds=yes --leak-check=full --leak-resolution=high --time-stamp=no --read-var-info=yes --track-origins=yes \
		--num-callers=36 --show-reachable=yes --log-file=lcsam.log \
		./lcsam -d -u spamd -U postfix
