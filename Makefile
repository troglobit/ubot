# ubot - very small and stupid irc bot
#
# Copyright (c) 2015  Joachim Nilsson <troglobit@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

.PHONY: all install uninstall clean distclean dist

VERSION    ?= 0.1
EXEC        = ubot
OBJS        = ubot.o
DEPS        = $(OBJS:.o=.d)
CFLAGS     += -O2 -W -Wall -g
CPPFLAGS   += -D_GNU_SOURCE -DVERSION='"$(VERSION)"'
LDLIBS     += -lssl -lcrypto
TOPDIR      = $(shell pwd)
ROOTDIR    ?= $(TOPDIR)
JUNK        = *~ *.bak *.map *.d *.o DEADJOE *.gdb *.elf core core.*

# Pretty printing and GCC -M for auto dep files
%.o: %.c
	@printf "  CC      $(subst $(ROOTDIR)/,,$(shell pwd)/$@)\n"
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c -MMD -MP -o $@ $<

# Pretty printing and create .map files
%: %.o
	@printf "  LINK    $(subst $(ROOTDIR)/,,$(shell pwd)/$@)\n"
	@$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-Map,$@.map -o $@ $^ $(LDLIBS$(LDLIBS-$(@)))

all: $(EXEC)

$(EXEC): $(OBJS)

clean:
	-@$(RM) $(OBJS) $(EXEC)

distclean: clean
	-@$(RM) $(JUNK)

-include $(DEPS)
