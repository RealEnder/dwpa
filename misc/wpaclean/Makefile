AC_ROOT		= .
include $(AC_ROOT)/common.mak

TEST_DIR	= $(AC_ROOT)/test

CFLAGS		+= -Iinclude

iCC             = $(shell find /opt/intel/cc/*/bin/icc)
iCFLAGS         = -w -mcpu=pentiumpro -march=pentiumpro $(COMMON_CFLAGS)
iOPTFLAGS       = -O3 -ip -ipo -D_FILE_OFFSET_BITS=64

BINFILES        = wpaclean$(EXE)

ifneq ($(OSNAME), Linux)
	OBJS_ADU	+= osdep/common.o
endif
OBJS_WC		= wpaclean.o osdep/radiotap/radiotap.o

OSD		= osdep
LIBS		:= -L$(OSD) -l$(OSD) $(LIBS)
ifeq ($(OSNAME), cygwin)
LIBS		+= -liphlpapi -lsetupapi -luuid
endif
LIBOSD		= $(OSD)/lib$(OSD).a

LIBSSL		= -lssl -lcrypto

all: userland $(SBINFILES)

userland: $(BINFILES)

$(LIBOSD):
	$(MAKE) -C $(OSD)

wpaclean$(EXE): $(OBJS_WC) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_WC) -o $(@) $(LIBS)

strip: $(BINFILES) $(SBINFILES)
	strip $(BINFILES) $(SBINFILES)

clean:
	$(MAKE) -C $(OSD) clean
	-rm -f $(SBINFILES) $(BINFILES) $(OPTFILES) wpaclean$(EXE) *.o a.out

distclean: clean

install: all
	$(MAKE) -C $(OSD) install
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(BINFILES) $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(sbindir)
	install -m 755 $(SBINFILES) $(DESTDIR)$(sbindir)

uninstall:
	$(MAKE) -C $(OSD) uninstall
	-rm -f $(DESTDIR)$(bindir)/wpaclean$(EXE)
