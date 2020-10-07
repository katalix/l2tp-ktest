SRCDIR		:= src
INCDIR		:= inc
OBJDIR		:= src/.obj
DEPDIR		:= .d
TARGETS		:=
CLEANFILES  := l2tp-ktest.tgz tags $(OBJDIR) $(SRCDIR)/syzbot/syzbot.mk $(DEPDIR)
SRCS		:=

MY_CFLAGS   := $(CFLAGS) -I/usr/include/libnl3 -Wall -Werror -g -ggdb
DEPFLAGS	:= -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMMON_SOURCES 	:= $(SRCDIR)/l2tp_netlink.c
COMMON_SOURCES 	+= $(SRCDIR)/util.c $(SRCDIR)/util_ppp_2.c
COMMON_LIBS	:= nl-genl-3 nl-3 pthread

OPT_NO_SYZBOT_APPS := 0

$(shell mkdir -p $(DEPDIR) > /dev/null)
$(shell $(SRCDIR)/syzbot/bootstrap.sh > $(SRCDIR)/syzbot/syzbot.mk)

.PHONY: all default
default: all

# Macro for building an application
# $1 -- target binary name
# Expects <target name>_SRCS and <target name>_LIBS to be defined
define buildapp
TARGETS += $(1)
CLEANFILES += $(1)
SRCS += $($(1)_SRCS)
$(1) : $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$($(1)_SRCS))
	$(CC) $$^ -o $$@ $(patsubst %,-l%,$($(1)_LIBS))
endef

# tunl_query_race
tunl_query_race_SRCS := $(SRCDIR)/tunl_query_race.c $(COMMON_SOURCES)
tunl_query_race_LIBS := $(COMMON_LIBS)
$(eval $(call buildapp,tunl_query_race))

# tunl_delete_race
tunl_delete_race_SRCS := $(SRCDIR)/tunl_delete_race.c $(COMMON_SOURCES)
tunl_delete_race_LIBS := $(COMMON_LIBS)
$(eval $(call buildapp,tunl_delete_race))

# kcreate
kcreate_SRCS := $(SRCDIR)/kcreate.c $(COMMON_SOURCES)
kcreate_LIBS := $(COMMON_LIBS)
$(eval $(call buildapp,kcreate))

# sess_dataif
sess_dataif_SRCS := $(SRCDIR)/sess_dataif.c $(COMMON_SOURCES)
sess_dataif_LIBS := $(COMMON_LIBS)
$(eval $(call buildapp,sess_dataif))

# seqnum
seqnum_SRCS := $(SRCDIR)/seqnum.c $(COMMON_SOURCES)
seqnum_LIBS := $(COMMON_LIBS)
$(eval $(call buildapp,seqnum))

# pppoe_sess_pkt
pppoe_sess_pkt_SRCS := $(SRCDIR)/pppoe_sess_pkt.c $(COMMON_SOURCES)
pppoe_sess_pkt_LIBS := $(COMMON_LIBS)
$(eval $(call buildapp,pppoe_sess_pkt))

# getstats
getstats_SRCS := $(SRCDIR)/getstats.c $(COMMON_SOURCES)
getstats_LIBS := $(COMMON_LIBS)
$(eval $(call buildapp,getstats))

# syzbot reproducers
ifeq ($(OPT_NO_SYZBOT_APPS),0)
include $(SRCDIR)/syzbot/syzbot.mk
endif

all: $(TARGETS) l2tp-ktest.tgz

$(OBJDIR)/.created:
	mkdir -p $(OBJDIR)
	touch $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(OBJDIR)/.created $(DEPDIR)/%.d
	$(CC) -I$(INCDIR) -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td $(MY_CFLAGS) -c $< -o $@
	@mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d

$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

.PHONY: clean
clean:
	@rm -rf $(CLEANFILES)

.PHONY: tags
tags:
	ctags -Rb

.PHONY: tarball
tarball: l2tp-ktest.tgz

l2tp-ktest.tgz: $(TARGETS) l2tp_ktest
	tar -czf $@ $^

include $(wildcard $(patsubst $(SRCDIR)/%.c,$(DEPDIR)/%.d,$(SRCS)))
