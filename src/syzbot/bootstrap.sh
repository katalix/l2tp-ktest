#!/bin/sh
for i in $(dirname $0)/*
do
    if test -f $i/repro.c
    then
        repro=$i/repro.c
        target=syzbot_$(basename $i)
        src="\$(SRCDIR)/${target}.c"
        cat << __EOF__
$src : $repro
	cp $repro $src
${target}_SRCS := $src
${target}_LIBS := pthread
\$(eval \$(call buildapp,$target))
CLEANFILES += $src
__EOF__
    fi
done
