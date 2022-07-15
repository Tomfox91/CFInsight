#!/bin/sh

set -ue

cd ${CBCH_SPEC:-${PWD}}


export LC_ALL=C
export LC_LANG=C
export PATH=<<<<<SPEC_CPU>>>>>/bin:$PATH
export SPEC=<<<<<SPEC_CPU>>>>>
export SPECPERLLIB=<<<<<SPEC_CPU>>>>>/bin/lib:<<<<<SPEC_CPU>>>>>/bin

unset BAT_PAGER
unset DBUS_SESSION_BUS_ADDRESS
unset EXA_COLORS
unset LANG
unset LANGUAGE
unset LC_TERMINAL
unset LC_TERMINAL_VERSION
unset LESS_TERMCAP_md
unset LESS_TERMCAP_me
unset LESS_TERMCAP_se
unset LESS_TERMCAP_so
unset LESS_TERMCAP_ue
unset LESS_TERMCAP_us
unset LS_COLORS
unset MOTD_SHOWN
unset SSH_CLIENT
unset SSH_CONNECTION
unset SSH_TTY
unset TERM
unset TMUX_PANE
unset TMUX
unset USER
unset XDG_RUNTIME_DIR
unset XDG_SESSION_CLASS
unset XDG_SESSION_ID
unset XDG_SESSION_TYPE

exec bin/runcpu "$@"
