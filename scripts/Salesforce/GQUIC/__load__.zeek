#
# This is loaded when a user activates the plugin.
#

@load ./main
@load ./gquic_events.zeek

@load-sigs ./dpd.sig
