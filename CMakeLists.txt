
cmake_minimum_required(VERSION 2.8)

project(BroPluginGQUIC)

include(BroPlugin)

bro_plugin_begin(Salesforce GQUIC)
bro_plugin_cc(src/GQUIC.cc src/Plugin.cc)
bro_plugin_bif(src/events.bif src/consts.bif src/types.bif)
bro_plugin_pac(src/gquic.pac src/gquic-protocol.pac src/gquic-analyzer.pac)
bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_end()
