
cmake_minimum_required(VERSION 2.8)

project(ZeekPluginGQUIC)

include(ZeekPlugin)

zeek_plugin_begin(Salesforce GQUIC)
zeek_plugin_cc(src/GQUIC.cc src/Plugin.cc)
zeek_plugin_bif(src/events.bif src/consts.bif src/types.bif)
zeek_plugin_pac(src/gquic.pac src/gquic-protocol.pac src/gquic-analyzer.pac)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()
