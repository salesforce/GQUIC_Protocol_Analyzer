#
# This is loaded unconditionally at Bro startup before any of the BiFs
# defined by the plugin become available.
#
# This is primarily for defining types that BiFs already depend on.
# If you need to do any other unconditional initialization (usually that's
# just for other BiF elements), that should go into __load__.bro instead.
#

@load ./types.bro

