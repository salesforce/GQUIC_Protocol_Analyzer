/*
 * Copyright (c) 2017-2019, Corelight Inc. and GQUIC Protocol Analyzer contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef ZEEK_PLUGIN_SALESFORCE_GQUIC
#define ZEEK_PLUGIN_SALESFORCE_GQUIC

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin::Salesforce_GQUIC {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}

#endif
