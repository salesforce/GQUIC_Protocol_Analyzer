/*
 * Copyright (c) 2017-2019, Corelight Inc. and GQUIC Protocol Analyzer contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef BRO_PLUGIN_SALESFORCE_GQUIC
#define BRO_PLUGIN_SALESFORCE_GQUIC

#include <plugin/Plugin.h>

namespace plugin {
namespace Salesforce_GQUIC {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
