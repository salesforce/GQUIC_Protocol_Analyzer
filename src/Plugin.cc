/*
 * Copyright (c) 2017-2019, Corelight Inc. and GQUIC Protocol Analyzer contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

#include "GQUIC.h"
#include "Plugin.h"

namespace zeek::plugin { namespace Salesforce_GQUIC { Plugin plugin; } }

using namespace plugin::Salesforce_GQUIC;

zeek::plugin::Configuration Plugin::Configure()
	{
	auto c = new zeek::::analyzer::Component("GQUIC",
		zeek::analyzer::gquic::GQUIC_Analyzer::Instantiate);
	AddComponent(c);
	zeek::plugin::Configuration config;
	config.name = "Salesforce::GQUIC";
	config.description = "Google QUIC (GQUIC) protocol analyzer for Q039-Q046";
	config.version.major = 1;
	config.version.minor = 0;
	return config;
	}
