#include "GQUIC.h"
#include "Plugin.h"

namespace plugin { namespace Salesforce_GQUIC { Plugin plugin; } }

using namespace plugin::Salesforce_GQUIC;

plugin::Configuration Plugin::Configure()
	{
	auto c = new ::analyzer::Component("GQUIC",
		::analyzer::gquic::GQUIC_Analyzer::Instantiate);
	AddComponent(c);
	plugin::Configuration config;
	config.name = "Salesforce::GQUIC";
	config.description = "Google QUIC (GQUIC) protocol analyzer for Q039-Q046";
	config.version.major = 1;
	config.version.minor = 0;
	return config;
	}
