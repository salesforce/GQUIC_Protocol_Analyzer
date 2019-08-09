
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
