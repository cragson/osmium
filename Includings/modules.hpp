#pragma once

#include "../Memory/Process/process.hpp"

#include "../Testing/test_overlay.hpp"

#include "../Testing/test_cheat.hpp"

namespace Modules
{
	inline std::unique_ptr< process > g_pProcess = std::make_unique< process >();

	inline std::unique_ptr< test_overlay > g_pOverlay = std::make_unique< test_overlay >();

	inline std::unique_ptr< test_cheat > g_pCheat = std::make_unique< test_cheat >();
}
