#include "test_cheat.hpp"

#include "test_feature.hpp"

#include <Windows.h>

bool test_cheat::setup_features()
{
	return false;
}

bool test_cheat::setup_offsets()
{
	return false;
}

void test_cheat::run()
{
	for (const auto& feature : this->m_features)
	{
		// before tick'ing the feature, check first if the state will eventually change
		if ( GetAsyncKeyState( feature->get_virtual_key_code() ) & 0x8000 )
			feature->toggle();

		// let the feature tick() when active
		if (feature->is_active())
			feature->tick();
	}
}

void test_cheat::shutdown()
{
}

void test_cheat::print_features()
{
}

void test_cheat::print_offsets()
{
}
