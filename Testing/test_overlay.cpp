#include "test_overlay.hpp"

#include "../Includings/modules.hpp"

void test_overlay::render()
{
	this->m_Device->Clear( NULL, nullptr, D3DCLEAR_TARGET, D3DCOLOR_ARGB( 0, 0, 0, 0 ), 1.0f, NULL );
	this->m_Device->BeginScene();

	const auto fg_hwnd = GetForegroundWindow();

	if( fg_hwnd == this->m_TargetWindow )
	{
		const auto features = Modules::g_pCheat->get_features_as_ptr();

		for( auto it = features->begin(); it != features->end(); ++it )
		{
			const auto current_feature = it->get();

			if( !current_feature->should_be_drawn() )
				continue;

			if( current_feature->is_active() )
				current_feature->on_render();
		}
	}

	this->m_Device->EndScene();
	this->m_Device->PresentEx( nullptr, nullptr, nullptr, nullptr, NULL );
	
}
