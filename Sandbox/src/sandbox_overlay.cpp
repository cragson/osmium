#include "sandbox_overlay.hpp"

void sandbox_overlay::render()
{
	this->m_Device->BeginScene();

	const auto fg_hwnd = GetForegroundWindow();

	if (fg_hwnd == this->m_TargetWindow)
	{
		this->draw_string("osmium sandbox", 10, 10, 255, 255, 255);
	}

	this->m_Device->EndScene();
	this->m_Device->PresentEx(nullptr, nullptr, nullptr, nullptr, NULL);
	this->m_Device->Clear(NULL, nullptr, D3DCLEAR_TARGET, D3DCOLOR_ARGB(0, 0, 0, 0), 1.0f, NULL);
}