//#include <Includings/custom_data_types.hpp>
//#include <Memory/Process/process.hpp>

#include "sandbox_overlay.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <d3d9.h>
#pragma comment (lib, "d3d9.lib")

static constexpr int WINDOW_WIDTH = 800;
static constexpr int WINDOW_HEIGHT = 600;

LPDIRECT3D9EX d3d;
LPDIRECT3DDEVICE9EX d3d_device;

std::unique_ptr<sandbox_overlay> sbox_overlay;

void d3d_initialize(HWND hwnd)
{
    Direct3DCreate9Ex(D3D_SDK_VERSION, &d3d);

    D3DPRESENT_PARAMETERS d3dpp;

    ZeroMemory(&d3dpp, sizeof(d3dpp));
    d3dpp.Windowed = true;
    d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    d3dpp.hDeviceWindow = hwnd;
    d3dpp.BackBufferFormat = D3DFMT_X8R8G8B8;
    d3dpp.BackBufferWidth = WINDOW_WIDTH;
    d3dpp.BackBufferHeight = WINDOW_HEIGHT;

    //D3DDISPLAYMODEEX dm;
    //dm.Format = D3DFMT_X8R8G8B8;
    //dm.Height = WINDOW_HEIGHT;
    //dm.Size = sizeof(dm);
    //dm.RefreshRate = 60;
    //dm.ScanLineOrdering = D3DSCANLINEORDERING_PROGRESSIVE;
    //dm.Width = WINDOW_WIDTH;

    d3d->CreateDeviceEx(D3DADAPTER_DEFAULT,
        D3DDEVTYPE_HAL,
        hwnd,
        D3DCREATE_FPU_PRESERVE | D3DCREATE_MULTITHREADED | D3DCREATE_SOFTWARE_VERTEXPROCESSING,
        &d3dpp,
        NULL,
        &d3d_device);
}

void d3d_render_frame()
{
    d3d_device->Clear(0, NULL, D3DCLEAR_TARGET, D3DCOLOR_XRGB(100, 0, 0), 1.0f, 0);

    d3d_device->BeginScene();

    // render
    sbox_overlay->render();

    d3d_device->EndScene();

    d3d_device->PresentEx(nullptr, nullptr, nullptr, nullptr, NULL);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
        case WM_DESTROY:
        {
            PostQuitMessage(0);
            return 0;
        }
        break;
    }

    return DefWindowProc(hwnd, message, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSEX wc;
    ZeroMemory(&wc, sizeof(WNDCLASSEX));

    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    // wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.lpszClassName = L"OsmiumSandbox";

    RegisterClassEx(&wc);

    HWND hwnd = CreateWindowEx(NULL,
        L"OsmiumSandbox", // Window class
        L"Osmium Sandbox Application", // Window title
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, // Window style
        0, // X
        0, // Y
        WINDOW_WIDTH, // Width
        WINDOW_HEIGHT, // Height
        NULL, // Parent
        NULL, // Menu
        hInstance, // Application handle
        NULL // lParam
    );

    ShowWindow(hwnd, nCmdShow);

    d3d_initialize(hwnd);

    sbox_overlay = std::make_unique<sandbox_overlay>();
    if (!sbox_overlay->initialize(hwnd)) {
        MessageBoxA(hwnd, "Failed to initialize overlay\n", "Error", NULL);
        return 1;
    }
    sbox_overlay->set_device_ptr(d3d_device);

    MSG msg;
    while (true)
    {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        if (msg.message == WM_QUIT)
            break;

        d3d_render_frame();
    }

    d3d_device->Release();
    d3d->Release();

    return msg.wParam;
}

//int main(int argc, char** argv) {
//	auto proc = new process();
//	if (!proc->setup_process(L"win32calc.exe")) {
//		printf("failed to attach to win32calc.exe\n");
//		return 1;
//	}
//
//	printf("found calc.exe, pid: %d\n", proc->get_process_id());
//
//	return 0;
//}
