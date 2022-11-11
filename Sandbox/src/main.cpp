#include <Includings/custom_data_types.hpp>
#include <Memory/Process/process.hpp>

int main(int argc, char** argv) {
	auto proc = new process();
	if (!proc->setup_process(L"win32calc.exe")) {
		printf("failed to attach to win32calc.exe\n");
		return 1;
	}

	printf("found calc.exe, pid: %d\n", proc->get_process_id());

	return 0;
}
