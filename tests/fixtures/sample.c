/*
 * Deterministic fixture binary for idamcp integration tests.
 * Build (MSVC x64):  see tests/fixtures/build_fixture.ps1
 *
 * Known properties the tests assert on:
 *   - exported functions: idamcp_add, idamcp_checksum, idamcp_classify
 *   - idamcp_classify has a multi-way branch (several basic blocks)
 *   - main -> idamcp_checksum -> idamcp_mix (call graph)
 *   - string literals containing the marker "IDAMCP_MARKER"
 *   - imports from KERNEL32.dll (GetTickCount, OutputDebugStringA)
 */
#include <windows.h>
#include <stdio.h>

static const char g_banner[] = "IDAMCP_MARKER: fixture banner v1";
static const char g_secret[] = "IDAMCP_MARKER: secret-string-42";
static unsigned char g_magic[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE };

__declspec(noinline) static unsigned int idamcp_mix(unsigned int h, unsigned char c)
{
    h ^= c;
    h *= 16777619u;
    return h;
}

__declspec(dllexport) __declspec(noinline) int idamcp_add(int a, int b)
{
    return a + b;
}

__declspec(dllexport) __declspec(noinline) unsigned int idamcp_checksum(const unsigned char *p, size_t n)
{
    unsigned int h = 2166136261u;
    for (size_t i = 0; i < n; i++)
        h = idamcp_mix(h, p[i]);
    return h;
}

__declspec(dllexport) __declspec(noinline) const char *idamcp_classify(int v)
{
    if (v < 0)
        return "negative";
    if (v == 0)
        return "zero";
    if (v < 10)
        return "small";
    if (v < 1000)
        return "medium";
    return "large";
}

int main(int argc, char **argv)
{
    (void)argv;
    OutputDebugStringA(g_banner);
    unsigned int t = GetTickCount();
    unsigned int c = idamcp_checksum(g_magic, sizeof(g_magic));
    int s = idamcp_add(argc, (int)(t & 0xff));
    printf("%s %u %d %s\n", g_secret, c, s, idamcp_classify(s));
    return 0;
}
