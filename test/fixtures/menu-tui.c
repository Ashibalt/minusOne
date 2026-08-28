/*
 * Interactive menu TUI fixture for the console plane (console.launch /
 * console.send / console.read). Reads keys with _getch-style console input
 * (INPUT_RECORD plane, NOT stdin bytes) and draws a small menu that reacts
 * to arrow keys, characters, and Enter — the shape of ratatui/crossterm
 * crackmes that defeated the stdin pipe in combat.
 */
#include <stdio.h>
#include <windows.h>
#include <conio.h>

int main(void) {
    int selected = 0;
    char name[64] = "";
    int name_len = 0;
    for (;;) {
        COORD origin = {0, 0};
        HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO info;
        int height = 10;
        if (GetConsoleScreenBufferInfo(out, &info)) {
            height = info.srWindow.Bottom - info.srWindow.Top + 1;
        }
        origin.Y = info.srWindow.Top;
        for (int y = 0; y < height; y++) {
            DWORD written = 0;
            COORD line = {0, (SHORT)(info.srWindow.Top + y)};
            FillConsoleOutputCharacterW(out, L' ', info.dwSize.X, line, &written);
        }
        printf("=== MINUSONE MENU TUI ===\n");
        printf("[1] Enter name (current: %s)\n", name);
        printf("%s Run check\n", selected == 0 ? ">" : " ");
        printf("%s Quit\n", selected == 1 ? ">" : " ");
        printf("Enter=select  arrows=move  F12=refresh\n");
        fflush(stdout);
        int key = _getch();
        if (key == 0 || key == 224) { /* extended key */
            int ext = _getch();
            if (ext == 72) { selected = (selected + 1) % 2; }      /* UP   */
            else if (ext == 80) { selected = (selected + 1) % 2; } /* DOWN */
            continue;
        }
        if (key == 'v') {
            /* VK probe through the RAW INPUT_RECORD plane — what
             * ratatui/crossterm actually reads (ReadConsoleInputW).
             * Skips key-up leftovers, reports the next key-down VK. */
            HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
            INPUT_RECORD rec; DWORD n = 0;
            for (;;) {
                if (!ReadConsoleInputW(in, &rec, 1, &n) || n != 1) break;
                if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) {
                    printf("VK=%u\n", rec.Event.KeyEvent.wVirtualKeyCode);
                    fflush(stdout);
                    _getch(); /* hold the VK line on screen */
                    break;
                }
            }
            continue;
        }
        if (key == 'q' || key == 'Q') {
            printf("BYE\n");
            fflush(stdout);
            return 0;
        }
        if (key == '\r') {
            if (selected == 0) {
                printf("CHECK name='%s' len=%d\n", name, name_len);
                fflush(stdout);
                /* Hold the CHECK line on screen until the next keypress —
                 * the redraw at the loop top must not erase it instantly. */
                _getch();
            } else {
                printf("BYE\n");
                fflush(stdout);
                return 0;
            }
        } else if (key == '1') {
            printf("NAME> \n");
            fflush(stdout);
            name_len = 0;
            for (;;) {
                int c = _getch();
                if (c == '\r' || c == '\n') break;
                if (c == 8 && name_len > 0) { name_len--; }
                else if (c >= 32 && c < 127 && name_len < 62) { name[name_len++] = (char)c; }
                COORD pos = {6, 5};
                SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), pos);
                printf("%s", name);
                fflush(stdout);
            }
            name[name_len] = 0;
        }
    }
}
