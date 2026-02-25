#include <stdio.h>

/* Nested if — only the innermost branch closes.
   Path true→true:  fclose → CLOSED   (clean)
   Path true→false: no close → OPEN   (leak)
   Path false:      no close → OPEN   (leak)
   Joined at exit: OPEN|CLOSED → may-leak.
   Expected: state-resource-leak-possible. */
void nested_branch_leak(int a, int b) {
    FILE *f = fopen("data.txt", "r");
    if (a) {
        if (b) {
            fclose(f);
        }
    }
}
