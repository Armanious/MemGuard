#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void memguard_violation(void *addr){}

long
argmatch (const char *arg, const char *const *arglist,
          const char *vallist, size_t valsize)
{
  size_t i;                     /* Temporary index in ARGLIST.  */
  size_t arglen;                /* Length of ARG.  */
  long matchind = -1;      /* Index of first nonexact match.  */
  int ambiguous = 0;       /* If true, multiple nonexact match(es).  */

  arglen = strlen (arg);

  /* Test all elements for either exact match or abbreviated matches.  */
  for (i = 0; arglist[i]; i++)
    {
      if (!strncmp (arglist[i], arg, arglen))
        {
          if (strlen (arglist[i]) == arglen)
            /* Exact match found.  */
            return i;
          else if (matchind == -1)
            /* First nonexact match found.  */
            matchind = i;
          else
            {
              /* Second nonexact match found.  */
              if (vallist == 0
                  || memcmp (vallist + valsize * matchind,
                             vallist + valsize * i, valsize))
                {
                  /* There is a real ambiguity, or we could not
                     disambiguate. */
                  ambiguous = 1;
                }
            }
        }
    }
  if (ambiguous)
    return -2;
  else
    return matchind;
}

int main(){
    printf("hi\n");

}
