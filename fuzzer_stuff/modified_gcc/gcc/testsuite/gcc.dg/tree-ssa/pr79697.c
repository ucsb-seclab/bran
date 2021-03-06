/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-gimple -fdump-tree-cddce-details -fdump-tree-optimized" } */

void f(void)
{
  __builtin_strdup ("abc");
}

void g(void)
{
  __builtin_strndup ("abc", 3);
}

void h(void)
{
  __builtin_realloc (0, 10);
}

void k(void)
{
  char *p = __builtin_strdup ("abc");
  __builtin_free (p);

  char *q = __builtin_strndup ("abc", 3);
  __builtin_free (q);
}

/* { dg-final { scan-tree-dump "Deleting : __builtin_strdup" "cddce1" } } */
/* { dg-final { scan-tree-dump "Deleting : __builtin_strndup" "cddce1" } } */
/* { dg-final { scan-tree-dump "__builtin_malloc" "gimple" } } */
/* { dg-final { scan-tree-dump-not "__builtin_strdup" "optimized" } } */
/* { dg-final { scan-tree-dump-not "__builtin_strndup" "optimized" } } */
/* { dg-final { scan-tree-dump-not "__builtin_free" "optimized" } } */
