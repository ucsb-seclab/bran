/* { dg-do compile } */
/* { dg-options "-O2" } */

void bar (float);
void
foo (void)
{
  bar (0.0);
}

/* { dg-final { scan-assembler "movi\\tv0\.2s, #0" } } */
