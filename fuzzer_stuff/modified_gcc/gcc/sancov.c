/* Code coverage instrumentation for fuzzing.
   Copyright (C) 2015-2017 Free Software Foundation, Inc.
   Contributed by Dmitry Vyukov <dvyukov@google.com>

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

GCC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "backend.h"
#include "tree.h"
#include "gimple.h"
#include "basic-block.h"
#include "options.h"
#include "flags.h"
#include "stmt.h"
#include "gimple-iterator.h"
#include "tree-cfg.h"
#include "tree-pass.h"
#include "tree-iterator.h"
#include "asan.h"
#include "output.h"

namespace {

unsigned
sancov_pass (function *fun)
{
  initialize_sanitizer_builtins ();

  /* Insert callback into beginning of every BB. */
  tree fndecl = builtin_decl_implicit (BUILT_IN_SANITIZER_COV_TRACE_PC);
  basic_block bb;
  FOR_EACH_BB_FN (bb, fun)
    {
      gimple_stmt_iterator gsi = gsi_start_nondebug_after_labels_bb (bb);
      if (gsi_end_p (gsi))
	continue;
      gimple *stmt = gsi_stmt (gsi);
      gimple *gcall = gimple_build_call (fndecl, 0);
      gimple_set_location (gcall, gimple_location (stmt));
      gsi_insert_before (&gsi, gcall, GSI_SAME_STMT);
    }
  return 0;
}

template <bool O0> class pass_sancov : public gimple_opt_pass
{
public:
  static char** max_num_functions;
  static bool is_filter_func_init;
  static unsigned num_filter_funcs;	

  pass_sancov (gcc::context *ctxt) : gimple_opt_pass (data, ctxt) {
    pass_sancov<O0>::read_filter_functions("/home/machiry/Desktop/sanitize_cov_filter.txt");
  }

  static void read_filter_functions(const char *file_name) {
    unsigned lines_allocated = 128;
    unsigned max_line_len = 256;
    char **words;
    FILE *fp;
    unsigned i, j, new_size;

    if(pass_sancov<O0>::is_filter_func_init) {
	return;
    }
    pass_sancov<O0>::is_filter_func_init = true;

    fp = fopen(file_name, "r");
    if (fp == NULL)
        {
        fprintf(stderr,"Error opening coverage filter file:%s\n", file_name);
        return;
        }

    /* Allocate lines of text */
    words = (char **)xmalloc(sizeof(char*)*lines_allocated);
    pass_sancov<O0>::max_num_functions = words;
    if (words==NULL)
        {
        fprintf(stderr,"Out of memory (1).\n");
	return;
        }

    for (i=0;1;i++)
        {

        /* Have we gone over our line allocation? */
        if (i >= lines_allocated)
            {

            /* Double our allocation and re-allocate */
            new_size = lines_allocated*2;
            words = (char **)xrealloc(words,sizeof(char*)*new_size);
            if (words==NULL)
                {
                fprintf(stderr,"Out of memory.\n");
                return;
                }
            lines_allocated = new_size;
            }
        /* Allocate space for the next line */
        words[i] = (char*)xmalloc(max_line_len);
	pass_sancov<O0>::num_filter_funcs = i+1;
        if (words[i]==NULL)
            {
            fprintf(stderr,"Out of memory (3).\n");
            return;
            }
        if (fgets(words[i],max_line_len-1,fp)==NULL)
            break;

        /* Get rid of CR or LF at end of line */
        for (j=strlen(words[i])-1;j>=0 && (words[i][j]=='\n' || words[i][j]=='\r');j--)
            ;
        words[i][j+1]='\0';
        }
    /* Close file */
    fclose(fp);
  }

  static bool is_func_interesting(const char *func_name) 
  {
     unsigned i = 0;
     if(pass_sancov<O0>::max_num_functions != NULL) {
	for(;i < pass_sancov<O0>::num_filter_funcs; i++) {
	    if(!strcmp(func_name, pass_sancov<O0>::max_num_functions[i])) {
                return true;
            }
	}
        return false;
     }
     return true;
  }

  static const pass_data data;
  opt_pass *
  clone ()
  {
    return new pass_sancov<O0> (m_ctxt);
  }
  virtual bool
  gate (function *f)
  {
    return flag_sanitize_coverage && (!O0 || !optimize) && is_func_interesting(get_fnname_from_decl(f->decl));
  }
  virtual unsigned int
  execute (function *fun)
  {
    return sancov_pass (fun);
  }
}; // class pass_sancov

template <bool O0>
const pass_data pass_sancov<O0>::data = {
  GIMPLE_PASS,		       /* type */
  O0 ? "sancov_O0" : "sancov", /* name */
  OPTGROUP_NONE,	       /* optinfo_flags */
  TV_NONE,		       /* tv_id */
  (PROP_cfg),		       /* properties_required */
  0,			       /* properties_provided */
  0,			       /* properties_destroyed */
  0,			       /* todo_flags_start */
  TODO_update_ssa,	     /* todo_flags_finish */
};

template <bool O0> bool pass_sancov<O0>::is_filter_func_init = false;
template <bool O0> unsigned pass_sancov<O0>::num_filter_funcs = 0;
template <bool O0> char** pass_sancov<O0>::max_num_functions = NULL;
} // anon namespace

gimple_opt_pass *
make_pass_sancov (gcc::context *ctxt)
{
  return new pass_sancov<false> (ctxt);
}

gimple_opt_pass *
make_pass_sancov_O0 (gcc::context *ctxt)
{
  return new pass_sancov<true> (ctxt);
}
