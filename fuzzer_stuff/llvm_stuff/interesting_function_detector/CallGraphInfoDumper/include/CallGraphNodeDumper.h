//
// Created by machiry on 4/8/19.
//

#ifndef INTERESTING_FUNCTION_DETECTOR_CALLGRAPHNODEDUMPER_H
#define INTERESTING_FUNCTION_DETECTOR_CALLGRAPHNODEDUMPER_H

#include <llvm/Pass.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/ValueSymbolTable.h>
#include <iostream>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Support/Debug.h>
#include <llvm/Analysis/CFGPrinter.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>
#include <set>


using namespace llvm;
using namespace std;

namespace Kerneline {
    /***
     * A helper class that performs certain useful tasks needed to gather functions of interest.
     */
    class CallGraphNodeDumper {
    private:
        /***
         * Check if the provided CallGraphNode represents a function
         * that has a name.
         * @param currNode CallGraphNode to process.
         * @return true if the provided function has name else false
         */
        static bool hasFunctionName(CallGraphNode *currNode);
    public:

        /***
         * Process the provided call graph ndode.
         * @param targetNode provided call graph node.
         * @param output output stream where the output should be written.
         * @param addInitC Add comma before.
         * @return True if atleast one new function is added else false
         */
        static bool processCallGraphNode(CallGraphNode *targetNode, raw_ostream &output, bool addInitC);

    };

}

#endif //INTERESTING_FUNCTION_DETECTOR_CALLGRAPHNODEDUMPER_H
