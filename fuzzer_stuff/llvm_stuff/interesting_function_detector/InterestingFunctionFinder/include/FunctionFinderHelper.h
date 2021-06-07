//
// Created by machiry on 4/8/19.
//

#ifndef INTERESTING_FUNCTION_DETECTOR_FUNCTIONFINDERHELPER_H
#define INTERESTING_FUNCTION_DETECTOR_FUNCTIONFINDERHELPER_H

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
    class FunctionFinderHelper {
    public:
        /***
         * Read all function names from the provided file and store them in the list.
         * @param filePath Path of the file that contains all the interesting functions.
         * @param targetFunctions Set of interesting functions.
         * @return True if the read was successful.
         */
        static bool readFunctionsFromFile(string &filePath, std::set<string> &targetFunctions);

        /***
         * Write provided function set to the file.
         * @param filePath Path to the file to which the functions should be written.
         * @param targetFunctions Set of function names to write.
         * @return True if successful else false.
         */
        static bool writeFunctionsToFile(string &filePath, std::set<string> &targetFunctions);

        /***
         * Process the provided call graph ndode.
         * @param targetNode provided call graph node.
         * @param targetFunctions list of interesting functions.
         * @return True if atleast one new function is added else false
         */
        static bool processCallGraphNode(CallGraphNode *targetNode, std::set<string> &targetFunctions);

    };

}

#endif //INTERESTING_FUNCTION_DETECTOR_FUNCTIONFINDERHELPER_H
