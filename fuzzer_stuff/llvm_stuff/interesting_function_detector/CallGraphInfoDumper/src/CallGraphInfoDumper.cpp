//
// Created by machiry at the beginning of time.
//

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
#include "CallGraphNodeDumper.h"


using namespace llvm;
using namespace std;

namespace Kerneline {

    // This is the path of the file where all the call graph info should be dumped.
    static cl::opt<std::string> outputFile("outputFile",
                                           cl::desc("Path to the file where all the "
                                                    "called function names should be dumped."),
                                           cl::value_desc("Absolute path to the file "
                                                          "where all the interesting functions should be dumped."),
                                           cl::init(""));


    /***
     *  The main pass that finds all the callees of all the functions
     *  in the provided module
     */
    struct CallGraphInfoDumper: public ModulePass {
    public:
        static char ID;

        CallGraphInfoDumper() : ModulePass(ID) {
        }

        ~CallGraphInfoDumper() {
        }

        /***
         *  Process the call graph.
         * @param targetCG CallGraph to process.
         * @param output output file stream.
         */
        void processCallGraph(CallGraph &targetCG, llvm::raw_fd_ostream &output) {
            bool addComma = false;
            for(auto &fuMap: targetCG) {
                addComma = CallGraphNodeDumper::processCallGraphNode(fuMap.second.get(), output, addComma) || addComma;
            }
        }

        bool runOnModule(Module &m) override {
            std::set<string> allFunctions;
            allFunctions.clear();

            CallGraphWrapperPass &targetPass = getAnalysis<CallGraphWrapperPass>();
            CallGraph &targetCG = targetPass.getCallGraph();
            std::error_code res_code;
            llvm::raw_fd_ostream op_stream(outputFile, res_code, llvm::sys::fs::F_Text);
            op_stream << "{\"CallGraphInfo\":[";
            processCallGraph(targetCG, op_stream);
            op_stream << "]}";

            return false;
        }

        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.setPreservesAll();
            AU.addRequired<CallGraphWrapperPass>();
        }

    };

    char CallGraphInfoDumper::ID = 0;

    static RegisterPass<CallGraphInfoDumper> x("cgdumpjson", "Dump call graph of the functions "
                                                             "in the module to a json file.", false, true);
}
