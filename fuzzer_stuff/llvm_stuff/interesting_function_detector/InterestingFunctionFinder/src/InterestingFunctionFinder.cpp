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
#include "FunctionFinderHelper.h"


using namespace llvm;
using namespace std;

namespace Kerneline {

    // This is the path of the file containing interesting function list.
    static cl::opt<std::string> interestingFnList("interFunctionList",
                                                  cl::desc("Path to the file containing all the interesting functions."),
                                                  cl::value_desc("Absolute path to the file "
                                                                 "containing all interesting function names."),
                                                  cl::init(""));


    /***
     *  The main pass that finds all the callers of the functions
     *  listed in the provided file.
     *  it also updates the newly found functions.
     */
    struct InterestingFunctionFinder: public ModulePass {
    public:
        static char ID;

        InterestingFunctionFinder() : ModulePass(ID) {
        }

        ~InterestingFunctionFinder() {
        }

        /***
         *  Process the call graph using a worklist algorithm.
         * @param targetCG CallGraph to process.
         * @param allFunctions Set of interesting functions.
         */
        void processCallGraph(CallGraph &targetCG, std::set<string> &allFunctions) {
            bool hasChanged = true;
            while(hasChanged) {
                hasChanged = false;
                for(auto &fuMap: targetCG) {
                    hasChanged = FunctionFinderHelper::processCallGraphNode(fuMap.second.get(), allFunctions) || hasChanged;
                }
            }

        }

        bool runOnModule(Module &m) override {
            std::set<string> allFunctions;
            allFunctions.clear();

            if(FunctionFinderHelper::readFunctionsFromFile(interestingFnList, allFunctions)) {
                dbgs() << "[+] Read :" << allFunctions.size() << " functions from file:" << interestingFnList << "\n";
                CallGraphWrapperPass &targetPass = getAnalysis<CallGraphWrapperPass>();
                CallGraph &targetCG = targetPass.getCallGraph();
                processCallGraph(targetCG, allFunctions);
                dbgs() << "[+] New functions :" << allFunctions.size() << "\n";
                dbgs() << "[+] Writing function to file:" << interestingFnList << "\n";
                FunctionFinderHelper::writeFunctionsToFile(interestingFnList, allFunctions);
            } else {
                dbgs() << "[!] Unable to read function from file:" << interestingFnList << "\n";
            }




            return false;
        }

        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.setPreservesAll();
            AU.addRequired<CallGraphWrapperPass>();
        }

    };

    char InterestingFunctionFinder::ID = 0;

    static RegisterPass<InterestingFunctionFinder> x("infufi", "Interesting function finder.", false, true);
}
