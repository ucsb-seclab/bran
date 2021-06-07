//
// Created by machiry on 4/8/19.
//

#include <fstream>
#include <unistd.h>
#include <stdio.h>
#include "FunctionFinderHelper.h"

namespace Kerneline {
    bool FunctionFinderHelper::readFunctionsFromFile(string &filePath, std::set<string> &targetFunctions) {
        bool hasChanged = false;
        std::ifstream infile(filePath);
        std::string line;
        while (std::getline(infile, line)) {
            hasChanged = targetFunctions.insert(line).second || hasChanged;
        }
        infile.close();
        return hasChanged;
    }

    bool FunctionFinderHelper::writeFunctionsToFile(string &filePath, std::set<string> &targetFunctions) {
        FILE *outputFile = fopen(filePath.c_str(), "w");
        if(outputFile != NULL) {
            for(auto &currLine: targetFunctions) {
                fprintf(outputFile, "%s\n", currLine.c_str());
            }
            fclose(outputFile);
        }
        return true;
    }

    bool FunctionFinderHelper::processCallGraphNode(CallGraphNode *targetNode,
                                                    std::set<string> &targetFunctions) {
        bool hasChanged = false;
        if(targetNode->size() > 0 && targetNode->getFunction() != nullptr && targetNode->getFunction()->hasName()) {
            for (auto &outEdge: *targetNode) {
                Function *calledFunc = outEdge.second->getFunction();
                if (calledFunc != nullptr && calledFunc->hasName()) {
                    if (targetFunctions.find(calledFunc->getName().str()) != targetFunctions.end()) {
                        hasChanged =
                                targetFunctions.insert(targetNode->getFunction()->getName().str()).second || hasChanged;
                    }
                }
            }
        }
        return hasChanged;
    }
}