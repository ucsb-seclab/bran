//
// Created by machiry on 4/8/19.
//

#include <fstream>
#include <unistd.h>
#include <stdio.h>
#include "CallGraphNodeDumper.h"

namespace Kerneline {

    bool CallGraphNodeDumper::hasFunctionName(CallGraphNode *targetNode) {
        return targetNode->getFunction() != nullptr && targetNode->getFunction()->hasName();
    }

    bool CallGraphNodeDumper::processCallGraphNode(CallGraphNode *targetNode, raw_ostream &output, bool addInitC) {
        bool hasChanged = false;
        std::set<string> called_funs;
        called_funs.clear();

        if(targetNode->size() > 0 && CallGraphNodeDumper::hasFunctionName(targetNode)) {

            for (auto &outEdge: *targetNode) {
                CallGraphNode *childNode = outEdge.second;
                if(CallGraphNodeDumper::hasFunctionName(childNode)) {
                    called_funs.insert(childNode->getFunction()->getName().str());
                }
            }
            if(addInitC) {
                output << ",\n";
            }

            output << "{\"" << targetNode->getFunction()->getName() << "\":[";
            hasChanged = true;
            bool addComma = false;
            for(auto &currF: called_funs) {
                if(addComma) {
                    output << ",";
                }
                output << "\"" << currF << "\"";
                addComma = true;
            }
            output << "]}";

        }


        return hasChanged;
    }
}