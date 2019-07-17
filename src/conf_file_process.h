#ifndef CONF_FILE_PROCESS_H_
#define CONF_FILE_PROCESS_H_

#include <string>
#include <vector>

#include "util/macro.h"

struct ConfItem{
	char itemName[CONF_NAME_SIZE];
	char itemContent[CONF_CONTENT_SIZE];
};

class ConfFileProcessor{
private:
    ConfFileProcessor();

    ~ConfFileProcessor(); 

    static ConfFileProcessor * instance;

    class GCInstance{
    public:
        ~GCInstance(){
            if(ConfFileProcessor::instance != nullptr){
                delete ConfFileProcessor::instance;
                ConfFileProcessor::instance = nullptr;
            }
        }
    };

public:
    static ConfFileProcessor * getInstance(){
        if(instance == nullptr){
            instance = new ConfFileProcessor;
            static GCInstance gc;
        }

        return instance;
    }

    bool load(const char * confFileName);

    const char * getItemContent_str(const char * itemName);

    int getItemContent_int(const char * itemName, const int def);

private:
    std::vector<ConfItem *> m_confItemList;
};

#endif // CONF_FILE_PROCESS_H_