#include "abe.h"
#include "abe_ssl.h"
#include <string>
#include <string.h>
// #include "sql/table.h"

// static void requestAbeInfo(Oid userId, const char *attribute, AbeInfo abe_info)
// {
//     Abe_ssl abe_ssl;
//     abe_info->user_name = GetUserNameFromId(userId);
//     abe_info->attribute = pstrdup(attribute);
//     abe_ssl.generateABEInfo(abe_info);
// }

static void addAbeKey(std::string userhost, const AbeInfo abe_info)
{
    // TABLE_LIST tables("mysql", "abe_user_key", TL_WRITE);

}

static void addAbeAttributeManager(std::string userhost, char* abeAttribute)
{
    // TABLE_LIST tables("mysql", "abe_user_key", TL_WRITE);
}

void initAbeData(std::string userhost, std::string abeAttribute)
{
    

    AbeInfo abe_info = (AbeInfo)malloc(sizeof(AbeInfoData));
    Abe_ssl abe_ssl;
    abe_info->user_name = strdup(userhost.c_str());
    abe_info->attribute = strdup(abeAttribute.c_str());
    abe_ssl.generateABEInfo(abe_info);
    // requestAbeInfo(userId, abeAttribute, abe_info);

    // addAbeKey(userId, abe_info);
    // addAbeAttributeManager(userId, abeAttribute);
    free(abe_info->user_name);
    free(abe_info->attribute);
    free(abe_info);
}